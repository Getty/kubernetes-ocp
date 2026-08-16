package OCP::Cmd::SSH;
# ABSTRACT: SSH into a cluster node with the key it trusts

use Moo;
use MooX::Cmd;
use MooX::Options;
use OCP;
use OCP::Choices;
use OCP::ClusterKey;
use OCP::Config;
use OCP::Kubernetes;
use OCP::Secrets;
use OCP::SSH;
use Path::Tiny qw(path);

with 'OCP::Role::Cmd';

option node => (
    is     => 'ro',
    format => 's',
    doc    => 'Node name or IP to SSH into',
);

# This command used to unlock the admin key by hand and demand PIN2
# unconditionally — including in a --nopassword project, which has no
# keys.yaml at all and where the prompt could only ever end in "Wrong PIN2 or
# no admin-key found". karr #94 filed the mirror image of that: at the time,
# `provider: ssh` machines trusted the bootstrap key, so PIN2 bought a key the
# machine did not know.
#
# Both disappear into OCP::ClusterKey. Secure mode reaches every machine with
# the admin key on every provider, so #94's premise is gone: PIN2 here is
# correct, not theatre. Dev mode has one key and no PIN, so this connects
# without prompting, as everything else in dev mode does.
sub execute {
    my ($self, $args, $chain) = @_;

    my $config_file = $self->ocp->config;
    my $config = OCP::Config->new(file => $config_file);

    unless ($config->cluster_exists) {
        die "No cluster deployed yet. Run 'ocp apply' first.\n";
    }

    my $node_arg = $self->node;
    unless ($node_arg) {
        die "Usage: ocp ssh --node <name|ip>\n";
    }

    my $secure = -f $config->project_dir->child('keys.yaml');

    print "╔═══════════════════════════════════════════════════════════════╗\n";
    printf "║  %-60s║\n", $secure
        ? 'ADMIN-SSH ACCESS (requires PIN2)'
        : 'SSH ACCESS (dev mode: .ocp/id_ed25519, no PIN)';
    print "╚═══════════════════════════════════════════════════════════════╝\n\n";

    # PIN1 if the age key is still locked: _lookup_node_ip below decrypts
    # kubeconfig.yaml with it, and it is a no-op once .ocp/age.key is there.
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    $secrets->ensure_age_key();

    # OCP::ClusterKey prompts for PIN2 itself where one is needed, unlocks the
    # age key on the way, and owns the temp file it writes — the hand-rolled
    # File::Temp here had UNLINK => 1 but no owner for the .pub Rex-style
    # callers expect.
    my $key = $self->cluster_ssh_key($config, reason => 'ocp ssh');
    print "[ok] " . $key->describe . "\n";

    # Determine target host
    my $target_host = $self->_resolve_target_host($config, $secrets, $node_arg);

    unless ($target_host) {
        die $self->_unknown_node_error($node_arg, $self->_node_names($secrets));
    }

    print "[ok] Target: $target_host\n";
    print "[..] Connecting...\n\n";

    my $ssh = OCP::SSH->new(
        host     => $target_host,
        key_file => $key->path,
    );

    # ->interactive execs, so this process is gone the moment it runs and
    # cannot report anything afterwards. Where a lockout is plausible — an
    # admin key, and a bootstrap key still lying in the project — probe first
    # with a batch-mode connection and say what a refusal probably means.
    #
    # The probe never blocks the session: it warns and hands over anyway. It
    # is also skipped entirely unless migration_hint has something to say, so
    # a normal `ocp ssh` keeps its single connection.
    if (my $hint = $key->migration_hint) {
        unless ($ssh->is_reachable) {
            print "[!!] $target_host did not accept the admin key.\n";
            print $hint;
            print "\nHanding over to ssh anyway — its own error follows.\n\n";
        }
    }

    $ssh->interactive;

    return 0;
}

# The names the Kubernetes API answers to, or nothing.
#
# Asked only once the connection target has already failed to resolve, so it
# repeats the list call _lookup_node_ip may just have made. That is on
# purpose: this way the answer is the same whichever of the branches above
# came up empty — including the one that never asked at all — and the cost is
# one API call on a path that is about to exit non-zero anyway.
#
# Tolerant like every listing built for an error message: a failing list must
# not replace the message with its own.
sub _node_names {
    my ($self, $secrets) = @_;

    return () unless $secrets->has_kubeconfig;
    my $kubeconfig = $secrets->read_kubeconfig or return ();

    my $k8s   = eval { OCP::Kubernetes->new(kubeconfig => $kubeconfig) } or return ();
    my $nodes = eval { $k8s->list_nodes }                               or return ();

    return sort grep { length } map { $k8s->node_name($_) } @$nodes;
}

# Resolve --node to an SSH target. Returns the host string, or undef when
# nothing matches -- the caller hands that to _unknown_node_error.
#
# The raw YAML field is normalised into a list of CPs: single-CP clusters
# store control_planes as a hash, multi-CP clusters (the canonical case is
# mixed hetzner+ssh) store it as an arrayref. The previous dispatch read
# $cp_spec->{provider} unconditionally, which threw 'Not a HASH reference'
# the moment a project had more than one control plane -- bypassing
# _unknown_node_error entirely (karr #117).
#
# Hetzner CPs follow the RoboCop naming (police1, police2, ...), ssh CPs
# are named after their host's first label. The walk below matches the
# node arg against that identity so a `ocp ssh --node police1` on a mixed
# cluster reaches the hetzner CP, not whichever provider the first entry
# happens to be.
#
# Anything that does not match a CP falls through to the legacy
# police/cp regex (API lookup), and from there to the IP/hostname path
# -- the same cascade that `ocp ssh --node 1.2.3.4` always used.
sub _resolve_target_host {
    my ($self, $config, $secrets, $node_arg) = @_;

    my $raw = $config->spec->{control_planes};
    my $cps = ref $raw eq 'ARRAY' ? $raw
            : ref $raw eq 'HASH'  ? [ $raw ]
            :                          [ {} ];

    my $het_index = 0;
    for my $cp (@$cps) {
        my $cp_name;
        if (($cp->{provider} // '') eq 'ssh' && $cp->{host}) {
            ($cp_name = $cp->{host}) =~ s/\..*//;
        } else {
            $het_index++;
            $cp_name = 'police' . $het_index;
        }
        next unless $cp_name && $node_arg eq $cp_name;

        if (($cp->{provider} // '') eq 'ssh') {
            return $cp->{host};
        }
        print "[..] Looking up control plane IP via Kubernetes API...\n";
        return $self->_lookup_node_ip($secrets, $node_arg);
    }

    # No exact identity match. The legacy /^(police|cp)/ regex: anything
    # that looks like a CP name is API-looked-up; anything else is an IP.
    if ($node_arg eq 'police1' || $node_arg =~ /^police\d+$/ || $node_arg =~ /^cp/) {
        print "[..] Looking up control plane IP via Kubernetes API...\n";
        return $self->_lookup_node_ip($secrets, $node_arg);
    }

    return $node_arg;
}

# Why --node did not resolve to anything to connect to.
#
# Two different truths, so two different sentences. A name nothing answers to
# gets the house rejection — name the word, then say what would have worked
# (karr #67, #89, #103). A name that DOES match a node the API knows is not a
# typo at all: that node simply has no address recorded, and calling it
# unknown would be false. The same rule as the type hint in
# OCP::Role::Cmd::provider_cr — a claim about the input is made only where it
# is true.
#
# What gets listed is what this command could actually have used: Kubernetes
# node names. Not OCPNode CRs — a CR whose machine has not joined yet is
# nothing `ocp ssh` can reach, so offering it would be a lie of its own.
sub _unknown_node_error {
    my ($self, $node_arg, @names) = @_;

    # The same match _lookup_node_ip makes, so "known but without an address"
    # means the same thing in both places.
    my ($matched) = grep { /\Q$node_arg\E/i } @names;

    return "Node '$matched' has no address in the Kubernetes API.\n"
         . "Connect by address instead: ocp ssh --node <ip>\n"
        if defined $matched;

    return OCP::Choices::unknown('node', $node_arg, [@names],
        empty => "No node list could be read from the Kubernetes API"
               . " (no kubeconfig in this project, or the API did not answer).\n");
}

sub _lookup_node_ip {
    my ($self, $secrets, $node_name) = @_;

    return undef unless $secrets->has_kubeconfig;

    my $kubeconfig = $secrets->read_kubeconfig
        or return undef;

    my $k8s = OCP::Kubernetes->new(kubeconfig => $kubeconfig);

    for my $node (@{ $k8s->list_nodes }) {
        my $name = $k8s->node_name($node);
        next unless $name =~ /\Q$node_name\E/i;

        my $ip = $k8s->node_external_ip($node);
        return $ip if $ip;

        $ip = $k8s->node_internal_ip($node);
        return $ip if $ip;
    }

    return undef;
}

1;

__END__

=head1 NAME

OCP::Cmd::SSH - SSH into a cluster node with the key it trusts

=head1 SYNOPSIS

    # SSH into control plane
    ocp ssh --node police1

    # SSH into node by IP
    ocp ssh --node 1.2.3.4

    # SSH into worker
    ocp ssh --node worker-1

=head1 DESCRIPTION

Connects to a cluster node with the key that node trusts, which
L<OCP::ClusterKey> picks:

=over 4

=item *

B<Secure mode> — the admin key from F<keys.yaml>, on every provider, which
costs a PIN2 prompt. This is the human tier: only someone with PIN2 gets a
shell on a cluster machine. Robocop holds the robo key (C<purpose:
automation>) and cannot use it.

=item *

B<Dev mode> (C<--nopassword>, no F<keys.yaml>) — F<.ocp/id_ed25519>, with no
prompt at all. There is no admin key in such a project; this command used to
ask for PIN2 anyway and could only fail.

=back

If the connection is refused while F<.ocp/id_ed25519> is still in the
project, the command says what that usually means: machines authorised before
the bootstrap key was removed from secure mode carry the wrong public key.
See L<OCP::ClusterKey/migration_hint>. It never falls back to that key.

=head1 OPTIONS

=head2 --node <name|ip>

Node name or IP address to SSH into.

A name that resolves to nothing is refused with the node names the
Kubernetes API does answer to:

    Unknown node 'police1'.
    Available: cp-lab, otho-gpu

A name that I<does> match a known node but has no address recorded is a
different fact and gets a different sentence — it is not a typo, so it is not
called unknown.

=cut
