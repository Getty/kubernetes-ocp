package OCP::Cmd::SSH;
# ABSTRACT: SSH into a cluster node with the key it trusts

use Moo;
use MooX::Cmd;
use MooX::Options;
use OCP;
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
    my $target_host;

    # Try to find node in spec
    my $spec = $config->spec;
    my $cp_spec = $spec->{control_planes};

    # Check if it's a control plane node
    if ($node_arg eq 'police1' || $node_arg =~ /^police\d+$/ || $node_arg =~ /^cp/) {
        if ($cp_spec->{provider} eq 'ssh') {
            $target_host = $cp_spec->{host};
        } elsif ($cp_spec->{provider} eq 'hetzner') {
            # Look up the node's IP via the Kubernetes API
            print "[..] Looking up control plane IP via Kubernetes API...\n";
            $target_host = $self->_lookup_node_ip($secrets, $node_arg);
        }
    } else {
        # Assume it's an IP or hostname
        $target_host = $node_arg;
    }

    unless ($target_host) {
        die "ERROR: Could not determine host for node: $node_arg\n";
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

=cut
