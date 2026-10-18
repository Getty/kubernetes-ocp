package OCP::Cmd::SSH;
# ABSTRACT: SSH into a cluster node with the key it trusts

use Moo;
use MooX::Cmd;
use MooX::Options;
use OCP;
use OCP::Choices;
use OCP::ClusterKey;
use OCP::Config;
use OCP::K8s;
use OCP::Kubernetes;
use OCP::Node;
use OCP::Secrets;
use OCP::SSH;
use Path::Tiny qw(path);

with 'OCP::Role::Cmd';

# The OCPNode --node resolved to, as an OCP::Node bound to the cluster API
# (k235): its status.hostKeys are what the connection is verified against.
# Unset for a control plane or an address -- those stay on the project's
# known_hosts, as decided in k171.
has _target_node => (is => 'rw');

option node => (
    is     => 'ro',
    format => 's',
    doc    => 'Node name or IP to SSH into',
);

# This command used to unlock the admin key by hand and demand PIN2
# unconditionally — including in a --nopassword project, which has no
# keys.yaml at all and where the prompt could only ever end in "Wrong PIN2 or
# no admin-key found". k94 filed the mirror image of that: at the time,
# `provider: ssh` machines trusted the bootstrap key, so PIN2 bought a key the
# machine did not know.
#
# Both disappear into OCP::ClusterKey. Secure mode reaches every machine with
# the admin key on every provider, so k94's premise is gone: PIN2 here is
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
        die "Usage: ocp ssh --node <name|ip> [-- COMMAND ...]\n";
    }

    # Before any prompt: a stray word is refused while nothing has been asked.
    my @command = $self->_remote_command($args);

    my $secure = -f $config->project_dir->child('keys.yaml');

    # This command's payload is the interactive session ->interactive execs
    # into, which inherits STDOUT. So all of ocp's own framing goes to STDERR
    # to keep STDOUT clean for the remote shell (house rule: STDOUT is the
    # payload, everything else is diagnosis).
    print STDERR "╔═══════════════════════════════════════════════════════════════╗\n";
    printf STDERR "║  %-60s║\n", $secure
        ? 'ADMIN-SSH ACCESS (requires PIN2)'
        : 'SSH ACCESS (dev mode: .ocp/id_ed25519, no PIN)';
    print STDERR "╚═══════════════════════════════════════════════════════════════╝\n\n";

    # PIN1 if the age key is still locked: _lookup_node_ip below decrypts
    # kubeconfig.yaml with it, and it is a no-op once .ocp/age.key is there.
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    $secrets->ensure_age_key();

    # OCP::ClusterKey prompts for PIN2 itself where one is needed, unlocks the
    # age key on the way, and owns the temp file it writes — the hand-rolled
    # File::Temp here had UNLINK => 1 but no owner for the .pub Rex-style
    # callers expect.
    #
    # OCP::ClusterKey explains its PIN2 prompt with plain prints -- narration
    # for `ocp apply`, but here it would land in the payload, ahead of what a
    # remote command prints (k229). This command's framing is STDERR, so that
    # is where those lines go too.
    my $was = select STDERR;
    my $key = eval { $self->cluster_ssh_key($config, reason => 'ocp ssh') };
    my $key_err = $@;
    select $was;
    die $key_err unless $key;
    print STDERR "[ok] " . $key->describe . "\n";

    # Determine target host
    my $target_host = $self->_resolve_target_host($config, $secrets, $node_arg);

    unless ($target_host) {
        die $self->_unknown_node_error($node_arg, $self->_node_names($secrets));
    }

    print STDERR "[ok] Target: $target_host\n";
    print STDERR "[..] Connecting...\n\n";

    my $node = $self->_target_node;
    my $ssh = OCP::SSH->new(
        host     => $target_host,
        key_file => $key->path,
        # An OCPNode's pins, not the project's file (k235).
        ($node ? (known_hosts => $node->known_hosts_for($target_host)) : ()),
    );
    $self->_check_node_host_key($node, $ssh, $target_host) if $node;

    # ->interactive execs, so this process is gone the moment it runs and
    # cannot report anything afterwards. Where a lockout is plausible — an
    # admin key, and a bootstrap key still lying in the project — probe first
    # with a batch-mode connection and say what a refusal probably means.
    #
    # The probe never blocks the session: it warns and hands over anyway. It
    # is skipped unless migration_hint has something to say -- apart from an
    # OCPNode target, which always gets one connection of its own first, for
    # the host key check above (k235).
    if (my $hint = $key->migration_hint) {
        unless ($ssh->is_reachable) {
            print STDERR "[!!] $target_host did not accept the admin key.\n";
            print STDERR $hint;
            print STDERR "\nHanding over to ssh anyway — its own error follows.\n\n";
        }
    }

    # With a command, ssh runs it instead of a shell (k229). The process is
    # replaced all the same, so what the command prints is this command's
    # STDOUT -- the payload, nothing of ocp's own in between -- and its exit
    # status is ocp's.
    $ssh->interactive(@command);

    return 0;
}

# The host key of an OCPNode, checked before the session is handed over
# (k235): ->interactive execs and cannot report afterwards. One batch-mode
# connection, against the pins of the OCPNode: a changed key ends the command
# with the message every other refusal uses, trust-host included; a node
# without pins is trusted on this first contact and pinned, what the install
# does. A machine that does not answer is not this check's business -- ssh's
# own error follows -- but whatever it recorded before failing is pinned.
sub _check_node_host_key {
    my ($self, $node, $ssh, $host) = @_;

    eval { $ssh->run('true'); 1 } or do {
        my $err = $@;
        die $node->host_key_message($host) . "\n"
            if ref $err && $err->isa('OCP::SSH::HostKeyChanged');
        die $err;
    };
    eval { $node->pin_host_keys($host); 1 } or do {
        my $err = $@;
        chomp $err;
        print STDERR "[!!] Could not pin the host key of " . $node->name . ": $err\n";
    };
    return;
}

# The command to run on the node: everything after `--`, verbatim (k229).
#
# MooX::Cmd hands execute the command line as typed, options included, and
# MooX::Options stops reading options at the `--`, so what follows it is
# nobody's but the remote command's -- `ocp ssh --node crag -- ls -la` keeps
# its -la. Without the `--` an option of the command would be read as one of
# ours and refused by Getopt.
#
# A word before the `--` that is neither an option nor an option's value is
# refused, not dropped: `ocp ssh --node crag uptime` would otherwise open a
# shell and quietly ignore the uptime. Which options take a value is asked
# of MooX::Options, abbreviations included, the way Getopt reads them.
sub _remote_command {
    my ($self, $args) = @_;

    my @args = @{ $args // [] };
    my (@before, $dashes);
    while (@args) {
        my $arg = shift @args;
        if ($arg eq '--') { $dashes = 1; last }
        push @before, $arg;
    }

    my %options = $self->_options_data;
    my @valued  = grep { $options{$_}{format} } keys %options;

    while (defined(my $arg = shift @before)) {
        if ($arg =~ /^--?([\w-]+)$/) {
            (my $opt = $1) =~ tr/-/_/;
            shift @before if grep { index($_, $opt) == 0 } @valued;
            next;
        }
        next if $arg =~ /^-/;
        die "Unexpected argument '$arg'. A command to run on the node goes after '--':\n"
          . '  ocp ssh --node ' . ($self->node // '<name|ip>') . " -- $arg\n";
    }

    return $dashes ? @args : ();
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
# not replace the message with its own -- each of the two lists below fails on
# its own.
#
# The OCPNodes are listed too since k229, those with an address: that is what
# _lookup_by_name connects to, so a worker that has not joined but has a host
# is something this command can reach. One without an address still is not,
# and is not offered.
sub _node_names {
    my ($self, $secrets) = @_;

    my $k8s = eval { $self->_kubernetes($secrets) } or return ();

    my $nodes = eval { $k8s->list_nodes } // [];
    my @names = map { $k8s->node_name($_) } @$nodes;

    my $crs = eval {
        my $api = $k8s->api;
        OCP::K8s->register($api);
        [ map { $api->k8s->object_to_struct($_) }
              @{ $api->list('OCPNode', namespace => 'ocp-system')->items // [] } ];
    } // [];
    push @names, map  { $_->{metadata}{name} }
                 grep { $_->{status}{publicIP} || $_->{spec}{host} } @$crs;

    my %seen;
    return sort grep { length && !$seen{$_}++ } @names;
}

# Resolve --node to an SSH target. Returns the host string, or undef when
# nothing matches -- the caller hands that to _unknown_node_error.
#
# The raw YAML field is normalised into a list of CPs: single-CP clusters
# store control_planes as a hash, multi-CP clusters (the canonical case is
# mixed hetzner+ssh) store it as an arrayref. The previous dispatch read
# $cp_spec->{provider} unconditionally, which threw 'Not a HASH reference'
# the moment a project had more than one control plane -- bypassing
# _unknown_node_error entirely (k117).
#
# Hetzner CPs follow the RoboCop naming (police1, police2, ...), ssh CPs
# are named after their host's first label. The walk below matches the
# node arg against that identity so a `ocp ssh --node police1` on a mixed
# cluster reaches the hetzner CP, not whichever provider the first entry
# happens to be.
#
# Anything that does not match a CP falls through to the legacy
# police/cp regex (API lookup), then to the node of exactly that name
# (OCPNode, then Kubernetes Node; k229), and from there to the IP/hostname
# path -- the same cascade that `ocp ssh --node 1.2.3.4` always used.
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
            # The name cp_identity gives it, IP hosts included (k218).
            require OCP::Cmd::Apply::Bootstrap;
            ($cp_name) = OCP::Cmd::Apply::Bootstrap::host_name_parts($cp->{host});
        } else {
            $het_index++;
            $cp_name = 'police' . $het_index;
        }
        next unless $cp_name && $node_arg eq $cp_name;

        if (($cp->{provider} // '') eq 'ssh') {
            return $cp->{host};
        }
        print STDERR "[..] Looking up control plane IP via Kubernetes API...\n";
        return $self->_lookup_node_ip($secrets, $node_arg);
    }

    # No exact identity match. The legacy /^(police|cp)/ regex: anything
    # that looks like a CP name is API-looked-up, as it always was. Only what
    # that finds nothing for is asked by its exact name as well (k229) -- a
    # worker called cpu-1 is a worker, whatever its first letters say.
    if ($node_arg eq 'police1' || $node_arg =~ /^police\d+$/ || $node_arg =~ /^cp/) {
        print STDERR "[..] Looking up control plane IP via Kubernetes API...\n";
        return $self->_lookup_node_ip($secrets, $node_arg)
            // $self->_lookup_by_name($secrets, $node_arg);
    }

    # A worker, by the name `ocp node ls` shows (k229). It used to fall
    # straight through to the hostname path below, so `ocp ssh --node crag`
    # ended in "Could not resolve hostname crag" for a node whose address the
    # cluster had all along. An IP is not a node name, and asking the API
    # about one would only cost a round trip.
    unless ($node_arg =~ /^[\d.]+$/ || $node_arg =~ /:/) {
        my $address = $self->_lookup_by_name($secrets, $node_arg);
        return $address if defined $address;
    }

    return $node_arg;
}

# The address of the node called exactly $name, or undef when nothing in the
# cluster has that name (k229).
#
# The OCPNode first, its address in the order OCP::Node::_resolve_host uses:
# status.publicIP, then spec.host. That is the address OCP installed the
# machine over, so it is the one its SSH answers on; the Kubernetes Node's
# addresses are what the kubelet reports, which may be a private one (k174).
# Then the Kubernetes Node of exactly that name, ExternalIP before InternalIP
# like _lookup_node_ip -- but not by substring: "crag" must not reach
# "crag-2".
#
# A node that exists and has no address yet is not "nothing called that":
# that dies with what is missing, instead of handing the name to ssh as a
# hostname. An API that does not answer is said on STDERR and leaves the
# hostname path to try.
sub _lookup_by_name {
    my ($self, $secrets, $name) = @_;

    my $k8s = $self->_kubernetes($secrets) or return undef;

    my ($cr, $node);
    my $ok = eval {
        my $api = $k8s->api;
        OCP::K8s->register($api);
        $cr   = $self->_get_or_undef($api, 'OCPNode', name => $name, namespace => 'ocp-system');
        $node = $self->_get_or_undef($api, 'Node',    name => $name);
        1;
    };
    unless ($ok) {
        my $err = $@;
        chomp $err;
        print STDERR "[!!] Could not look up node '$name' in the cluster API: $err\n"
                   . "     Trying '$name' as a hostname.\n";
        return undef;
    }

    if ($cr) {
        # Whatever address ends up used, the pins are this OCPNode's (k235).
        $self->_target_node(OCP::Node->from_cr($cr, k8s => $k8s->api));
        my $address = $cr->{status}{publicIP} || $cr->{spec}{host};
        return $address if $address;
    }
    if ($node) {
        my $address = $k8s->node_external_ip($node) || $k8s->node_internal_ip($node);
        return $address if $address;
    }
    return undef unless $cr || $node;

    die $self->_unknown_node_error($name, $name) unless $cr;
    die "OCPNode '$name' has no address yet (phase "
      . ($cr->{status}{phase} // 'Pending')
      . ': no status.publicIP, no spec.host), and no Kubernetes node of that name has one.'
      . "\nConnect by address instead: ocp ssh --node <ip>\n";
}

# A get that answers a 404 with undef, the way OCP::Node::_get_cr draws the
# line: absent is an answer, every other failure is not.
sub _get_or_undef {
    my ($self, $api, $kind, %args) = @_;
    my $obj = eval { $api->get($kind, %args) };
    if (my $err = $@) {
        die $err unless $err =~ /\b404\b/;
        return undef;
    }
    return $obj && $kind eq 'OCPNode' ? $api->k8s->object_to_struct($obj) : $obj;
}

# The cluster API as OCP::Kubernetes, from the project's kubeconfig, or undef
# when the project has none.
sub _kubernetes {
    my ($self, $secrets) = @_;
    return undef unless $secrets->has_kubeconfig;
    my $kubeconfig = $secrets->read_kubeconfig or return undef;
    return OCP::Kubernetes->new(kubeconfig => $kubeconfig);
}

# Why --node did not resolve to anything to connect to.
#
# Two different truths, so two different sentences. A name nothing answers to
# gets the house rejection — name the word, then say what would have worked
# (k67, k89, k103). A name that DOES match a node the API knows is not a
# typo at all: that node simply has no address recorded, and calling it
# unknown would be false. The same rule as the type hint in
# OCP::Role::Cmd::provider_cr — a claim about the input is made only where it
# is true.
#
# What gets listed is what this command could actually have used: Kubernetes
# node names, and since k229 the OCPNodes that have an address -- a worker
# that has not joined is reachable once its host is known, because
# _lookup_by_name connects to it by that. An OCPNode with no address is still
# left out: nothing `ocp ssh` can reach, so offering it would be a lie of its
# own. (_node_names makes that choice; this sub lists what it is given.)
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

    my $k8s = $self->_kubernetes($secrets) or return undef;

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

    # SSH into worker, by its OCPNode name -- joined or not
    ocp ssh --node worker-1

    # Run a command instead of a shell: its output on STDOUT, its exit
    # status as ocp's
    ocp ssh --node worker-1 -- uptime
    ocp ssh --node worker-1 -- journalctl -u rke2-agent -n 50 > agent.log

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

A target that is an OCPNode is verified against the host keys pinned in its
C<status.hostKeys>, not against the project's known_hosts.  One batch-mode
connection is made first, before the session is handed over: a changed key
ends the command with the same message every other refusal gives, naming
C<ocp node trust-host>; a node without pins is trusted on this first contact
and pinned.  A control plane or a bare address stays on the project's
known_hosts.

=head1 OPTIONS

=head2 --node <name|ip>

Node name or IP address to SSH into.  A name is looked for in this order:

=over 4

=item 1. a control plane of F<ocp.yaml> by its name (C<police1>, an ssh
control plane by its host's first label)

=item 2. a name that looks like a control plane's (C<police*>, C<cp*>): the
Kubernetes node whose name contains it

=item 3. the OCPNode of exactly that name, at C<status.publicIP>, else
C<spec.host> -- the address OCP installed it over, so a worker that never
joined is reachable too -- then the Kubernetes node of exactly that name, at
its ExternalIP, else its InternalIP

=item 4. otherwise the argument itself, as an IP address or hostname

=back

A control-plane-like name that resolves to nothing is refused with the names
this command could have reached -- Kubernetes nodes and OCPNodes that have an
address:

    Unknown node 'police1'.
    Available: cp-lab, crag, otho-gpu

A name that I<does> match a known node but has no address recorded is a
different fact and gets a different sentence — it is not a typo, so it is not
called unknown.  That holds for an OCPNode with no address yet as well: it is
refused naming its phase, instead of being handed to ssh as a hostname.

=head2 -- COMMAND ...

Everything after C<--> is run on the node instead of a login shell.  ssh joins
the words and the remote shell reads them, as with plain ssh.  The command's
output is this command's STDOUT and its exit status is C<ocp>'s, so it pipes
and scripts like ssh does; C<ocp>'s own framing stays on STDERR.

A word before the C<--> that is no option is refused with the form that would
have worked, rather than dropped:

    Unexpected argument 'uptime'. A command to run on the node goes after '--':
      ocp ssh --node crag -- uptime

=cut
