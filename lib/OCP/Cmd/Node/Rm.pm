package OCP::Cmd::Node::Rm;
# ABSTRACT: Remove an OCPNode (drain, teardown, delete)

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use List::Util qw(first);
use OCP::Choices;
use OCP::Config;
use OCP::Secrets;
use OCP::K8s;
use OCP::Node;
use OCP::Provider;

with 'OCP::Role::Cmd';

option name => (
    is     => 'ro',
    format => 's',
    doc    => 'Node name (may also be given as the first argument)',
);

# k229: the way out for a node whose machine cannot be cleaned up -- one that
# never reached its host fails the ssh uninstall on every attempt, and its
# OCPNode (finalizer included) stays. Named for what it costs, not for what
# it forces: the machine is left exactly as it is, and the command says so.
option keep_machine => (
    is  => 'ro',
    doc => 'Remove the OCPNode but leave its machine as it is: no server delete, no uninstall',
);

has k8s => (is => 'rw');

# The project's ocp.yaml, read once: the kubeconfig and the cluster SSH key
# both hang off it.
has _config => (is => 'lazy');

sub _build__config {
    my $self = shift;
    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;
    return OCP::Config->new(file => $file);
}

sub _k8s {
    my $self = shift;
    return $self->k8s if $self->k8s;

    my $config  = $self->_config;
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    my $kc_content = $secrets->read_kubeconfig;
    die "ERROR: Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n"
        unless $kc_content;

    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print {$kc_fh} $kc_content;
    close $kc_fh;

    my $api = Kubernetes::REST::Kubeconfig->new(
        kubeconfig_path => $kc_fh->filename,
    )->api;

    OCP::K8s->register($api);
    $self->k8s($api);
    return $api;
}

# The OCPNode CRs this cluster has, by name — for the rejection above and
# nothing else. `ocp node ls` shows the same set with its columns; here only
# the names matter, because a name is what `ocp node rm` takes.
#
# Tolerant on purpose, exactly like OCP::Role::Cmd::provider_crs: a list call
# that fails while a message is being built must not replace "that node does
# not exist" with something worse. No list means the rejection says so
# instead of offering an empty one.
#
# Private rather than a sibling of provider_crs in the role: one command
# needs it. provider_crs earned its place there by having three callers.
sub _node_names {
    my ($self, $api, $ns) = @_;

    my $list = eval { $api->list('OCPNode', namespace => $ns) } or return ();

    return sort map { $api->k8s->object_to_struct($_)->{metadata}{name} }
                @{ $list->items // [] };
}

sub execute {
    my ($self, $args, $chain) = @_;

    # MooX::Cmd hands over the command line as typed, options included, so
    # the name is the first word that is not one: `ocp node rm --keep-machine
    # crag` must not try to remove a node called "--keep-machine".
    my $name = $self->name // first { !/^-/ } @{ $args // [] };
    die "Usage: ocp node rm NAME [--keep-machine]\n" unless defined $name && length $name;

    my $api  = $self->_k8s;
    my $ns   = 'ocp-system';

    my $cr_obj = eval {
        $api->get('OCPNode', name => $name, namespace => $ns);
    };
    if ($@ || !$cr_obj) {
        die OCP::Choices::unknown('node', $name, [ $self->_node_names($api, $ns) ],
            empty => "No OCPNode exists in this cluster;"
                   . " 'ocp node add' creates one.\n");
    }

    my $cr = $api->k8s->object_to_struct($cr_obj);

    return $self->_remove_keeping_machine($api, $ns, $cr) if $self->keep_machine;

    my $provider = $self->_provider($api, $ns, $cr->{spec}{providerRef}, $name);

    my $node = OCP::Node->from_cr(
        $cr,
        k8s      => $api,
        ($provider ? (provider => $provider) : ()),
    );

    # Dies when the node could not be taken off its machine, with the reason;
    # the OCPNode stays (phase Failed) so running this again retries. bin/ocp
    # puts that on STDERR and exits 1 -- "removed" is only ever printed for a
    # node that really is gone (k175).
    #
    # When it was the machine that could not be cleaned up, the error also
    # says what else there is to do (k229). That part is said here and not in
    # OCP::Node: robocop runs the same teardown, and --keep-machine is a flag
    # of this command.
    eval { $node->teardown; 1 } or do {
        my $err = $@;
        die $err unless $node->machine_cleanup_failed;
        die $err . $self->_keep_machine_hint($api, $ns, $cr);
    };
    print "Node '$name' removed.\n";
    return 0;
}

# --keep-machine: the same teardown minus the provider step. No provider is
# built for it -- the machine is not contacted, so there is no cluster key to
# unlock and no PIN2 to ask for, and an OCPNodeProvider that is gone does not
# stand in the way. What was left running is part of the result, so it goes
# to STDOUT with "removed": it is not an error, it is what was asked for.
sub _remove_keeping_machine {
    my ($self, $api, $ns, $cr) = @_;
    my $name = $cr->{metadata}{name};

    OCP::Node->from_cr($cr, k8s => $api)->teardown(keep_machine => 1);

    print "Node '$name' removed. Its machine was not touched:\n";
    print '  ' . $self->_machine_left($api, $ns, $cr);
    return 0;
}

# The way out, appended to a teardown that failed at the machine. Strongest
# for a node that never joined -- no Kubernetes node name, no join time on
# record -- because that is the case it was made for: a machine OCP never got
# onto has nothing to uninstall, and retrying cannot succeed.
sub _keep_machine_hint {
    my ($self, $api, $ns, $cr) = @_;
    my $name   = $cr->{metadata}{name};
    my $status = $cr->{status} // {};
    my $joined = $status->{kubernetesNodeName} || $status->{joinedAt};

    return ($joined
        ? "If the machine is gone, or you will deal with it yourself, remove the\n"
        . "OCPNode without touching the machine:\n"
        : "This node never joined the cluster, so there may be nothing on the\n"
        . "machine to clean up. Remove the OCPNode without touching the machine:\n")
      . "  ocp node rm $name --keep-machine\n"
      . "Then check the machine by hand:\n"
      . '  ' . $self->_machine_left($api, $ns, $cr);
}

# What --keep-machine leaves behind, in the terms of the machine's provider.
# The type comes from the OCPNodeProvider when it can still be read, else from
# what the OCPNode itself recorded: a provider id is a cloud server, an
# address without one is a host OCP was pointed at.
sub _machine_left {
    my ($self, $api, $ns, $cr) = @_;
    my $status = $cr->{status} // {};
    my $id     = $status->{providerId};
    my $host   = $status->{publicIP} || $cr->{spec}{host};
    my $type   = $self->_provider_type($api, $ns, $cr->{spec}{providerRef})
              // (defined $id && length $id ? 'hetzner' : $host ? 'ssh' : '');

    if ($type eq 'hetzner') {
        return "no Hetzner server was recorded for it (no providerId); if provisioning\n"
             . "  got as far as creating one, 'ocp hetzner list' shows it.\n"
            unless defined $id && length $id;
        return "Hetzner server $id" . ($host ? " ($host)" : '')
             . " keeps running and is billed\n"
             . "  until you delete it in the Hetzner project.\n";
    }
    return 'if RKE2/K3s got installed on ' . $host . ", it is still there -- and a running\n"
         . "  agent registers its Node again. Uninstall it on the host\n"
         . "  (rke2-uninstall.sh, k3s-agent-uninstall.sh).\n"
        if $host;
    return "nothing recorded says where it is; check your provider.\n";
}

# The OCPNodeProvider's spec.type, or undef. Tolerant: this only words a
# message, and a provider that cannot be read must not replace it.
sub _provider_type {
    my ($self, $api, $ns, $provider_name) = @_;
    return undef unless $provider_name;
    my $obj = eval {
        $api->get('OCPNodeProvider', name => $provider_name, namespace => $ns);
    } or return undef;
    return $api->k8s->object_to_struct($obj)->{spec}{type};
}

# The provider that takes the node off its machine, or undef for a node that
# names none.
#
# Every failure to build one is fatal, before anything is touched. This used
# to fall back to a teardown without a provider, which deletes the Node and the
# OCPNode and leaves the machine as it is: a Hetzner server billing with no
# record left in the cluster, an ssh worker still running rke2-agent (k175).
#
# An ssh provider needs the cluster key -- the CR carries none (ADR 0027), and
# without one the adapter's ssh logged in with no identity at all. Asked for
# only when it is needed: a Hetzner node is deleted through the API and must
# not grow a PIN2 prompt it never had.
#
# A provider that is gone is a machine nobody can clean up through OCP any
# more, so its refusal offers --keep-machine as well (k229).
sub _provider {
    my ($self, $api, $ns, $provider_name, $node_name) = @_;
    return unless $provider_name;

    my $prov_obj = eval {
        $api->get('OCPNodeProvider', name => $provider_name, namespace => $ns);
    };
    die "Cannot load OCPNodeProvider/$provider_name, which this node was created\n"
      . 'through: ' . ($@ || "not found\n")
      . "Without it the machine cannot be cleaned up; nothing was removed.\n"
      . "Restore the provider ('ocp apply' or 'ocp provider add') and run this again,\n"
      . "or remove the node and leave its machine as it is:\n"
      . "  ocp node rm $node_name --keep-machine\n"
        unless $prov_obj;

    my $prov_cr = $api->k8s->object_to_struct($prov_obj);

    my %key;
    if (($prov_cr->{spec}{type} // '') eq 'ssh') {
        my $key = $self->cluster_ssh_key($self->_config,
            provider => 'ssh',
            reason   => 'ocp node rm',
        );
        %key = (ssh_key_path => $key->path);
    }

    my $provider = eval { OCP::Provider->from_cr($prov_cr, k8s => $api, %key) };
    die "Cannot build provider '$provider_name': $@"
      . "Nothing was removed.\n"
        unless $provider;

    return $provider;
}

1;

__END__

=head1 NAME

OCP::Cmd::Node::Rm - Remove an OCPNode (drain, teardown, delete)

=head1 SYNOPSIS

    ocp node rm worker-1

    # A node whose machine cannot be cleaned up, e.g. one that never
    # reached its host: remove the OCPNode, leave the machine alone
    ocp node rm worker-1 --keep-machine

=head1 DESCRIPTION

Looks up the named OCPNode CR, resolves its provider, and calls
L<OCP::Node/Teardown>.  Teardown marks the node C<Terminating>, cordons and
drains it in Kubernetes, deletes the provider server (C<hetzner>) or
uninstalls RKE2/K3s from it (C<ssh>, C<local>), removes the Kubernetes node
object, and deletes the CR.

For an C<ssh> node the machine is reached with the cluster key, the one
C<ocp node add> installed it with; in secure mode that costs the PIN2 prompt.
A C<hetzner> node is deleted through the API and asks for no key.

B<A node that could not be taken off its machine is not removed.>  When the
provider cannot be loaded, the drain does not finish, or the server delete or
uninstall fails, the command says why on STDERR and exits 1.  The OCPNode is
kept with phase C<Failed> and the reason as its message (C<ocp node ls>
shows it); running C<ocp node rm> again retries.

When it was the machine that could not be cleaned up -- the server delete or
the uninstall failed -- the error ends with the way out, C<--keep-machine>, and
what to check by hand afterwards.  It says so most plainly for a node that
never joined the cluster: an ssh node that never reached its host fails the
uninstall on every retry, for the same reason it failed to install.

B<Host key first.>  For an C<ssh> or C<local> node, where the teardown contacts the
machine, the host key is checked against the pins in C<status.hostKeys> before
anything is changed (L<OCP::Node/host_key_mismatch_message>): no lease, no
C<Terminating>, no cordon, no drain.  A machine that is not the pinned one
ends the command with the "host key of ... changed" message and
C<ocp node trust-host NAME> as the way out; the node stays as it was.  Not
checked: a node without pins, a machine that does not answer, a Hetzner node
(deleted through the API) and C<--keep-machine> (no contact).

B<robocop and this command.>  Deleting a worker OCPNode through the API
(C<ocp.internal/teardown> finalizer) leaves the teardown to robocop; this
command does the teardown itself, whether or not robocop runs, and removes
the finalizer before it deletes the OCPNode.  Both hold the node's lease
while they work, so while robocop tears a node down (or provisions it) this
command refuses with the lease holder named and touches nothing -- run it
again once that is done.  An OCPNode deleted through the API while no robocop
runs stays at its finalizer; this command is how it goes.

A name that matches no OCPNode is refused with the ones that exist, and
nothing is torn down:

    Unknown node 'wroker-1'.
    Available: cp-lab, otho-gpu, worker-1

=head1 OPTIONS

=head2 --keep-machine

Removes the node without touching its machine: the same teardown -- lease,
cordon and drain (both find nothing to do for a node that never registered),
the Kubernetes Node, the C<ocp.internal/teardown> finalizer, the OCPNode --
minus the server delete or uninstall.  No provider is built for it, so no
cluster key or PIN2 is asked for, and a missing OCPNodeProvider does not stop
it.

What was left as it is goes to STDOUT with the result: a Hetzner server keeps
running and is billed until it is deleted in the Hetzner project (its id is
named); on an C<ssh> or C<local> host an RKE2/K3s install, if one got that
far, is still there, and a running agent registers its Node again.

Never the default and never implied: without the option a machine that cannot
be cleaned up keeps its OCPNode.

=head1 SEE ALSO

L<OCP::Node>, L<OCP::Cmd::Node::Add>, L<OCP::Cmd::Node::Ls>

=cut
