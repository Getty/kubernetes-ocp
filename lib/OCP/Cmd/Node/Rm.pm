package OCP::Cmd::Node::Rm;
# ABSTRACT: Remove an OCPNode (drain, teardown, delete)

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
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

    my $name = $self->name // ($args && $args->[0]);
    die "Usage: ocp node rm NAME\n" unless defined $name && length $name;

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

    my $provider = $self->_provider($api, $ns, $cr->{spec}{providerRef});

    my $node = OCP::Node->from_cr(
        $cr,
        k8s      => $api,
        ($provider ? (provider => $provider) : ()),
    );

    # Dies when the node could not be taken off its machine, with the reason;
    # the OCPNode stays (phase Failed) so running this again retries. bin/ocp
    # puts that on STDERR and exits 1 -- "removed" is only ever printed for a
    # node that really is gone (k175).
    $node->teardown;
    print "Node '$name' removed.\n";
    return 0;
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
sub _provider {
    my ($self, $api, $ns, $provider_name) = @_;
    return unless $provider_name;

    my $prov_obj = eval {
        $api->get('OCPNodeProvider', name => $provider_name, namespace => $ns);
    };
    die "Cannot load OCPNodeProvider/$provider_name, which this node was created\n"
      . 'through: ' . ($@ || "not found\n")
      . "Without it the machine cannot be cleaned up; nothing was removed.\n"
      . "Restore the provider ('ocp apply' or 'ocp provider add') and run this again.\n"
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

B<robocop and this command.>  Deleting a worker OCPNode through the API
(C<ocp.internal/teardown> finalizer) leaves the teardown to robocop; this
command does the teardown itself, whether or not robocop runs, and removes
the finalizer before it deletes the OCPNode.  Both hold the node's lease
while they work, so while robocop tears a node down (or provisions it) this
command refuses with the lease holder named and touches nothing -- run it
again once that is done.

A name that matches no OCPNode is refused with the ones that exist, and
nothing is torn down:

    Unknown node 'wroker-1'.
    Available: cp-lab, otho-gpu, worker-1

=head1 SEE ALSO

L<OCP::Node>, L<OCP::Cmd::Node::Add>, L<OCP::Cmd::Node::Ls>

=cut
