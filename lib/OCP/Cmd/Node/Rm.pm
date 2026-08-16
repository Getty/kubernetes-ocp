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

sub _k8s {
    my $self = shift;
    return $self->k8s if $self->k8s;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config  = OCP::Config->new(file => $file);
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

    my $provider;
    my $provider_name = $cr->{spec}{providerRef};
    if ($provider_name) {
        my $prov_obj = eval {
            $api->get('OCPNodeProvider', name => $provider_name, namespace => $ns);
        };
        if ($prov_obj) {
            my $prov_cr = $api->k8s->object_to_struct($prov_obj);
            $provider = eval { OCP::Provider->from_cr($prov_cr, k8s => $api) };
        }
    }

    my $node = OCP::Node->from_cr(
        $cr,
        k8s      => $api,
        ($provider ? (provider => $provider) : ()),
    );

    $node->teardown;
    print "Node '$name' removed.\n";
    return 0;
}

1;

__END__

=head1 NAME

OCP::Cmd::Node::Rm - Remove an OCPNode (drain, teardown, delete)

=head1 SYNOPSIS

    ocp node rm worker-1

=head1 DESCRIPTION

Looks up the named OCPNode CR, resolves its provider, and calls
L<OCP::Node/teardown>.  Teardown marks the node C<Terminating>, cordons it
in Kubernetes, deletes the provider server, removes the Kubernetes node
object, and deletes the CR.

A name that matches no OCPNode is refused with the ones that exist, and
nothing is torn down:

    Unknown node 'wroker-1'.
    Available: cp-lab, otho-gpu, worker-1

=head1 SEE ALSO

L<OCP::Node>, L<OCP::Cmd::Node::Add>, L<OCP::Cmd::Node::Ls>

=cut
