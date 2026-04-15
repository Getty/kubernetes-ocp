package OCP::Cmd::Node::Rm;
# ABSTRACT: Remove an OCPNode (drain, teardown, delete)

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use OCP::Config;
use OCP::Secrets;
use OCP::K8s;
use OCP::Node;
use OCP::Provider;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

option name => (
    is       => 'ro',
    format   => 's',
    required => 1,
    doc      => 'Node name',
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

sub execute {
    my ($self, $args, $chain) = @_;

    my $api  = $self->_k8s;
    my $name = $self->name;
    my $ns   = 'ocp-system';

    my $cr_obj = eval {
        $api->get('OCPNode', name => $name, namespace => $ns);
    };
    die "Node '$name' not found\n" if $@ || !$cr_obj;

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
