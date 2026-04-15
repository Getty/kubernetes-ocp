package OCP::Cmd::Provider::Ls;
# ABSTRACT: List OCPNodeProvider CRs

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use OCP::Config;
use OCP::Secrets;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

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

    $self->k8s($api);
    return $api;
}

sub execute {
    my ($self, $args, $chain) = @_;

    my $api = $self->_k8s;
    my $ns  = 'ocp-system';

    my $providers = $api->get(
        path => "/apis/ocp.internal/v1/namespaces/$ns/ocpnodeproviders",
    );
    my $nodes = $api->get(
        path => "/apis/ocp.internal/v1/namespaces/$ns/ocpnodes",
    );

    my %refs;
    for my $n (@{ $nodes->{items} // [] }) {
        my $ref = $n->{spec}{providerRef} or next;
        $refs{$ref}++;
    }

    printf "%-14s %-9s %-10s %-8s %s\n", qw(NAME TYPE LOCATION DEFAULT NODES);
    for my $p (@{ $providers->{items} // [] }) {
        my $name = $p->{metadata}{name};
        my $type = $p->{spec}{type} // '';
        my $loc  = $type eq 'hetzner' ? ($p->{spec}{hetzner}{location} // '') : '';
        my $def  = ($p->{metadata}{annotations}{'ocp.internal/default'} // '') eq 'true' ? '*' : '';
        my $cnt  = $refs{$name} // 0;
        printf "%-14s %-9s %-10s %-8s %d\n", $name, $type, $loc, $def, $cnt;
    }
}

1;
