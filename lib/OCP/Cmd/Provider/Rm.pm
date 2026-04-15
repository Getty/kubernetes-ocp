package OCP::Cmd::Provider::Rm;
# ABSTRACT: Remove an OCPNodeProvider CR (and its Secret)

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use OCP::Config;
use OCP::Secrets;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

has name => (is => 'ro');

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

    my $api  = $self->_k8s;
    my $ns   = 'ocp-system';
    my $name = $self->name // ($args && $args->[0]);
    die "Usage: ocp provider rm NAME\n" unless $name;

    my $cr = eval {
        $api->get(path => "/apis/ocp.internal/v1/namespaces/$ns/ocpnodeproviders/$name")
    };
    die "Provider '$name' not found\n" if $@ || !$cr;

    my $nodes = $api->get(path => "/apis/ocp.internal/v1/namespaces/$ns/ocpnodes");
    my @refs  = grep { ($_->{spec}{providerRef} // '') eq $name }
                @{ $nodes->{items} // [] };

    if (@refs) {
        printf STDERR "Error: provider '%s' has %d referencing nodes:\n", $name, scalar @refs;
        for my $n (@refs) {
            printf STDERR "  %s (%s)\n",
                $n->{metadata}{name},
                $n->{status}{phase} // 'Pending';
        }
        printf STDERR "Remove nodes first: ocp node rm %s\n",
            join(' ', map { $_->{metadata}{name} } @refs);
        die "Provider '$name' has referencing nodes\n";
    }

    eval {
        $api->delete(path => "/api/v1/namespaces/$ns/secrets/ocp-provider-$name-token");
    };

    $api->delete(path => "/apis/ocp.internal/v1/namespaces/$ns/ocpnodeproviders/$name");

    print "Provider '$name' removed.\n";
    return 1;
}

1;
