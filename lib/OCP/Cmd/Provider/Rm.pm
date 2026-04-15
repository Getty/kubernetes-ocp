package OCP::Cmd::Provider::Rm;
# ABSTRACT: Remove an OCPNodeProvider CR (and its Secret)

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use OCP::Config;
use OCP::Secrets;
use OCP::K8s;

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

    OCP::K8s->register($api);
    $self->k8s($api);
    return $api;
}

sub execute {
    my ($self, $args, $chain) = @_;

    my $api  = $self->_k8s;
    my $ns   = 'ocp-system';
    my $name = $self->name // ($args && $args->[0]);
    die "Usage: ocp provider rm NAME\n" unless $name;

    my $cr_obj = eval {
        $api->get('OCPNodeProvider', name => $name, namespace => $ns)
    };
    die "Provider '$name' not found\n" if $@ || !$cr_obj;
    my $cr = $api->k8s->object_to_struct($cr_obj);

    my $nodes_list = $api->list('OCPNode', namespace => $ns);
    my @nodes = map { $api->k8s->object_to_struct($_) } @{ $nodes_list->items // [] };
    my @refs  = grep { ($_->{spec}{providerRef} // '') eq $name } @nodes;

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
        $api->delete('Secret', name => "ocp-provider-$name-token", namespace => $ns);
    };

    $api->delete('OCPNodeProvider', name => $name, namespace => $ns);

    print "Provider '$name' removed.\n";
    return 1;
}

1;

__END__

=head1 NAME

OCP::Cmd::Provider::Rm - Remove an OCPNodeProvider CR (and its Secret)

=head1 SYNOPSIS

    ocp provider rm hetzner-a

=head1 DESCRIPTION

Deletes the named OCPNodeProvider CR and its associated token Secret (if
any).  Refuses to delete if any OCPNode CRs reference the provider; lists
the blocking nodes and suggests the removal command.

=head1 SEE ALSO

L<OCP::Cmd::Provider::Add>, L<OCP::Cmd::Provider::Ls>

=cut
