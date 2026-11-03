package OCP::Cmd::Provider::Ls;
# ABSTRACT: List OCPNodeProvider CRs

use Moo;
use MooX::Cmd;
use MooX::Options;

with 'OCP::Role::Cmd';

has k8s => (is => 'rw');

sub _k8s {
    my $self = shift;
    return $self->k8s if $self->k8s;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    # The key, kubeconfig.yaml, the client and one GET /version: an API that
    # does not answer, or answers /version with an error, is said there, in
    # one line (k384, k387, k399).
    return $self->k8s($self->cluster_api);
}

sub execute {
    my ($self, $args, $chain) = @_;

    my $api = $self->_k8s;
    my $ns  = 'ocp-system';

    # An error the API answers with is one line naming the server (k387).
    my $providers_list = $self->cluster_api_call($api, sub { $api->list('OCPNodeProvider', namespace => $ns) });
    my $nodes_list     = $self->cluster_api_call($api, sub { $api->list('OCPNode',         namespace => $ns) });

    my @providers = map { $api->k8s->object_to_struct($_) } @{ $providers_list->items // [] };
    my @nodes     = map { $api->k8s->object_to_struct($_) } @{ $nodes_list->items     // [] };

    my %refs;
    for my $n (@nodes) {
        my $ref = $n->{spec}{providerRef} or next;
        $refs{$ref}++;
    }

    printf "%-14s %-9s %-10s %-8s %s\n", qw(NAME TYPE LOCATION DEFAULT NODES);
    for my $p (@providers) {
        my $name = $p->{metadata}{name};
        my $type = $p->{spec}{type} // '';
        my $loc  = $type eq 'hetzner' ? ($p->{spec}{hetzner}{location} // '') : '';
        my $def  = ($p->{metadata}{annotations}{'ocp.internal/default'} // '') eq 'true' ? '*' : '';
        my $cnt  = $refs{$name} // 0;
        printf "%-14s %-9s %-10s %-8s %d\n", $name, $type, $loc, $def, $cnt;
    }

    return 0;
}

1;

__END__

=head1 SYNOPSIS

    ocp provider ls

=head1 DESCRIPTION

Lists all OCPNodeProvider CRs in the C<ocp-system> namespace.  Columns:
NAME, TYPE, LOCATION, DEFAULT (C<*> if annotated as default), NODES (count
of OCPNode CRs referencing this provider).

=head1 SEE ALSO

L<OCP::Cmd::Provider::Add>, L<OCP::Cmd::Provider::Rm>

=cut
