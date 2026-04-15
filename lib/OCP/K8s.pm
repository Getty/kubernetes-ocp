package OCP::K8s;
# ABSTRACT: Register OCP's CRD classes with a Kubernetes::REST api instance

use strict;
use warnings;
use OCP::K8s::OCPNode;
use OCP::K8s::OCPNodeProvider;

our $VERSION = '0.001';

sub register {
    my ($class, $api) = @_;
    $api->resource_map->{OCPNode}         = '+OCP::K8s::OCPNode';
    $api->resource_map->{OCPNodeProvider} = '+OCP::K8s::OCPNodeProvider';
    return $api;
}

1;

__END__

=head1 NAME

OCP::K8s - Register OCP CRD classes with a Kubernetes::REST api instance

=head1 SYNOPSIS

    use OCP::K8s;

    OCP::K8s->register($api);

    # OCPNode and OCPNodeProvider are now typed
    my $node = $api->get('OCPNode', name => 'worker-1', namespace => 'ocp-system');

=head1 DESCRIPTION

Registers L<OCP::K8s::OCPNode> and L<OCP::K8s::OCPNodeProvider> into the
resource map of a L<Kubernetes::REST> instance so that C<get>, C<list>,
C<ensure>, and C<delete> calls return typed objects instead of bare hashes.

Call C<register> once per API instance before issuing any CRD requests.

=head1 SEE ALSO

L<OCP::K8s::OCPNode>, L<OCP::K8s::OCPNodeProvider>, L<Kubernetes::REST>

=cut
