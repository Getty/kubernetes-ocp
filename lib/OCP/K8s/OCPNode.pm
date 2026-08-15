package OCP::K8s::OCPNode;
# ABSTRACT: OCPNode Custom Resource
use IO::K8s::APIObject
    api_version     => 'ocp.internal/v1',
    resource_plural => 'ocpnodes';

with 'IO::K8s::Role::Namespaced';
k8s spec   => { Str => 1 };
k8s status => { Str => 1 };
1;

__END__

=head1 NAME

OCP::K8s::OCPNode - IO::K8s class for the OCPNode CRD

=head1 SYNOPSIS

    # Registered automatically via OCP::K8s->register($api)
    my $node = $api->get('OCPNode', name => 'worker-1', namespace => 'ocp-system');
    my $h    = $api->k8s->object_to_struct($node);
    print $h->{status}{phase};

=head1 DESCRIPTION

IO::K8s typed class for C<ocp.internal/v1 OCPNode>.  Spec and status fields
are passed through as plain hash structures.  Register this class via
L<OCP::K8s> before issuing API calls.

=head1 SEE ALSO

L<OCP::K8s>, L<OCP::K8s::OCPNodeProvider>, L<IO::K8s>

=cut
