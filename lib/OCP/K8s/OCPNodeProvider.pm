package OCP::K8s::OCPNodeProvider;
# ABSTRACT: OCPNodeProvider Custom Resource
use IO::K8s::APIObject
    api_version     => 'ocp.internal/v1',
    resource_plural => 'ocpnodeproviders';

our $VERSION = '0.001';

with 'IO::K8s::Role::Namespaced';
k8s spec   => { Str => 1 };
k8s status => { Str => 1 };
1;

__END__

=head1 NAME

OCP::K8s::OCPNodeProvider - IO::K8s class for the OCPNodeProvider CRD

=head1 SYNOPSIS

    # Registered automatically via OCP::K8s->register($api)
    my $p = $api->get('OCPNodeProvider', name => 'hetzner-a', namespace => 'ocp-system');
    my $h = $api->k8s->object_to_struct($p);
    print $h->{spec}{type};

=head1 DESCRIPTION

IO::K8s typed class for C<ocp.internal/v1 OCPNodeProvider>.  Spec and status
fields are passed through as plain hash structures.  Register this class via
L<OCP::K8s> before issuing API calls.

=head1 SEE ALSO

L<OCP::K8s>, L<OCP::K8s::OCPNode>, L<OCP::Provider>

=cut
