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
