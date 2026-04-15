package OCP::K8s::OCPNodeProvider;
# ABSTRACT: OCPNodeProvider Custom Resource
use IO::K8s::APIObject
    api_version     => 'ocp.internal/v1',
    resource_plural => 'ocpnodeproviders';
with 'IO::K8s::Role::Namespaced';
k8s spec   => { Str => 1 };
k8s status => { Str => 1 };
1;
