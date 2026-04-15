use strict;
use warnings;
use Test::More;

use Kubernetes::REST;
use OCP::K8s;

# Construct a minimal Kubernetes::REST client without network access.
# If that's not possible, fall back to a simpler test that just loads the classes.

my $api = eval { Kubernetes::REST->new };
if (!$api) {
    # Kubernetes::REST may require network / kubeconfig to instantiate.
    # Just verify the classes load.
    use_ok 'OCP::K8s::OCPNode';
    use_ok 'OCP::K8s::OCPNodeProvider';
    is(OCP::K8s::OCPNode->api_version, 'ocp.internal/v1', 'api_version set');
    is(OCP::K8s::OCPNode->kind, 'OCPNode', 'kind derived from class name');
    done_testing;
    exit 0;
}

OCP::K8s->register($api);

my $class = $api->expand_class('OCPNode');
is $class, 'OCP::K8s::OCPNode', 'OCPNode resolves to OCP::K8s::OCPNode';

my $prov_class = $api->expand_class('OCPNodeProvider');
is $prov_class, 'OCP::K8s::OCPNodeProvider', 'OCPNodeProvider resolves';

done_testing;
