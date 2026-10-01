use strict;
use warnings;
use Test::More;

use JSON::MaybeXS;
use Kubernetes::REST;
use OCP::K8s;
use OCP::K8s::OCPNode;
use OCP::K8s::OCPNodeProvider;

# spec/status are free maps (Opaque): nested structures and booleans pass
# through untouched and without IO::K8s's "map of strings" warning.
{
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    my $node = OCP::K8s::OCPNode->new(
        metadata => { name => 'w1' },
        spec     => { gpu => JSON::MaybeXS::true, labels => { 'a/b' => 'c' },
                      taints => [ { key => 'k', effect => 'NoSchedule' } ] },
        status   => { phase => 'Ready', conditions => [ { type => 'Ready' } ] },
    );
    my $prov = OCP::K8s::OCPNodeProvider->new(
        metadata => { name => 'p1' },
        spec     => { type => 'hetzner', hetzner => { location => 'fsn1' } },
    );
    my $h  = $node->TO_JSON;
    my $ph = $prov->TO_JSON;
    is_deeply \@warnings, [], 'nested spec/status raise no IO::K8s warning';
    is_deeply $h->{spec}{labels}, { 'a/b' => 'c' }, 'spec.labels map kept';
    is $h->{spec}{taints}[0]{effect}, 'NoSchedule', 'spec.taints list kept';
    ok JSON::MaybeXS::is_bool($h->{spec}{gpu}), 'spec.gpu stays a boolean';
    is $h->{status}{conditions}[0]{type}, 'Ready', 'status.conditions kept';
    is $ph->{spec}{hetzner}{location}, 'fsn1', 'provider spec nested map kept';
}

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
