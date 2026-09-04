use strict;
use warnings;
use Test::More;

use lib 'lib';

use Kubernetes::REST ();
use OCP::Kubernetes ();

# k131/k132: the CRD provider Kinds OCP addresses by name (CiliumNetworkPolicy,
# Certificate, GatewayClass) must be registered so that they survive a rebuild
# of the inner IO::K8s. Since Kubernetes::REST 1.108 resource_map/with live on
# the Kubernetes::REST instance and the inner IO::K8s is a lazy, rebuildable
# cache: a one-shot $api->k8s->add() is discarded the first time the discovery
# or openapi cache is invalidated, after which the Kinds fall back to fabricated
# IO::K8s::<Kind> names. register_resource_providers must register them on the
# `with` list instead, which the builder re-applies on every rebuild (D12).
#
# Both OCP entry points that need typed CRD access route through
# OCP::Kubernetes::register_resource_providers: OCP::Kubernetes (ocp status /
# drift) and OCP::Cmd::Apply::K8s (the in-cluster apply phases).

# Off-cluster: no discovery fetch, so the whole test is network-free.
sub fresh_api {
    return Kubernetes::REST->new(
        server                    => { endpoint => 'https://cluster.invalid:6443' },
        credentials               => { token => 'fake-token' },
        resource_map_from_cluster => 0,
    );
}

my %EXPECT = (
    CiliumNetworkPolicy => 'IO::K8s::Cilium::V2::CiliumNetworkPolicy',
    Certificate         => 'IO::K8s::CertManager::V1::Certificate',
    GatewayClass        => 'IO::K8s::GatewayAPI::V1::GatewayClass',
);

subtest 'register_resource_providers resolves all three provider Kinds' => sub {
    my $api = fresh_api();
    OCP::Kubernetes->register_resource_providers($api);

    for my $kind (sort keys %EXPECT) {
        is $api->expand_class($kind), $EXPECT{$kind},
            "$kind resolves to its provider class";
    }
};

subtest 'the registration survives an inner-IO::K8s rebuild' => sub {
    my $api = fresh_api();
    OCP::Kubernetes->register_resource_providers($api);

    # Prime the inner instance, then invalidate it the way ensure_crd's
    # invalidate_discovery does. A runtime add() would be gone after this;
    # a `with`-list registration is re-applied by the k8s builder.
    $api->k8s;
    $api->invalidate_discovery;

    for my $kind (sort keys %EXPECT) {
        is $api->expand_class($kind), $EXPECT{$kind},
            "$kind still resolves after a rebuild";
    }
};

subtest 'registration is durable even when k8s was already built' => sub {
    my $api = fresh_api();
    $api->k8s;   # force the inner instance to exist before we register
    OCP::Kubernetes->register_resource_providers($api);

    is $api->expand_class('CiliumNetworkPolicy'),
        $EXPECT{CiliumNetworkPolicy},
        'a provider registered after first k8s access still resolves';
};

subtest 'no duplicate entries when called twice' => sub {
    my $api = fresh_api();
    OCP::Kubernetes->register_resource_providers($api);
    OCP::Kubernetes->register_resource_providers($api);

    my %seen;
    $seen{$_}++ for @{ $api->with };
    is_deeply [ grep { $seen{$_} > 1 } keys %seen ], [],
        'each provider appears once on the with list';

    is $api->expand_class('Certificate'), $EXPECT{Certificate},
        'Kinds still resolve after a second registration';
};

done_testing;
