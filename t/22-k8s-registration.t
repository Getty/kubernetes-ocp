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

# The register half (k420). It used to build the client with no arguments, and
# Kubernetes::REST->new dies without server and credentials, so it always took
# a classes-load fallback and the registration itself never ran. A client needs
# no network to be built: resource_map_from_cluster => 0 keeps the built-in map,
# so neither register nor expand_class asks the cluster for discovery -- the
# endpoint below is never contacted.
is(OCP::K8s::OCPNode->api_version, 'ocp.internal/v1', 'api_version set');
is(OCP::K8s::OCPNode->kind, 'OCPNode', 'kind derived from class name');

my $api = Kubernetes::REST->new(
    server                    => { endpoint => 'https://127.0.0.1:1' },
    credentials               => { token => 'k420-not-a-token' },
    resource_map_from_cluster => 0,
);

# Resolving a name first builds the inner IO::K8s, so register has to merge
# into a built one, add_provider's other path.
isnt scalar(eval { $api->expand_class('OCPNode') }), 'OCP::K8s::OCPNode',
    'control: before register, OCPNode is no class of OCP\'s';

is(OCP::K8s->register($api), $api, 'register returns the api');
is scalar(@{ $api->with }), 1, 'one provider on the with list';

OCP::K8s->register($api);
is scalar(@{ $api->with }), 1, 'a second register adds nothing';

is $api->expand_class('OCPNode'), 'OCP::K8s::OCPNode',
    'OCPNode resolves to OCP::K8s::OCPNode';
is $api->expand_class('OCPNodeProvider'), 'OCP::K8s::OCPNodeProvider',
    'OCPNodeProvider resolves';

done_testing;
