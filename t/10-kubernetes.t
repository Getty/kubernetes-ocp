#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::MaybeXS ();
use Path::Tiny qw(path);

use lib 'lib';

use Kubernetes::REST;
use Kubernetes::REST::LWPIO;
use OCP::Kubernetes;

#
# OCP::Kubernetes: the node helpers, and the two calls that used to guess.
#
# list_nodes and register_resource_providers both used to probe before they
# acted -- $list->can('items'), $api->can('k8s') -- and fall back to doing
# nothing when the probe failed. Neither fallback could be seen from outside:
#
#   * list_nodes returned [] for "the object I got back is not the shape I
#     expected", which reads exactly like "the cluster has no nodes". `ocp
#     status` prints that as a successful reading of an empty cluster and
#     returns 0. Same failure shape as karr #21 and #35: the call failed, the
#     operation reported success.
#   * register_resource_providers returned early, and the Cilium/CertManager/
#     GatewayAPI Kinds were simply never registered -- surfacing much later,
#     somewhere else, as an untyped lookup.
#
# Both probes were on GETTY distributions that cpanfile pins (Kubernetes::REST
# and IO::K8s, both 1.107), so the guess had nothing to add over the pin, and
# the two could only ever drift apart. They are gone; the methods call
# straight through.
#
# So the point of this file is no longer "does list_nodes cope with whatever
# comes back" but "is an empty cluster still distinguishable from a cluster
# that did not answer". That is checked below through a real Kubernetes::REST
# with only its HTTP transport replaced -- the inflation, the status check and
# the resource map are all the shipped code.
#

our $JSON = JSON::MaybeXS->new(utf8 => 1, canonical => 1, convert_blessed => 1);

# Kubernetes::REST builds its resource map from the cluster's OpenAPI document
# (resource_map_from_cluster defaults to 1). Answering that fetch keeps the
# client off its warn-and-fall-back path.
my $OPENAPI = $JSON->encode({
    paths => {
        '/api/v1/nodes/{name}' => {
            get => { 'x-kubernetes-group-version-kind' =>
                     { group => '', version => 'v1', kind => 'Node' } },
        },
    },
});

package Resp {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
    sub headers { {} }
}

package main;

# Replaces the HTTP transport of every Kubernetes::REST in the process, which
# is what it takes here: OCP::Kubernetes builds its client inside
# Kubernetes::REST::Kubeconfig, so there is no `io` argument to hand in.
# A path with no answer is a 404 rather than a silent empty body, so a test
# that aims at the wrong URL says so.
sub loopback_io {
    my (%answers) = @_;
    return sub {
        my ($self, $req) = @_;
        my $path = $req->url;
        $path =~ s{^https?://[^/]+}{};
        return Resp->new(status => 200, content => $OPENAPI) if $path eq '/openapi/v2';
        my $answer = $answers{$path}
            or return Resp->new(status => 404, content => qq({"message":"no fixture for $path"}));
        return $answer if ref $answer eq 'Resp';
        return Resp->new(status => 200, content => $JSON->encode($answer));
    };
}

my $tmp = Path::Tiny->tempdir;
my $KUBECONFIG = $tmp->child('kubeconfig.yaml');
$KUBECONFIG->spew_utf8(<<'YAML');
apiVersion: v1
kind: Config
current-context: ocp
clusters:
- name: cl
  cluster:
    server: https://k8s.example:6443
    insecure-skip-tls-verify: true
contexts:
- name: ocp
  context:
    cluster: cl
    user: u
users:
- name: u
  user:
    token: kc-token
YAML

# A Node as the API server actually sends one. nodeInfo carries every field
# because IO::K8s requires them all, and Kubernetes::REST drops a list item it
# cannot inflate without a word -- a half-filled fixture would arrive here as
# an empty list and look like the bug this file is about.
sub node_json {
    my (%a) = @_;
    return {
        apiVersion => 'v1',
        kind       => 'Node',
        metadata   => {
            name   => $a{name},
            labels => $a{labels} // {},
        },
        status => {
            addresses  => $a{addresses} // [],
            capacity   => $a{capacity} // { cpu => '4', memory => '8Gi' },
            conditions => $a{conditions} // [],
            nodeInfo   => {
                kubeletVersion          => $a{version} // 'v1.32.1',
                architecture            => 'amd64',
                bootID                  => 'boot-id',
                containerRuntimeVersion => 'containerd://2.0.0',
                kernelVersion           => '6.1.0',
                kubeProxyVersion        => $a{version} // 'v1.32.1',
                machineID               => 'machine-id',
                operatingSystem         => 'linux',
                osImage                 => 'Debian GNU/Linux 12',
                systemUUID              => 'system-uuid',
            },
        },
    };
}

#
# 1. The extraction helpers, on plain structs.
#

my $ready_node = {
    metadata => {
        name   => 'police1',
        labels => {
            'node-role.kubernetes.io/control-plane' => '',
            'node-role.kubernetes.io/master'        => '',
        },
    },
    status => {
        nodeInfo   => { kubeletVersion => 'v1.32.1' },
        conditions => [
            { type => 'MemoryPressure', status => 'False' },
            { type => 'Ready',          status => 'True'  },
        ],
        addresses => [
            { type => 'Hostname',   address => 'police1' },
            { type => 'InternalIP', address => '10.0.0.10' },
        ],
    },
};

my $worker_node = {
    metadata => {
        name   => 'worker-1',
        labels => {},
    },
    status => {
        nodeInfo   => { kubeletVersion => 'v1.32.1' },
        conditions => [
            { type => 'Ready', status => 'False' },
        ],
        addresses => [
            { type => 'InternalIP', address => '10.0.0.20' },
        ],
    },
};

my $gpu_node = {
    metadata => {
        name   => 'gpu-worker',
        labels => {
            'feature.node.kubernetes.io/pci-10de.present' => 'true',
        },
    },
    status => {
        nodeInfo   => { kubeletVersion => 'v1.32.1' },
        capacity   => { 'nvidia.com/gpu' => 2, cpu => '16', memory => '64Gi' },
        conditions => [
            { type => 'Ready', status => 'True' },
        ],
        addresses => [
            { type => 'InternalIP', address => '10.0.0.30' },
        ],
    },
};

{
    package Local::FakeList;
    sub new { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
}

{
    package Local::FakeAPI;
    sub new { bless { nodes => $_[1] }, $_[0] }
    sub list {
        my ($self, $kind) = @_;
        die "unexpected kind: $kind" unless $kind eq 'Node';
        return Local::FakeList->new($self->{nodes});
    }
}

my $k8s = OCP::Kubernetes->new(kubeconfig_path => 'dummy');
$k8s->{api} = Local::FakeAPI->new([$ready_node, $worker_node, $gpu_node]);

my $nodes = $k8s->list_nodes;
is(scalar @$nodes, 3, 'list_nodes returns node items');

ok($k8s->node_ready($ready_node), 'node_ready detects ready node');
ok(!$k8s->node_ready($worker_node), 'node_ready detects non-ready node');

is($k8s->node_name($ready_node), 'police1', 'node_name extracts metadata name');
is($k8s->node_roles($ready_node), 'control-plane,master', 'node_roles joins known role labels');
is($k8s->node_roles($worker_node), '<none>', 'node_roles falls back to <none>');
is($k8s->node_version($ready_node), 'v1.32.1', 'node_version extracts kubelet version');
is($k8s->node_internal_ip($ready_node), '10.0.0.10', 'node_internal_ip extracts internal IP');
is($k8s->node_internal_ip({ metadata => { name => 'missing-ip' }, status => { addresses => [] } }), '', 'node_internal_ip falls back to empty string');

# GPU helpers
is($k8s->node_gpu_count($gpu_node), 2, 'node_gpu_count returns GPU count');
is($k8s->node_gpu_count($ready_node), 0, 'node_gpu_count returns 0 for non-GPU node');
is($k8s->node_gpu_count($worker_node), 0, 'node_gpu_count returns 0 for worker without capacity');

my $gpu_nodes = $k8s->gpu_nodes;
is(scalar @$gpu_nodes, 1, 'gpu_nodes returns only GPU nodes');
is($gpu_nodes->[0]{metadata}{name}, 'gpu-worker', 'gpu_nodes returns correct node');

#
# 2. Empty cluster vs. cluster that did not answer -- through the real client.
#
# This is the pair the old `return [] unless $list->can('items')` collapsed
# into one. Both go through Kubernetes::REST's own list(), so what separates
# them is the client's behaviour, not a shape OCP guessed at.
#

subtest 'an empty cluster and an unreachable one are different answers' => sub {
    my $empty = do {
        no warnings 'redefine';
        local *Kubernetes::REST::LWPIO::call = loopback_io(
            '/api/v1/nodes' => { apiVersion => 'v1', kind => 'NodeList', items => [] },
        );
        OCP::Kubernetes->new(kubeconfig_path => "$KUBECONFIG")->list_nodes;
    };

    is ref $empty, 'ARRAY', 'a cluster with no nodes answers with an arrayref';
    is scalar @$empty, 0, '... an empty one';

    my ($down, $error) = do {
        no warnings 'redefine';
        local *Kubernetes::REST::LWPIO::call = loopback_io(
            '/api/v1/nodes' =>
                Resp->new(status => 503, content => 'upstream connect error'),
        );
        my $k = OCP::Kubernetes->new(kubeconfig_path => "$KUBECONFIG");
        local $@;
        my $r = eval { $k->list_nodes };
        ($r, $@);
    };

    ok !defined $down, 'a cluster that refuses the request returns nothing at all';
    like $error, qr/Kubernetes API error/,
        '... it dies, so "no nodes" cannot be read off a failed call';
    like $error, qr/\b503\b/, '... and the status the cluster gave is in the message';

    # The pair, stated once: same method, same caller, two outcomes that no
    # longer look alike. Before, the second one was an empty arrayref too.
    is_deeply
        [ ref $empty, (defined $down ? 'returned a list' : 'died') ],
        [ 'ARRAY',    'died' ],
        'empty cluster hands back a list, unreachable cluster hands back nothing';
};

subtest 'nodes come back inflated, and the helpers read them' => sub {
    no warnings 'redefine';
    local *Kubernetes::REST::LWPIO::call = loopback_io(
        '/api/v1/nodes' => {
            apiVersion => 'v1',
            kind       => 'NodeList',
            items      => [
                node_json(
                    name       => 'police1',
                    labels     => { 'node-role.kubernetes.io/control-plane' => '' },
                    addresses  => [
                        { type => 'InternalIP', address => '10.0.0.10' },
                        { type => 'ExternalIP', address => '203.0.113.10' },
                    ],
                    conditions => [ { type => 'Ready', status => 'True' } ],
                ),
                node_json(
                    name       => 'gpu-worker',
                    addresses  => [ { type => 'InternalIP', address => '10.0.0.30' } ],
                    capacity   => { 'nvidia.com/gpu' => '2', cpu => '16' },
                    conditions => [ { type => 'Ready', status => 'False' } ],
                ),
            ],
        },
    );

    my $k    = OCP::Kubernetes->new(kubeconfig_path => "$KUBECONFIG");
    my $list = $k->list_nodes;

    is scalar @$list, 2, 'both nodes survive the round trip';
    isa_ok $list->[0], 'IO::K8s::Api::Core::V1::Node', 'the first node';

    is $k->node_name($list->[0]), 'police1', 'node_name reads a typed object';
    is $k->node_roles($list->[0]), 'control-plane', '... and so does node_roles';
    is $k->node_version($list->[0]), 'v1.32.1', '... node_version';
    is $k->node_internal_ip($list->[0]), '10.0.0.10', '... node_internal_ip';
    is $k->node_external_ip($list->[0]), '203.0.113.10', '... node_external_ip';
    ok $k->node_ready($list->[0]), '... node_ready on a Ready node';
    ok !$k->node_ready($list->[1]), '... and on one that is not';

    is $k->node_gpu_count($list->[1]), '2', 'node_gpu_count reads status.capacity';
    is $k->node_gpu_count($list->[0]), 0, '... and 0 where there is no GPU';
};

#
# 3. What used to be swallowed.
#

subtest 'an api that cannot answer list() is not an empty cluster' => sub {
    my %shapes = (
        'undef'        => undef,
        'a hashref'    => { items => [] },
        'an arrayref'  => [],
    );

    for my $what (sort keys %shapes) {
        my $k = OCP::Kubernetes->new(kubeconfig_path => 'dummy');
        my $answer = $shapes{$what};
        $k->{api} = do {
            package Local::OddAPI;
            sub new  { bless { answer => $_[1] }, $_[0] }
            sub list { $_[0]{answer} }
            Local::OddAPI->new($answer);
        };

        local $@;
        my $r = eval { $k->list_nodes };
        ok !defined $r, "list() answering with $what does not become a node list";
        ok $@, "... it dies instead of reporting an empty cluster";
    }
};

subtest 'the typed CRD providers are registered, or nothing is' => sub {
    my $api = do {
        no warnings 'redefine';
        local *Kubernetes::REST::LWPIO::call = loopback_io();
        OCP::Kubernetes->new(kubeconfig_path => "$KUBECONFIG")->api;
    };

    is $api->k8s->expand_class('CiliumNetworkPolicy'),
        'IO::K8s::Cilium::V2::CiliumNetworkPolicy',
        'IO::K8s::Cilium is registered';
    is $api->k8s->expand_class('ClusterIssuer'),
        'IO::K8s::CertManager::V1::ClusterIssuer',
        'IO::K8s::CertManager is registered';
    is $api->k8s->expand_class('Gateway'),
        'IO::K8s::GatewayAPI::V1::Gateway',
        'IO::K8s::GatewayAPI is registered';

    # The probe this replaced returned early here and left every Kind above
    # unregistered, which only showed up at the first untyped lookup.
    my $k = OCP::Kubernetes->new(kubeconfig_path => 'dummy');
    local $@;
    ok !eval { $k->register_resource_providers(bless {}, 'Local::NotAClient'); 1 },
        'an api without k8s dies here';
    like $@, qr/k8s/, '... naming the method it needed';
};

done_testing;
