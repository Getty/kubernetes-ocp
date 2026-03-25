#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Kubernetes;

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

done_testing;
