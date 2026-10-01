#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Node::Add;
use OCP::Cmd::Apply;

#
# k220: `ocp apply` only deploys the GPU Operator when NFD already labels a
# node with an NVIDIA card. A cluster whose first apply had no GPU node
# ("GPU Operator skipped") and that got its GPU workers by `ocp node add --gpu`
# afterwards had Ready GPU nodes and no operator -- no nvidia.com/gpu -- until
# a second `ocp apply` happened to look again. Live on the CitiAI lab,
# 2026-10-01.
#
# `ocp node add --gpu` now runs the same check `ocp apply` runs
# (OCP::Cmd::Apply::Workloads::setup_gpu_operator) once the node is Ready,
# after waiting for NFD to label it. When that cannot happen -- --nowait, no
# label in time, a failed rollout -- it says so on STDERR and names
# `ocp apply` as the way to get the operator.
#

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my $rv;
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = $code->();
    }
    return ($rv, $out, $err);
}

{
    package FakeIO;
    sub new              { bless {}, $_[0] }
    sub object_to_struct { $_[1] }
}

{
    package FakeList;
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]->{items} }
}

{
    # A cluster with one provider, a Ready OCPNode named after the node, and a
    # Kubernetes Node that NFD labels after `label_after` reads of it.
    package GpuApi;
    my $io = FakeIO->new;
    sub new {
        my ($class, %a) = @_;
        return bless { label_after => $a{label_after}, node_reads => 0,
                       k8s_name => $a{k8s_name}, calls => [] }, $class;
    }
    sub k8s { $io }
    sub list {
        my ($self, $kind) = @_;
        return FakeList->new([{
            metadata => { name => 'ssh-default', annotations => {} },
            spec     => { type => 'ssh' },
        }]) if $kind eq 'OCPNodeProvider';
        return FakeList->new([]);
    }
    sub ensure { push @{ $_[0]{calls} }, ['ensure']; $_[1] }
    sub get {
        my ($self, $kind, %a) = @_;
        push @{ $self->{calls} }, ['get', $kind, $a{name}];
        if ($kind eq 'OCPNodeProvider') {
            return { metadata => { name => 'ssh-default', annotations => {} },
                     spec => { type => 'ssh' } };
        }
        if ($kind eq 'OCPNode') {
            return { metadata => { name => $a{name} },
                     status => { phase => 'Ready',
                         ($self->{k8s_name} ? (kubernetesNodeName => $self->{k8s_name}) : ()) } };
        }
        if ($kind eq 'Node') {
            $self->{node_read_names}{ $a{name} }++;
            my $n = ++$self->{node_reads};
            my $labelled = defined $self->{label_after} && $n > $self->{label_after};
            return { metadata => { name => $a{name}, labels => {
                ($labelled ? ('feature.node.kubernetes.io/pci-0302_10de.present' => 'true') : ()),
            } } };
        }
        return undef;
    }
}

{
    package FakeConfig;
    sub new          { my ($c, %a) = @_; bless { gpu => $a{gpu} // 1 }, $c }
    sub gpu_enabled  { $_[0]{gpu} }
    sub project_dir  { require Path::Tiny; Path::Tiny->tempdir }
    sub distribution { 'rke2' }
}

# Runs `ocp node add` down the CLI path to a Ready node, with the GPU Operator
# rollout itself replaced by a recorder (apply's own tests cover it).
sub run_add {
    my (%o) = @_;
    my $api = GpuApi->new(label_after => $o{label_after}, k8s_name => $o{k8s_name});
    my @setup;
    my $waited = 0;
    my $add = OCP::Cmd::Node::Add->new(
        k8s  => $api,
        name => 'brain',
        host => '10.0.0.5',
        ($o{gpu}    ? (gpu    => 1) : ()),
        ($o{nowait} ? (nowait => 1) : ()),
    );
    no warnings 'redefine';
    local *OCP::Cmd::Node::Add::_config         = sub { FakeConfig->new(gpu => $o{cluster_gpu}) };
    local *OCP::Cmd::Node::Add::_robocop_ready  = sub { 0 };
    local *OCP::Cmd::Node::Add::_cli_reconcile  = sub { 1 };
    local *OCP::Cmd::Node::Add::wait_seconds    = sub { $waited += $_[1] };
    local *OCP::Cmd::Node::Add::_apply_cmd      = sub {
        my ($self, $a) = @_;
        my $apply = bless { _k8s_api => $a }, 'OCP::Cmd::Apply';
        return $apply;
    };
    local *OCP::Cmd::Apply::_setup_gpu_operator = sub {
        my ($apply, $config) = @_;
        push @setup, { api => $apply->_k8s_api, config => $config };
        die $o{setup_dies} if $o{setup_dies};
        return 'deployed';
    };
    my ($rv, $out, $err) = capture { $add->execute([], []) };
    return { rv => $rv, out => $out, err => $err, setup => \@setup,
             api => $api, waited => $waited };
}

subtest 'node add --gpu deploys the GPU Operator once NFD labels the node' => sub {
    my $r = run_add(gpu => 1, label_after => 2);
    is $r->{rv}, 0, 'exit 0';
    like $r->{out}, qr/Node 'brain' is Ready\..*Checking GPU Operator/s,
        'the check runs after the node is Ready';
    is scalar @{ $r->{setup} }, 1, 'apply\'s setup_gpu_operator ran once';
    is $r->{setup}[0]{api}, $r->{api}, 'against the cluster node add talks to';
    like $r->{out}, qr/\[ok\] GPU Operator deployed/, 'and its verdict is reported';
    ok $r->{api}{node_reads} >= 3, 'it waited for the NFD label first';
    ok $r->{waited} > 0, 'pacing through wait_seconds';
    is $r->{err}, '', 'nothing on STDERR';
};

subtest 'the label is looked for on the Kubernetes node name the OCPNode records' => sub {
    my $r = run_add(gpu => 1, label_after => 0, k8s_name => 'brain.lab.example');
    ok $r->{api}{node_read_names}{'brain.lab.example'}, 'Node read by status.kubernetesNodeName';
    is scalar @{ $r->{setup} }, 1, 'setup ran';
};

subtest 'gpu.enabled: false -- same verdict as apply, no waiting' => sub {
    my $r = run_add(gpu => 1, cluster_gpu => 0, label_after => undef);
    is $r->{api}{node_reads}, 0, 'no NFD wait on a cluster without GPU';
    is scalar @{ $r->{setup} }, 1, 'setup_gpu_operator decides (and skips) as in apply';
};

subtest 'no label in time: a warning that names ocp apply, exit stays 0' => sub {
    my $r = run_add(gpu => 1, label_after => undef);
    is $r->{rv}, 0, 'the node is Ready, so exit 0';
    is scalar @{ $r->{setup} }, 0, 'no rollout without a GPU node to roll out for';
    like $r->{err}, qr/GPU Operator not ensured/, 'says what did not happen';
    like $r->{err}, qr/NFD/, 'and why';
    like $r->{err}, qr/ocp apply/, 'and what to run';
    is $r->{waited}, OCP::Cmd::Node::Add::gpu_label_timeout(), 'waited the whole budget';
};

subtest 'a failed rollout is a warning that names ocp apply' => sub {
    my $r = run_add(gpu => 1, label_after => 0, setup_dies => "gpu-operator not ready within 120s\n");
    is $r->{rv}, 0, 'exit 0';
    like $r->{err}, qr/gpu-operator not ready within 120s/, 'the cause';
    like $r->{err}, qr/ocp apply/, 'the remedy';
};

subtest 'without --gpu nothing GPU happens' => sub {
    my $r = run_add(label_after => 0);
    is scalar @{ $r->{setup} }, 0, 'no setup';
    is $r->{api}{node_reads}, 0, 'no Node read';
    unlike $r->{out}, qr/GPU Operator/, 'no GPU line';
};

subtest '--gpu --nowait: the hint, on STDERR, STDOUT stays the name' => sub {
    my $r = run_add(gpu => 1, nowait => 1);
    is $r->{rv}, 0, 'exit 0';
    is $r->{out}, "brain\n", 'STDOUT is only the node name';
    like $r->{err}, qr/ocp apply/, 'STDERR says to run ocp apply once it is Ready';
    is scalar @{ $r->{setup} }, 0, 'nothing deployed';
};

done_testing;
