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
# k251: the same for an AMD node. Its marker (ocp.internal/amd-gpu.present,
# set at registration by the host step) picks the AMD GPU stack
# (OCP::Cmd::Apply::AMDGPU) instead of the GPU Operator; a node that shows
# both gets both, one that shows neither is said as exactly that.
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
                       k8s_name => $a{k8s_name}, amd => $a{amd},
                       nvidia => $a{nvidia} // 1, calls => [] }, $class;
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
                ($labelled && $self->{nvidia}
                    ? ('feature.node.kubernetes.io/pci-0302_10de.present' => 'true') : ()),
                # The AMD marker is there from registration on: no label_after.
                ($self->{amd} ? ('ocp.internal/amd-gpu.present' => 'true') : ()),
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
    # k238: no control-plane address recorded -> the SSH preflight probe of
    # `node add --host` is skipped; this test is about the GPU Operator, not the probe.
    sub cluster_status { +{} }
}

{
    # An ocp with a config file on disk, for _k8s.
    package KcOcp;
    require Path::Tiny;
    my $dir = Path::Tiny->tempdir;
    sub new    { $dir->child('ocp.yaml')->spew("name: lab\nkubernetes:\n  dist: k3s\n"
                     . "control_planes:\n  provider: ssh\n  host: lab.ocp.invalid\n"); bless {}, $_[0] }
    sub config { $dir->child('ocp.yaml')->stringify }
}

# Runs `ocp node add` down the CLI path to a Ready node, with the GPU Operator
# rollout itself replaced by a recorder (apply's own tests cover it).
sub run_add {
    my (%o) = @_;
    my $api = GpuApi->new(label_after => $o{label_after}, k8s_name => $o{k8s_name},
                          amd => $o{amd}, nvidia => $o{nvidia});
    my @setup;
    my @amd;
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
    # The AMD stack's own decisions are t/251's; here only that node add
    # reaches it, against the right cluster, and says what it returned.
    local *OCP::Cmd::Apply::AMDGPU::setup = sub {
        my ($apply, $config) = @_;
        push @amd, { api => $apply->_k8s_api, config => $config };
        die $o{amd_dies} if $o{amd_dies};
        return @{ $o{amd_results} // [{ label => 'AMD GPU device plugin', outcome => 'deployed' }] };
    };
    # Whether the GPU checks completed: not the exit code (the node is Ready
    # either way), but what _ensure_gpu_stack says it did.
    my $ensured;
    my $orig = \&OCP::Cmd::Node::Add::_ensure_gpu_stack;
    local *OCP::Cmd::Node::Add::_ensure_gpu_stack = sub { $ensured = $orig->(@_) };
    my ($rv, $out, $err) = capture { $add->execute([], []) };
    return { rv => $rv, out => $out, err => $err, setup => \@setup, amd => \@amd,
             api => $api, waited => $waited, ensured => $ensured };
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

subtest 'no GPU shown in time: a warning that names both labels and ocp apply, exit stays 0' => sub {
    my $r = run_add(gpu => 1, label_after => undef);
    is $r->{rv}, 0, 'the node is Ready, so exit 0';
    is scalar @{ $r->{setup} }, 0, 'no GPU Operator rollout without a GPU node to roll out for';
    is scalar @{ $r->{amd} }, 0, 'and no AMD GPU stack either';
    like $r->{err}, qr/No GPU stack ensured: node 'brain' shows no GPU after 300s/, 'says what did not happen';
    like $r->{err}, qr{ocp\.internal/amd-gpu\.present=true}, 'names the AMD marker it waited for';
    like $r->{err}, qr/NFD NVIDIA label.*pci-0300_10de.*pci-0302_10de/s, 'and the NFD labels';
    like $r->{err}, qr/ocp apply/, 'and what to run';
    unlike $r->{out}, qr/Checking (?:GPU Operator|AMD GPU stack)/, 'no check claimed on STDOUT';
    is $r->{waited}, OCP::Cmd::Node::Add::gpu_label_timeout(), 'waited the whole budget';
    ok !$r->{ensured}, 'not ensured';
};

subtest 'an AMD node gets the AMD GPU stack, not the GPU Operator' => sub {
    my $r = run_add(gpu => 1, amd => 1, nvidia => 0, label_after => 0);
    is $r->{rv}, 0, 'exit 0';
    like $r->{out}, qr/Node 'brain' is Ready\..*Checking AMD GPU stack/s, 'the AMD check runs after Ready';
    is scalar @{ $r->{amd} }, 1, 'the AMD stack step ran once';
    is $r->{amd}[0]{api}, $r->{api}, 'against the cluster node add talks to';
    like $r->{out}, qr/\[ok\] AMD GPU device plugin deployed/, 'its verdict is reported';
    is scalar @{ $r->{setup} }, 0, 'no GPU Operator for an AMD node';
    unlike $r->{out}, qr/Checking GPU Operator/, 'nor a line claiming its check';
    is $r->{waited}, 0, 'the marker is there from registration: no wait';
    is $r->{err}, '', 'nothing on STDERR';
    ok $r->{ensured}, 'ensured';
};

subtest 'a node that shows both vendors gets both stacks' => sub {
    my $r = run_add(gpu => 1, amd => 1, label_after => 0);
    is scalar @{ $r->{setup} }, 1, 'GPU Operator check';
    is scalar @{ $r->{amd} }, 1, 'AMD GPU stack check';
};

subtest 'a failed AMD rollout: the cause and ocp apply on STDERR, exit 0' => sub {
    my $r = run_add(gpu => 1, amd => 1, nvidia => 0, label_after => 0,
        amd_results => [{ label => 'AMD GPU device plugin',
                          error => "AMD GPU device plugin not ready after 300s: node 'brain' shows no amd.com/gpu in status.allocatable\n" }]);
    is $r->{rv}, 0, 'the node is Ready, so exit 0';
    like $r->{err}, qr/\[!!\] AMD GPU device plugin setup failed: .*amd\.com\/gpu/, 'the cause';
    like $r->{err}, qr/AMD GPU stack not ensured\. Run `ocp apply`/, 'the remedy';
    unlike $r->{out}, qr/\[ok\] AMD GPU device plugin/, 'no [ok] for it';
    ok !$r->{ensured}, 'not ensured';
};

subtest 'an AMD stack the library cannot deploy: the WARN, no ocp apply hint' => sub {
    my $r = run_add(gpu => 1, amd => 1, nvidia => 0, label_after => 0,
        amd_results => [{ label => 'AMD GPU stack', outcome => 'skipped', warned => 1 }]);
    is $r->{rv}, 0, 'exit 0';
    unlike $r->{err}, qr/ocp apply/, 'ocp apply would not help: not named';
    ok !$r->{ensured}, 'and not ensured: the stack is not there';
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

subtest 'k251: the apply command node add hands on carries its kubeconfig file' => sub {
    require File::Temp;
    no warnings 'redefine';
    my $add = OCP::Cmd::Node::Add->new(name => 'brain', command_chain => [ KcOcp->new ]);
    local *OCP::Secrets::read_kubeconfig       = sub { "apiVersion: v1\nkind: Config\n" };
    local *Kubernetes::REST::Kubeconfig::api   = sub { 'API' };
    local *OCP::K8s::register                  = sub { 1 };
    my $api = $add->_k8s;
    is $api, 'API', '_k8s built the client';
    ok $add->{_kc_temp} && -f $add->{_kc_temp}->filename, 'and kept the kubeconfig file it built it from';
    my $apply = $add->_apply_cmd($api);
    is $apply->{_k8s_api}, 'API', 'the apply command gets the client';
    is OCP::Cmd::Apply::K8s::kubeconfig_path($apply), $add->{_kc_temp}->filename,
        'and the file the AMD GPU stack library reads';
};

done_testing;
