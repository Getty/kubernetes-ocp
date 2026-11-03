#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Kubernetes::REST::APIError;
use List::Util qw(sum0);
use Path::Tiny qw(path);
use YAML::XS ();

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Workloads;
use OCP::Cmd::Node::Add;

#
# k273: on AMD, the GPU stack is ready once amd.com/gpu shows in
# status.allocatable (k251). On NVIDIA, `ocp apply` and `ocp node add --gpu`
# found the nodes by their NFD label, applied the ClusterPolicy and called
# the stack ready. So "ready" meant "ClusterPolicy applied", not "a pod can
# get a GPU".
#
# setup_gpu_operator, which every GPU Operator check of both commands runs,
# now waits (gpu_ready_timeout) after a rollout and after "up to date" alike,
# until nvidia.com/gpu shows above 0 in status.allocatable on every NVIDIA
# node it detected. It waits for allocatable and never for capacity: the
# kubelet keeps capacity after a device plugin unregisters (k106/k270,
# capacity 1 and allocatable 0 on amdlab). A node that does not get there
# is a [WARN] on STDERR with why. That does not fail the step, the apply or
# the join. A read that fails is read again, and only a 404 means the node
# is absent (k269).
#
# k287: the same for an NVIDIA worker that joins later in the run, when the
# first check did not skip: the check after the worker join runs again for
# it (t/228 has when), and waits for it like for the others.
#

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my ($rv, $died);
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $code->() };
        $died = $@;
    }
    return ($rv, $out, $err, $died);
}

# What Kubernetes::REST dies with for an HTTP error status (as in t/269).
sub api_error {
    my ($code, $reason) = @_;
    return Kubernetes::REST::APIError->new(
        code    => $code,
        context => 'get',
        body    => qq({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"$reason","code":$code}),
    );
}

{
    package FakeResponse;
    sub new     { my ($c, $status, $content) = @_; bless { status => $status, content => $content }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
}
{
    package FakeList;
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
}
{
    package NodeItem;
    sub new      { bless { name => $_[1] }, $_[0] }
    sub metadata { $_[0] }
    sub name     { $_[0]{name} }
}
{
    # A cluster whose NVIDIA nodes NFD has labelled. Each node answers its
    # reads from a queue whose last answer repeats. A hash is the node's
    # status (allocatable, capacity); anything else is what the read dies
    # with. `running` says whether the GPU Operator's Namespace and
    # Deployment exist.
    package NvApi;
    my $NFD = 'feature.node.kubernetes.io/pci-0302_10de.present';
    sub new { my ($c, %a) = @_; bless { nodes => {}, reads => {}, running => 0, %a }, $c }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }
    sub ensure           { $_[1] }
    sub list {
        my ($self, $kind, %a) = @_;
        return FakeList->new([]) unless $kind eq 'Node' && ($a{labelSelector} // '') eq "$NFD=true";
        return FakeList->new([ map { NodeItem->new($_) } sort keys %{ $self->{nodes} } ]);
    }
    sub get {
        my ($self, $kind, @rest) = @_;
        my $name = @rest % 2 ? shift @rest : undef;
        my %a = @rest;
        $name //= $a{name};
        if ($kind eq 'Node') {
            my $queue = $self->{nodes}{$name} or die "404 Node/$name not found\n";
            $self->{reads}{$name}++;
            my $answer = @$queue > 1 ? shift @$queue : $queue->[0];
            die $answer unless ref $answer eq 'HASH';
            return { metadata => { name => $name, labels => { $NFD => 'true' } }, status => $answer };
        }
        return { metadata => { name => $name }, status => { phase => 'Ready' } } if $kind eq 'OCPNode';
        return { kind => $kind } if $self->{running} && ($kind eq 'Namespace' || $kind eq 'Deployment');
        die "404 $kind/$name not found\n";
    }
    # The ClusterPolicy is ready and agrees with gpu.toolkit; nothing else
    # is there.
    sub _request {
        my ($self, $method, $path) = @_;
        return FakeResponse->new(200, '{"spec":{"toolkit":{"enabled":true}},"status":{"state":"ready"}}')
            if $path eq '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy';
        return FakeResponse->new(404, '{}');
    }
}
{
    package FakeOCP;
    sub new       { bless {}, shift }
    sub verbose   { 0 }
    # No ocp.yaml: node add's _config is replaced below, and OCP::Role::Cmd's
    # check, which reads the file this names, has none to check (k400).
    sub config    { undef }
    sub dump      { my ($self, @r) = @_; return join '', map { YAML::XS::Dump($_) } @r }
    sub load_file { my ($self, $f) = @_; -f "$f" ? YAML::XS::LoadFile("$f") : undef }
    sub dump_file { my ($self, $f, $d) = @_; YAML::XS::DumpFile("$f", $d) }
}
{
    package FakeConfig;
    sub new {
        my ($class) = @_;
        my $dir = Path::Tiny::path(main::tempdir(CLEANUP => 1));
        $dir->child('.ocp')->mkpath;
        bless { dir => $dir }, $class;
    }
    sub distribution          { 'k3s' }
    sub gpu_driver            { 'host' }
    sub gpu_toolkit           { 1 }
    sub gpu_enabled           { 1 }
    # ocp node add --gpu checks the gpu: block first (k333, k306): a valid one.
    sub spec_errors           { () }
    sub has_external_cache    { 0 }
    sub has_external_upstream { 0 }
    sub project_dir           { $_[0]{dir} }
    sub cluster_status        { +{} }
    sub deployed_file         { $_[0]{dir}->child('.ocp', 'deployed.yaml')->stringify }
}

# Status answers.
sub gpu { my ($alloc, $cap) = @_; return { allocatable => $alloc, capacity => $cap } }
my $ONE   = gpu({ 'nvidia.com/gpu' => '1' }, { 'nvidia.com/gpu' => '1' });
my $STALE = gpu({ 'nvidia.com/gpu' => '0' }, { 'nvidia.com/gpu' => '1' });
my $NONE  = gpu({}, {});

# Only the network is faked: server-side apply and the operator Deployment's
# rollout. Returns what wait_seconds was asked for, in order.
sub with_cluster {
    my ($code) = @_;
    my @waits;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::K8s::server_side_apply = sub { 1 };
    local *OCP::Cmd::Apply::_poll_deployment_ready = sub { 1 };
    local *OCP::Cmd::Apply::wait_seconds           = sub { push @waits, $_[1] };
    # The CRD and ClusterPolicy comparisons of a running operator are
    # t/228's and t/40's. Here they find nothing, so "up to date" can happen.
    local *OCP::Drift::gpu_crds_differing                         = sub { () };
    local *OCP::Cmd::Apply::Workloads::cluster_policy_differences = sub { () };
    my @r = $code->();
    return (\@waits, @r);
}

sub new_apply {
    my ($api) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);
    $apply->{_k8s_api} = $api;
    return $apply;
}

# setup_gpu_operator, the step behind every GPU Operator check of
# `ocp apply` (deploy, reconcile, after the worker join). With `deployed`
# the operator is rolled out first, so this run finds it up to date.
sub gpu_step {
    my (%o) = @_;
    my $api    = NvApi->new;
    my $config = FakeConfig->new;
    if ($o{deployed}) {
        $api->{nodes} = { map { $_ => [ $ONE ] } keys %{ $o{nodes} } };
        with_cluster(sub { capture { OCP::Cmd::Apply::Workloads::setup_gpu_operator(new_apply($api), $config) } });
        $api->{running} = 1;
        $api->{reads}   = {};
    }
    $api->{nodes} = $o{nodes};
    my ($waits, $rv, $out, $err, $died) = with_cluster(sub {
        capture { OCP::Cmd::Apply::Workloads::setup_gpu_operator(new_apply($api), $config) }
    });
    my $hashes = -f $config->deployed_file ? YAML::XS::LoadFile($config->deployed_file) : {};
    return { outcome => $rv, out => $out, err => $err, died => $died, waits => $waits,
             reads => $api->{reads}, hashes => $hashes };
}

my $BUDGET = OCP::Cmd::Apply::Workloads::gpu_ready_timeout();
my $READS  = int($BUDGET / OCP::Cmd::Apply::Workloads::gpu_ready_interval()) + 1;
my $WARN   = "  [WARN] NVIDIA GPU not ready after ${BUDGET}s: ";

#
# ocp apply
#

subtest 'apply: allocatable 1 after a rollout is ready, said on STDOUT' => sub {
    my $r = gpu_step(nodes => { crag => [ $ONE ] });
    is $r->{died}, '', 'no death';
    is $r->{outcome}, 'deployed', 'deployed';
    like $r->{out}, qr/Waiting for nvidia\.com\/gpu on crag\.\.\.\n\s+nvidia\.com\/gpu allocatable on crag\n/,
        'the wait and its answer';
    is $r->{err}, '', 'nothing on STDERR';
    is $r->{reads}{crag}, 1, 'one read: there at once';
};

subtest 'apply: allocatable 0 with capacity 1 is a WARN; the step stands' => sub {
    my $r = gpu_step(nodes => { crag => [ $STALE ] });
    is $r->{died}, '', 'not a failed step';
    is $r->{outcome}, 'deployed', 'the verdict is the rollout\'s';
    is $r->{err}, $WARN . "node 'crag' shows no nvidia.com/gpu in status.allocatable"
        . " (capacity 1: stale after a device plugin unregisters, or unhealthy devices)\n",
        'on STDERR: the node, allocatable, and the capacity that stands without it';
    unlike $r->{out}, qr/allocatable on/, 'not called allocatable on STDOUT';
    is $r->{reads}{crag}, $READS, 'read for the whole budget';
    ok $r->{hashes}{'gpu-operator'}, 'the rollout is recorded all the same';
};

subtest 'apply: no nvidia.com/gpu at all is said without a capacity' => sub {
    my $r = gpu_step(nodes => { crag => [ $NONE ] });
    is $r->{err}, $WARN . "node 'crag' shows no nvidia.com/gpu in status.allocatable\n", 'what the node shows';
};

subtest 'apply: allocatable decides, capacity never does' => sub {
    my $r = gpu_step(nodes => { crag => [ gpu({}, { 'nvidia.com/gpu' => '1' }) ] });
    like $r->{err}, qr/node 'crag' shows no nvidia\.com\/gpu in status\.allocatable \(capacity 1/,
        'capacity 1 without allocatable: not ready';
    $r = gpu_step(nodes => { crag => [ gpu({ 'nvidia.com/gpu' => '2' }, { 'nvidia.com/gpu' => '4' }) ] });
    is $r->{err}, '', 'allocatable 2 of capacity 4: ready';
    $r = gpu_step(nodes => { crag => [ gpu({ 'nvidia.com/gpu' => '1' }, {}) ] });
    is $r->{err}, '', 'allocatable 1 with no capacity listed: ready';
};

subtest 'apply: "up to date" waits too, until the plugin registers' => sub {
    my $r = gpu_step(deployed => 1, nodes => { crag => [ $NONE, $STALE, $STALE, $ONE ] });
    is $r->{outcome}, 'unchanged', 'up to date';
    like $r->{out}, qr/already deployed \(up to date\)\n.*Waiting for nvidia\.com\/gpu on crag.*allocatable on crag\n/s,
        'and still waited for the node';
    is $r->{err}, '', 'nothing on STDERR';
    is_deeply $r->{waits}, [ (OCP::Cmd::Apply::Workloads::gpu_ready_interval()) x 3 ],
        'three intervals until the fourth read';
};

subtest 'apply: "up to date" on a node that never gets there: the whole budget, then the WARN' => sub {
    my $r = gpu_step(deployed => 1, nodes => { crag => [ $STALE ] });
    is $r->{outcome}, 'unchanged', 'up to date';
    is sum0(@{ $r->{waits} }), $BUDGET, 'waited the whole budget';
    like $r->{err}, qr/\A\Q$WARN\Enode 'crag' shows no/, 'then said it';
};

subtest 'apply: every NVIDIA node by its own answer' => sub {
    my $r = gpu_step(nodes => { brain => [ $ONE ], crag => [ $STALE ] });
    like $r->{out}, qr/Waiting for nvidia\.com\/gpu on brain, crag\.\.\./, 'both waited for';
    like $r->{out}, qr/nvidia\.com\/gpu allocatable on brain\n/, 'brain is ready';
    like $r->{err}, qr/node 'crag' shows no/, 'crag is not';
    unlike $r->{err}, qr/brain/, 'and brain is not in the warning';
    is $r->{reads}{brain}, 1, 'brain is not read again once it was there';
};

subtest 'apply k269: a failed read is no verdict; the last one is the why' => sub {
    for my $code (403, 500) {
        my $r = gpu_step(nodes => { crag => [ api_error($code, 'Refused') ] });
        is $r->{died}, '', "$code: not a failed step";
        is $r->{reads}{crag}, $READS, "$code: read again for the whole budget";
        like $r->{err}, qr/\A\Q$WARN\Ecould not read Node 'crag': Kubernetes API error \(get\): $code .*"reason":"Refused"/,
            "$code: the cause, not a node without a GPU";
        unlike $r->{err}, qr/not found|shows no/, "$code: neither absent nor GPU-less";
    }

    my $r = gpu_step(nodes => { crag => [ api_error(500, 'Blip'), api_error(403, 'Forbidden') ] });
    like $r->{err}, qr/: 403 .*Forbidden/, 'the last failed read is named';
    unlike $r->{err}, qr/Blip/, 'not an earlier one';

    $r = gpu_step(nodes => { crag => [ "404 Node/crag not found\n" ] });
    is $r->{err}, $WARN . "Node 'crag' not found\n", 'a 404: not found';

    $r = gpu_step(nodes => { crag => [ api_error(500, 'Blip'), $ONE ] });
    is $r->{err}, '', 'a 500 once, then allocatable: ready, nothing on STDERR';
    like $r->{out}, qr/allocatable on crag/, 'said on STDOUT';
};

subtest 'apply: the budget and the interval are gpu_ready_timeout and gpu_ready_interval' => sub {
    no warnings 'redefine';
    local *OCP::Cmd::Apply::Workloads::gpu_ready_timeout  = sub { 30 };
    local *OCP::Cmd::Apply::Workloads::gpu_ready_interval = sub { 5 };
    my $r = gpu_step(deployed => 1, nodes => { crag => [ $STALE ] });
    is_deeply $r->{waits}, [ (5) x 6 ], 'six waits of 5s';
    like $r->{err}, qr/NVIDIA GPU not ready after 30s: /, 'and the WARN names that budget';
};

subtest 'apply k287: a worker that joins after a check that ran is waited for' => sub {
    # The first check rolled the operator out for brain. crag joins in the
    # worker step, NFD labels it, and its plugin registers a while later.
    my $api    = NvApi->new;
    my $config = FakeConfig->new;
    my $apply  = new_apply($api);
    $api->{nodes} = { brain => [ $ONE ] };
    my (undef, $first) = with_cluster(sub {
        capture { OCP::Cmd::Apply::Workloads::setup_gpu_operator($apply, $config) } });
    is $first, 'deployed', 'the first check deployed';
    @$api{qw( running reads )} = (1, {});

    my $after_join = sub {
        my (@answers) = @_;
        $api->{nodes}{crag} = [ @answers ];
        my ($waits, $rv, $out, $err, $died) = with_cluster(sub { capture {
            OCP::Cmd::Apply::Workloads::setup_gpu_operator_after_join($apply, $config, $first, 'crag')
        } });
        return { outcome => $rv, out => $out, err => $err, died => $died, waits => $waits };
    };

    my $r = $after_join->($NONE, $NONE, $STALE, $ONE);
    is $r->{died}, '', 'no death';
    is $r->{outcome}, 'unchanged', 'checked again: up to date';
    like $r->{out}, qr/Checking GPU Operator again, after the worker join\.\.\.\n.*Waiting for nvidia\.com\/gpu on brain, crag\.\.\.\n\s+nvidia\.com\/gpu allocatable on brain, crag\n/s,
        'and waited for the new worker, on STDOUT';
    is $r->{err}, '', 'nothing on STDERR';
    is sum0(@{ $r->{waits} }), 2 * OCP::Cmd::Apply::Workloads::gpu_ready_interval(), 'until its plugin registered';

    $r = $after_join->($STALE);
    is $r->{died}, '', 'never: not a failed step';
    is $r->{outcome}, 'unchanged', 'the verdict stands';
    is $r->{err}, $WARN . "node 'crag' shows no nvidia.com/gpu in status.allocatable"
        . " (capacity 1: stale after a device plugin unregisters, or unhealthy devices)\n",
        'the WARN, on STDERR';
};

#
# ocp node add --gpu
#

# `ocp node add brain --gpu` down the CLI path to a Ready node on a cluster
# whose GPU Operator a previous apply rolled out. Everything after Ready is
# the real code, with only the network faked.
sub run_add {
    my (@answers) = @_;
    my $api    = NvApi->new;
    my $config = FakeConfig->new;
    $api->{nodes} = { brain => [ $ONE ] };
    with_cluster(sub { capture { OCP::Cmd::Apply::Workloads::setup_gpu_operator(new_apply($api), $config) } });
    @$api{qw( running reads )} = (1, {});
    $api->{nodes} = { brain => [ @answers ] };

    my $add = OCP::Cmd::Node::Add->new(
        k8s           => $api,
        name          => 'brain',
        host          => '10.0.0.5',
        gpu           => 1,
        command_chain => [ FakeOCP->new ],
    );
    my $add_waited = 0;
    no warnings 'redefine';
    local *OCP::Cmd::Node::Add::_config            = sub { $config };
    local *OCP::Cmd::Node::Add::_resolve_provider  = sub { +{ metadata => { name => 'ssh-default' },
                                                               spec     => { type => 'ssh' } } };
    local *OCP::Cmd::Node::Add::_robocop_ready     = sub { 0 };
    local *OCP::Cmd::Node::Add::_preflight_host    = sub { 1 };
    local *OCP::Cmd::Node::Add::_cli_reconcile     = sub { 1 };
    local *OCP::Cmd::Node::Add::wait_seconds       = sub { $add_waited += $_[1] };
    my ($waits, $rv, $out, $err, $died) = with_cluster(sub { capture { $add->execute([], []) } });
    return { rv => $rv, out => $out, err => $err, died => $died, waits => $waits, reads => $api->{reads} };
}

subtest 'node add --gpu: allocatable 1 on the new node is ready' => sub {
    my $r = run_add($ONE);
    is $r->{died}, '', 'no death';
    is $r->{rv}, 0, 'exit 0';
    like $r->{out}, qr/Node 'brain' is Ready\..*Checking GPU Operator.*up to date\)\n\s+Waiting for nvidia\.com\/gpu on brain\.\.\.\n\s+nvidia\.com\/gpu allocatable on brain\n  \[ok\] GPU Operator up to date/s,
        'after Ready: the check, the wait, the answer, the verdict';
    is $r->{err}, '', 'nothing on STDERR';
};

subtest 'node add --gpu: the plugin registers while it waits' => sub {
    my $r = run_add($NONE, $NONE, $STALE, $ONE);
    is $r->{err}, '', 'nothing on STDERR';
    like $r->{out}, qr/allocatable on brain/, 'ready';
    ok sum0(@{ $r->{waits} }) > 0, 'after waiting';
};

subtest 'node add --gpu: allocatable 0 is a WARN with the diagnosis; the join stands' => sub {
    my $r = run_add($STALE);
    is $r->{rv}, 0, 'exit 0: the node is Ready';
    like $r->{out}, qr/Node 'brain' is Ready\./, 'said as Ready';
    is $r->{err}, $WARN . "node 'brain' shows no nvidia.com/gpu in status.allocatable"
        . " (capacity 1: stale after a device plugin unregisters, or unhealthy devices)\n",
        'the WARN, on STDERR, and nothing else';
    unlike $r->{out}, qr/allocatable on brain/, 'not called allocatable';
    is sum0(@{ $r->{waits} }), $BUDGET, 'after the whole budget';
};

subtest 'node add --gpu k269: an unreadable node is said as that' => sub {
    my $r = run_add($ONE, api_error(403, 'Forbidden'));
    is $r->{rv}, 0, 'exit 0';
    like $r->{err}, qr/\A\Q$WARN\Ecould not read Node 'brain': Kubernetes API error \(get\): 403 /,
        'the cause of the last read';
};

done_testing;
