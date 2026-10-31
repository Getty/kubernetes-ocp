#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Kubernetes::REST::APIError;
use Path::Tiny qw(path);

use lib 'lib';

use OCP::Cmd::Apply::Workloads;
use OCP::Cmd::Apply::Deploy;

#
# k228 point 2 (lab 2026-10-16): an apply that joins a GPU worker through an
# ssh pool ran "Checking GPU Operator" before the join, found no NVIDIA label
# and skipped; the operator only came with the second apply. When the first
# check skipped and workers came up, the check runs again once NFD has looked
# at the new nodes.
#
# k287: a first check that ran (did not skip) covered the NVIDIA nodes it
# detected; one that joined later in the run was not waited for until the
# next apply. Now the check runs again for it too, once NFD labelled it as
# an NVIDIA node: setup_gpu_operator, up to date, waits for its
# nvidia.com/gpu in allocatable (k273). A worker without one gets no second
# check.
#

{
    package FakeK8s;
    sub new              { bless {}, shift }
    sub object_to_struct { $_[1] }
}
{
    package FakeApi;
    sub new { my ($c, %o) = @_; bless { %o, gets => [] }, $c }
    sub k8s { FakeK8s->new }
    sub get {
        my ($self, $kind, %a) = @_;
        push @{ $self->{gets} }, "$kind/$a{name}";
        # A read that fails the way the test says (k277): { "Kind/name" =>
        # error, or a sub that returns one -- or undef to read after all }.
        my $fail = $self->{fails}{"$kind/$a{name}"};
        $fail = $fail->() if ref $fail eq 'CODE';
        die $fail if $fail;
        if ($kind eq 'OCPNode') {
            return { status => { kubernetesNodeName => $self->{k8s_name}{ $a{name} } // $a{name} } };
        }
        my $labels = $self->{labels}{ $a{name} };
        $labels = $labels->() if ref $labels eq 'CODE';
        return { metadata => { labels => $labels // {} } };
    }
}
{
    package FakeConfig;
    sub new         { my ($c, %o) = @_; bless { gpu => 1, %o }, $c }
    sub gpu_enabled { $_[0]{gpu} }
}
{
    package FakeApply;
    sub new { my ($c, %o) = @_; bless { waited => 0, reported => [], %o }, $c }
    sub _k8s_api     { $_[0]{api} }
    sub wait_seconds { $_[0]{waited} += $_[1] }
    sub _setup_gpu_operator_after_join {
        my $self = shift;
        return OCP::Cmd::Apply::Workloads::setup_gpu_operator_after_join($self, @_);
    }
    sub _report_component { my ($s, $l, $o) = @_; push @{ $s->{reported} }, "$l=$o"; 0 }
}

# What Kubernetes::REST dies with for an HTTP error status (as in t/269).
sub api_error {
    my ($code, $reason) = @_;
    return Kubernetes::REST::APIError->new(code => $code, context => 'get',
        body => qq({"kind":"Status","status":"Failure","reason":"$reason","code":$code}));
}
my @REFUSALS = ([403, 'Forbidden'], [500, 'InternalError']);

my $NFD_ONLY = { 'feature.node.kubernetes.io/system-os_release.ID' => 'ubuntu' };
my $NFD_GPU  = { %$NFD_ONLY, 'feature.node.kubernetes.io/pci-0300_10de.present' => 'true' };

sub run_after_join {
    my (%o) = @_;
    my $calls = 0;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::Workloads::setup_gpu_operator = sub {
        $calls++;
        die $o{die} if $o{die};
        return $o{verdict} // 'deployed';
    };
    local *OCP::Cmd::Apply::Workloads::gpu_label_interval = sub { 10 };
    local *OCP::Cmd::Apply::Workloads::gpu_label_timeout  = sub { 30 };
    my $apply = FakeApply->new(api => FakeApi->new(labels => $o{labels} // {},
                                                  k8s_name => $o{k8s_name} // {},
                                                  fails => $o{fails} // {}));
    my ($out, $err) = ('', '');
    my ($got, $died);
    {
        local *STDOUT;
        local *STDERR;
        open STDOUT, '>', \$out or die;
        open STDERR, '>', \$err or die;
        $got = eval { OCP::Cmd::Apply::Workloads::setup_gpu_operator_after_join(
            $apply, FakeConfig->new(%{ $o{config} // {} }), $o{first}, @{ $o{names} // [] }) };
        $died = $@;
    }
    return { got => $got, calls => $calls, apply => $apply, out => $out, err => $err, died => $died };
}

subtest 'no second check when it is not needed' => sub {
    my $r = run_after_join(config => { gpu => 0 }, first => 'skipped', names => ['crag']);
    ok !defined $r->{got} && !$r->{calls}, 'gpu.enabled false';
    $r = run_after_join(first => 'deployed', names => ['cpu1'], labels => { cpu1 => $NFD_ONLY });
    ok !defined $r->{got} && !$r->{calls}, 'the first check deployed, and the worker has no NVIDIA GPU';
    $r = run_after_join(first => 'unchanged', names => ['cpu1'], labels => { cpu1 => $NFD_ONLY });
    ok !defined $r->{got} && !$r->{calls}, 'the first check found it up to date, and the worker has no NVIDIA GPU';
    $r = run_after_join(first => undef, names => ['crag'], labels => { crag => $NFD_GPU });
    ok !defined $r->{got} && !$r->{calls}, 'the first check failed: said already, not retried here';
    $r = run_after_join(first => 'skipped', names => []);
    ok !defined $r->{got} && !$r->{calls}, 'nobody joined';
};

subtest 'skipped before the join: checked again once NFD labelled the node' => sub {
    my $seen = 0;
    my $r = run_after_join(first => 'skipped', names => ['crag'],
        labels => { crag => sub { $seen++ ? $NFD_GPU : {} } });
    is $r->{got}, 'deployed', 'the verdict of the second check';
    is $r->{calls}, 1, 'setup_gpu_operator ran once';
    is $r->{apply}{waited}, 10, 'waited one interval for NFD';
    like $r->{out}, qr/Checking GPU Operator again, after the worker join/, 'said';
};

subtest 'k287: the first check ran: checked again for a worker NFD labels as NVIDIA' => sub {
    for my $first (qw( deployed updated restored unchanged )) {
        my $seen = 0;
        my $r = run_after_join(first => $first, names => ['crag'], verdict => 'unchanged',
            labels => { crag => sub { $seen++ ? $NFD_GPU : {} } });
        is $r->{calls}, 1, "first $first: setup_gpu_operator ran again, for its allocatable wait";
        is $r->{got}, 'unchanged', "first $first: its verdict";
        is $r->{apply}{waited}, 10, "first $first: after NFD labelled the node";
        like $r->{out}, qr/Waiting for NFD on the new worker\(s\): crag\n.*Checking GPU Operator again, after the worker join/s,
            "first $first: said";
    }

    my $r = run_after_join(first => 'deployed', names => [qw( cpu1 crag )], verdict => 'unchanged',
        labels => { cpu1 => $NFD_ONLY, crag => $NFD_GPU });
    is $r->{calls}, 1, 'one NVIDIA worker among others is enough';

    $r = run_after_join(first => 'deployed', names => ['cpu1'], labels => { cpu1 => $NFD_ONLY });
    is $r->{apply}{waited}, 0, 'a worker without one: no wait beyond NFD\'s first look';
    like $r->{out}, qr/Waiting for NFD on the new worker\(s\): cpu1\n {6}No NVIDIA GPU on the new worker\(s\)\n\z/,
        'and the wait answered on STDOUT';

    $r = run_after_join(first => 'deployed', names => ['crag'], labels => { crag => {} });
    is $r->{apply}{waited}, 30, 'NFD never labels: the whole budget';
    ok !$r->{calls}, 'and no second check: nothing says the node has an NVIDIA GPU';

    $r = run_after_join(first => 'deployed', names => ['crag'], k8s_name => { crag => '10-230-30-250' },
        verdict => 'unchanged', labels => { '10-230-30-250' => $NFD_GPU });
    is $r->{calls}, 1, 'the label is read on the Node the OCPNode names';
};

subtest 'a worker without GPU does not hold the run for the budget' => sub {
    my $r = run_after_join(first => 'skipped', names => ['cpu1'], labels => { cpu1 => $NFD_ONLY },
        verdict => 'skipped');
    is $r->{apply}{waited}, 0, 'any NFD label means NFD has looked: no wait';
    is $r->{got}, 'skipped', 'and the check decides on what it sees';
};

subtest 'the Kubernetes Node name comes from the OCPNode' => sub {
    my $r = run_after_join(first => 'skipped', names => ['crag'],
        k8s_name => { crag => '10-230-30-250' }, labels => { '10-230-30-250' => $NFD_GPU });
    ok( (grep { $_ eq 'Node/10-230-30-250' } @{ $r->{apply}{api}{gets} }), 'Node looked up by status.kubernetesNodeName');
};

subtest 'NFD never labels: warned, checked anyway' => sub {
    my $r = run_after_join(first => 'skipped', names => ['crag'], labels => { crag => {} },
        verdict => 'skipped');
    is $r->{apply}{waited}, 30, 'the whole budget';
    # k278: on STDERR -- the label that did not come is something that went wrong.
    like   $r->{err}, qr/^  \[WARN\] NFD has not labelled crag after 30s; checking with what is there$/m,
        'said, on STDERR';
    unlike $r->{out}, qr/NFD has not labelled/, 'not on STDOUT';
    is $r->{calls}, 1, 'still checked';
};

subtest 'gpu_after_join: only Ready workers, a failure is counted' => sub {
    no warnings 'redefine';
    my @args;
    local *FakeApply::_setup_gpu_operator_after_join = sub { shift; @args = @_; 'deployed' };
    my $apply = FakeApply->new(_gpu_outcome => 'skipped');
    ok OCP::Cmd::Apply::Deploy::gpu_after_join($apply, FakeConfig->new,
        [ { name => 'crag', phase => 'Ready' }, { name => 'ghost', phase => 'Failed' } ]), 'true';
    is_deeply [ @args[2 .. $#args] ], ['crag'], 'only the worker that came up';
    is $args[1], 'skipped', 'with the first check\'s verdict';
    is_deeply $apply->{reported}, ['GPU Operator=deployed'], 'the verdict is reported';

    @args = ();
    ok OCP::Cmd::Apply::Deploy::gpu_after_join($apply, FakeConfig->new,
        [ { name => 'ghost', phase => 'Failed' } ]), 'nobody Ready: true';
    ok !@args, 'and no check';

    local *FakeApply::_setup_gpu_operator_after_join = sub { die "ClusterPolicy rejected\n" };
    my $err = '';
    my $ok;
    {
        local *STDERR;
        open STDERR, '>', \$err or die;
        $ok = OCP::Cmd::Apply::Deploy::gpu_after_join($apply, FakeConfig->new,
            [ { name => 'crag', phase => 'Ready' } ]);
    }
    ok !$ok, 'a failed second check returns false';
    like $err, qr/\[!!\] GPU Operator setup failed: ClusterPolicy rejected/, 'on STDERR';
};

subtest 'both apply paths run it after their worker step' => sub {
    my $deploy = path('lib/OCP/Cmd/Apply/Deploy.pm')->slurp_utf8;
    like $deploy, qr/worker_step\(\$self.*?gpu_after_join\(\$self, \$config, \\\@results\)/s,
        'fresh deploy';
    my $drift = path('lib/OCP/Cmd/Apply/Drift.pm')->slurp_utf8;
    like $drift, qr/Deploy::worker_step\(.*?Deploy::gpu_after_join\(\$self, \$config, \\\@results\)/s,
        'reconcile';
    like $drift, qr/\$self->\{_gpu_outcome\} = \$outcome/, 'the reconcile keeps the first verdict';
};

#
# k277: the after-join check read the OCPNode and the Node through an eval
# that took every failure for absence -- an OCPNode it could not read for one
# without a Kubernetes name, a Node it could not read for one without labels,
# so after a first check that ran, "No NVIDIA GPU on the new worker(s)". Only
# a 404 is absent. An OCPNode read that fails otherwise dies (the step's
# [!!]); a Node read is polled again, the last failed one is named, and a node
# that could not be read is checked rather than called GPU-less.
#

subtest 'k277: the OCPNode -- a 404 leaves its name, a refusal fails the check' => sub {
    my $r = run_after_join(first => 'skipped', names => ['crag'], labels => { crag => $NFD_GPU },
        fails => { 'OCPNode/crag' => api_error(404, 'NotFound') });
    is $r->{died}, '', '404: no death';
    ok( (grep { $_ eq 'Node/crag' } @{ $r->{apply}{api}{gets} }), '404: the Node read by the OCPNode\'s name');
    is $r->{calls}, 1, '404: checked';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = run_after_join(first => 'skipped', names => ['crag'], labels => { crag => $NFD_GPU },
            fails => { 'OCPNode/crag' => api_error($code, $reason) });
        like $r->{died}, qr{\Acould not read OCPNode ocp-system/crag: Kubernetes API error \(get\): $code .*"reason":"$reason"},
            "$code: dies with the cause (gpu_after_join says it, [!!], counted)";
        ok !$r->{calls}, "$code: no check on a guessed name";
        ok !(grep { $_ eq 'Node/crag' } @{ $r->{apply}{api}{gets} }), "$code: no Node read under the OCPNode's name";
    }
};

subtest 'k277: the Node -- a refusal is no worker without a GPU' => sub {
    my $r = run_after_join(first => 'deployed', names => ['crag'],
        fails => { 'Node/crag' => api_error(404, 'NotFound') });
    is $r->{apply}{waited}, 30, '404 throughout: the whole budget';
    like $r->{err}, qr/^  \[WARN\] NFD has not labelled crag after 30s; checking with what is there\n\z/,
        '404 throughout: the NFD line, and no failed read named';
    ok !$r->{calls}, '404 throughout: no Node, no NVIDIA label, no second check';

    for my $refusal (@REFUSALS) {
        my ($code, $reason) = @$refusal;
        $r = run_after_join(first => 'deployed', names => ['crag'], verdict => 'unchanged',
            fails => { 'Node/crag' => api_error($code, $reason) });
        is $r->{died}, '', "$code throughout: no death";
        is $r->{apply}{waited}, 30, "$code throughout: read again for the whole budget";
        like $r->{err}, qr{^  \[WARN\] NFD has not labelled crag after 30s; checking with what is there\n {9}the last read failed: could not read Node 'crag': Kubernetes API error \(get\): $code .*"reason":"$reason".*\n\z},
            "$code throughout: the last failed read named, on STDERR";
        unlike $r->{out}, qr/No NVIDIA GPU/, "$code throughout: not called GPU-less";
        is $r->{calls}, 1, "$code throughout: checked, setup_gpu_operator decides on what it sees";
        is $r->{got}, 'unchanged', "$code throughout: its verdict";

        my $seen = 0;
        $r = run_after_join(first => 'deployed', names => ['crag'], labels => { crag => $NFD_ONLY },
            fails => { 'Node/crag' => sub { $seen++ ? undef : api_error($code, $reason) } });
        is $r->{err}, '', "$code once, then read: nothing on STDERR";
        like $r->{out}, qr/No NVIDIA GPU on the new worker\(s\)/, "$code once, then read: decided on the read";
        ok !$r->{calls}, "$code once, then read: no second check";
    }
};

done_testing;
