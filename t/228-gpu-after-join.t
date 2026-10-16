#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
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
                                                  k8s_name => $o{k8s_name} // {}));
    my $out = '';
    my $got;
    {
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        $got = OCP::Cmd::Apply::Workloads::setup_gpu_operator_after_join(
            $apply, FakeConfig->new(%{ $o{config} // {} }), $o{first}, @{ $o{names} // [] });
    }
    return { got => $got, calls => $calls, apply => $apply, out => $out };
}

subtest 'no second check when it is not needed' => sub {
    my $r = run_after_join(config => { gpu => 0 }, first => 'skipped', names => ['crag']);
    ok !defined $r->{got} && !$r->{calls}, 'gpu.enabled false';
    $r = run_after_join(first => 'deployed', names => ['crag']);
    ok !defined $r->{got} && !$r->{calls}, 'the first check deployed: its DaemonSets cover new nodes';
    $r = run_after_join(first => 'unchanged', names => ['crag']);
    ok !defined $r->{got} && !$r->{calls}, 'the first check found it up to date';
    $r = run_after_join(first => undef, names => ['crag']);
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
    like $r->{out}, qr/\[WARN\] NFD has not labelled crag after 30s/, 'said';
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

done_testing;
