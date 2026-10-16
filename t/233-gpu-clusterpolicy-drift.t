#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::PP ();
use YAML::XS ();

use lib 'lib';

use OCP::Cmd::Apply::Workloads;
use OCP::Cmd::Apply::Drift;

#
# Lab 2026-10-16 round 6, note 24: the runc pin taken out of the ClusterPolicy
# with kubectl patch was no drift -- dry-run said nothing, apply called the
# operator up to date. Note 27: dry-run did not announce a gpu.toolkit
# switch. Only what OCP sets is compared; the apiserver's defaults are not
# drift.
#

my $want = {
    apiVersion => 'nvidia.com/v1', kind => 'ClusterPolicy',
    metadata => { name => 'gpu-cluster-policy' },
    spec => {
        cdi     => { enabled => JSON::PP::true },
        toolkit => { enabled => JSON::PP::true, version => 'v1.19.1',
                     env => [ { name => 'CONTAINERD_SOCKET', value => '/run/k3s/containerd/containerd.sock' },
                              { name => 'NVIDIA_CONTAINER_RUNTIME_RUNTIMES', value => 'runc,crun' } ] },
        daemonsets => {},
    },
};
my $MANIFEST = YAML::XS::Dump({ kind => 'Namespace', metadata => { name => 'gpu-operator' } }, $want);

# What the apiserver hands back: the same, plus CRD defaults and status.
sub live {
    my $cp = JSON::PP::decode_json(JSON::PP::encode_json($want));
    $cp->{spec}{daemonsets}{updateStrategy} = 'RollingUpdate';
    $cp->{spec}{toolkit}{installDir} = '/usr/local/nvidia';
    $cp->{status} = { state => 'ready' };
    $_[0]->($cp) if $_[0];
    return $cp;
}

{
    package FakeApply;
    sub new { my ($c, %o) = @_; bless { %o }, $c }
    sub _crd_get { $_[0]{cp} }
    sub _k8s_api { 'API' }
    sub _resource_exists { $_[0]{running} // 1 }
}
{
    package FakeConfig;
    sub new { my ($c, %o) = @_; bless { toolkit => 1, %o }, $c }
    sub gpu_enabled { 1 }
    sub gpu_toolkit { $_[0]{toolkit} }
}

sub diffs {
    my ($cp) = @_;
    return [ OCP::Cmd::Apply::Workloads::cluster_policy_differences(
        FakeApply->new(cp => $cp), FakeConfig->new, 'API', $MANIFEST) ];
}

is_deeply diffs(live()), [], 'as applied, plus the apiserver\'s defaults: no drift';
is_deeply diffs(live(sub { pop @{ $_[0]{spec}{toolkit}{env} } })), ['spec.toolkit.env'],
    'the runc pin patched out: spec.toolkit.env';
is_deeply diffs(live(sub { $_[0]{spec}{toolkit}{version} = 'v1.18.0' })), ['spec.toolkit.version'],
    'another toolkit version';
is_deeply diffs(live(sub { $_[0]{spec}{cdi}{enabled} = JSON::PP::false })), ['spec.cdi.enabled'],
    'a boolean flipped';
is_deeply diffs(live(sub { delete $_[0]{spec}{toolkit} })), ['spec.toolkit'], 'a section gone';
is_deeply diffs(undef), [], 'no ClusterPolicy to read: nothing said here';

{
    open my $fh, '<', 'lib/OCP/Cmd/Apply/Workloads.pm' or die;
    my $src = do { local $/; <$fh> };
    like $src, qr/cluster_policy_differences\(\$self, \$config, \$api, \$manifest\).*?!\@cp_differ/s,
        'apply re-applies on a differing ClusterPolicy instead of calling it up to date';
}

subtest 'dry-run says both' => sub {
    no warnings 'redefine';
    local *OCP::Cmd::Apply::Workloads::generate_gpu_operator_manifest = sub { $MANIFEST };
    my $out = '';
    my @r;
    {
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        @r = OCP::Cmd::Apply::Drift::gpu_dry_run(
            FakeApply->new(cp => live(sub { pop @{ $_[0]{spec}{toolkit}{env} } })),
            FakeConfig->new(toolkit => 0));
    }
    is_deeply \@r, ['spec.toolkit.env'], 'one action';
    like $out, qr/\[drift\] GPU Operator ClusterPolicy differs from the spec at spec\.toolkit\.env/, 'named';
    like $out, qr/\[WARN\] gpu\.toolkit changed \(true -> false\)/, 'the toolkit switch is announced';

    $out = '';
    {
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        @r = OCP::Cmd::Apply::Drift::gpu_dry_run(FakeApply->new(cp => live(), running => 0), FakeConfig->new);
    }
    is_deeply \@r, [], 'no operator running: nothing';
    is $out, '', 'and silent';
};

subtest 'quiet: the same finding, said nowhere (k234)' => sub {
    no warnings 'redefine';
    local *OCP::Cmd::Apply::Workloads::generate_gpu_operator_manifest = sub { $MANIFEST };
    my $out = '';
    my @r;
    {
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        @r = OCP::Cmd::Apply::Drift::gpu_dry_run(
            FakeApply->new(cp => live(sub { pop @{ $_[0]{spec}{toolkit}{env} } })),
            FakeConfig->new(toolkit => 0), quiet => 1);
    }
    is_deeply \@r, ['spec.toolkit.env'], 'found, so "No drift detected" can be held back';
    is $out, '', 'and nothing printed';
};


done_testing;
