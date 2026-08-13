#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Encode ();

use lib 'lib';

use OCP::Cmd::Apply;

#
# `ocp apply` printed CONTROL PLANE DEPLOYED SUCCESSFULLY! and exited 0 as soon
# as its deploy steps had run. On cortex it did that while kube-system/coredns
# was in CrashLoopBackOff — cluster DNS entirely dead — and five gpu-operator
# pods hung in Init:ImagePullBackOff. The banner described the script, not the
# cluster. xt/smoke.sh checked exactly this from the outside; nothing checked it
# from inside apply.
#
# The gate has to survive two opposite failure modes: declaring a healthy
# cluster broken because pods are still coming up, and declaring a broken
# cluster healthy. The fixtures below are taken from the states seen on cortex.
#

my $apply = bless {}, 'OCP::Cmd::Apply';

sub pod {
    my (%a) = @_;
    return {
        metadata => { name => $a{name}, namespace => $a{ns} },
        status   => {
            phase => $a{phase} // 'Running',
            ($a{init}      ? (initContainerStatuses => $a{init})      : ()),
            ($a{containers} ? (containerStatuses    => $a{containers}) : ()),
        },
    };
}

sub waiting { { state => { waiting => { reason => $_[0] } }, restartCount => $_[1] // 0, ready => 0 } }
sub running { { state => { running => {} }, ready => $_[0] // 1, restartCount => 0 } }

package FakeList {
    sub new   { my ($c, $i) = @_; bless { items => $i }, $c }
    sub items { $_[0]{items} }
}
package FakeApi {
    sub new  { my ($c, %a) = @_; bless { %a, calls => [] }, $c }
    sub k8s  { $_[0] }
    sub object_to_struct { $_[1] }
    sub list {
        my ($self, $kind) = @_;
        push @{$self->{calls}}, $kind;
        return FakeList->new($self->{pods} // []);
    }
}

package main;

subtest 'a settled, healthy cluster reports nothing' => sub {
    my $api = FakeApi->new(pods => [
        pod(ns => 'kube-system', name => 'cilium-8pjjp',  containers => [running()]),
        pod(ns => 'kube-system', name => 'coredns-xyz',   containers => [running()]),
        pod(ns => 'ocp-system',  name => 'ocp-registry',  containers => [running()]),
        pod(ns => 'kube-system', name => 'helm-install',  phase => 'Succeeded'),
    ]);
    my $h = $apply->_check_cluster_health($api, timeout => 0);

    is scalar @{$h->{critical}}, 0, 'no critical findings';
    is scalar @{$h->{warnings}}, 0, 'no warnings';
    is scalar @{$h->{starting}}, 0, 'nothing still starting';
    is scalar @{$api->{calls}},  1, 'a single pod list, not a per-namespace sweep';
    is $api->{calls}[0], 'Pod', 'typed Kind';
};

subtest 'pods that are merely coming up are not failures' => sub {
    # This is the flakiness the gate must not have: straight after a deploy
    # these states are normal, not faults.
    my $api = FakeApi->new(pods => [
        pod(ns => 'kube-system', name => 'creating', phase => 'Pending',
            containers => [waiting('ContainerCreating')]),
        pod(ns => 'kube-system', name => 'initing',  phase => 'Pending',
            init => [waiting('PodInitializing')]),
        pod(ns => 'kube-system', name => 'unready',  containers => [running(0)]),
    ]);
    my $h = $apply->_check_cluster_health($api, timeout => 0);

    is scalar @{$h->{critical}}, 0, 'nothing declared broken';
    is scalar @{$h->{warnings}}, 0, 'nothing warned about';
    is scalar @{$h->{starting}}, 3, 'all three counted as still starting';
};

subtest 'CrashLoopBackOff in kube-system is fatal' => sub {
    # The cortex case: DNS dead, apply green.
    my $api = FakeApi->new(pods => [
        pod(ns => 'kube-system', name => 'coredns-54996dc9b4-dd4rb',
            containers => [waiting('CrashLoopBackOff', 2)]),
        pod(ns => 'kube-system', name => 'cilium-8pjjp', containers => [running()]),
    ]);
    my $h = $apply->_check_cluster_health($api, timeout => 0);

    is scalar @{$h->{critical}}, 1, 'one critical finding';
    is $h->{critical}[0]{name}, 'coredns-54996dc9b4-dd4rb', 'names the pod';
    is $h->{critical}[0]{namespace}, 'kube-system', 'names the namespace';
    like $h->{critical}[0]{reason}, qr/CrashLoopBackOff/, 'reports the reason';
    is scalar @{$h->{warnings}}, 0, 'not downgraded to a warning';
};

subtest 'a single startup crash is not yet a verdict' => sub {
    # CrashLoopBackOff with one restart can still be a dependency that came up
    # a moment later. Only a kubelet that actually looped counts.
    my $api = FakeApi->new(pods => [
        pod(ns => 'kube-system', name => 'coredns',
            containers => [waiting('CrashLoopBackOff', 1)]),
    ]);
    my $h = $apply->_check_cluster_health($api, timeout => 0);

    is scalar @{$h->{critical}}, 0, 'one restart does not fail the deploy';
    is scalar @{$h->{starting}}, 1, 'counted as still starting instead';
};

subtest 'gpu-operator ImagePullBackOff warns but does not fail the deploy' => sub {
    # All five gpu-operator pods failed in their INIT container
    # ("Init:ImagePullBackOff"), so a check that only looked at
    # containerStatuses would have seen nothing at all.
    my $api = FakeApi->new(pods => [
        pod(ns => 'gpu-operator', name => 'nvidia-dcgm-kbkwk',
            phase => 'Pending', init => [waiting('ImagePullBackOff')]),
        pod(ns => 'gpu-operator', name => 'nvidia-device-plugin-daemonset-c74jl',
            phase => 'Pending', init => [waiting('ImagePullBackOff')]),
        pod(ns => 'kube-system',  name => 'cilium-8pjjp', containers => [running()]),
    ]);
    my $h = $apply->_check_cluster_health($api, timeout => 0);

    is scalar @{$h->{critical}}, 0,
        'an opt-in add-on does not turn the whole apply red';
    is scalar @{$h->{warnings}}, 2, 'both gpu-operator pods reported';
    like $h->{warnings}[0]{reason}, qr/ImagePullBackOff/,
        'init-container reason detected';
};

subtest 'a critical fault and an optional one are reported separately' => sub {
    my $api = FakeApi->new(pods => [
        pod(ns => 'kube-system',  name => 'coredns',
            containers => [waiting('CrashLoopBackOff', 3)]),
        pod(ns => 'gpu-operator', name => 'nvidia-dcgm',
            phase => 'Pending', init => [waiting('ImagePullBackOff')]),
    ]);
    my $h = $apply->_check_cluster_health($api, timeout => 0);

    is scalar @{$h->{critical}}, 1, 'coredns is critical';
    is $h->{critical}[0]{namespace}, 'kube-system', 'and it is the kube-system one';
    is scalar @{$h->{warnings}}, 1, 'gpu-operator is a warning';
    is $h->{warnings}[0]{namespace}, 'gpu-operator', 'and it is the add-on one';
};

subtest 'other durable image and config faults are caught too' => sub {
    for my $reason (qw(ErrImagePull InvalidImageName CreateContainerConfigError
                       CreateContainerError RunContainerError)) {
        my $api = FakeApi->new(pods => [
            pod(ns => 'kube-system', name => 'broken',
                phase => 'Pending', containers => [waiting($reason)]),
        ]);
        my $h = $apply->_check_cluster_health($api, timeout => 0);
        is scalar @{$h->{critical}}, 1, "$reason fails the deploy";
    }

    my $api = FakeApi->new(pods => [
        pod(ns => 'kube-system', name => 'gone', phase => 'Failed'),
    ]);
    my $h = $apply->_check_cluster_health($api, timeout => 0);
    is scalar @{$h->{critical}}, 1, 'a Failed pod fails the deploy';
};

subtest 'the health report is printed, not swallowed' => sub {
    my $out = '';
    open my $fh, '>', \$out or die $!;
    {
        local *STDOUT = $fh;
        $apply->_print_health({
            critical => [{ namespace => 'kube-system', name => 'coredns',
                           reason => 'CrashLoopBackOff' }],
            warnings => [{ namespace => 'gpu-operator', name => 'nvidia-dcgm',
                           reason => 'ImagePullBackOff' }],
            starting => [],
        });
    }
    like $out, qr/\[!!\].*kube-system\/coredns.*CrashLoopBackOff/,
        'critical finding printed loudly';
    like $out, qr/\[WARN\].*gpu-operator\/nvidia-dcgm.*ImagePullBackOff/,
        'warning printed as a warning';
};

subtest 'the success banner is not claimed over a broken cluster' => sub {
    # The whole point: DEPLOYED SUCCESSFULLY must be reachable only when the
    # core of the cluster is actually up.
    my $clean  = { critical => [],   warnings => [],   starting => [] };
    my $warned = { critical => [],   warnings => [{}], starting => [] };
    my $broken = { critical => [{}], warnings => [],   starting => [] };

    like   $apply->_health_banner_text($clean),  qr/SUCCESSFULLY/,
        'clean run still says SUCCESSFULLY';
    unlike $apply->_health_banner_text($warned), qr/SUCCESSFULLY/,
        'warnings are visible in the banner';
    unlike $apply->_health_banner_text($broken), qr/SUCCESSFULLY/,
        'a broken cluster never says SUCCESSFULLY';
    like   $apply->_health_banner_text($broken), qr/NOT HEALTHY/,
        'and says what is wrong';

    # The banner and the exit code must key off the same thing, or one of them
    # goes back to lying.
    ok !$apply->_health_is_fatal($clean),  'clean run exits 0';
    ok !$apply->_health_is_fatal($warned),
        'an opt-in add-on failure does not change the exit code';
    ok  $apply->_health_is_fatal($broken), 'a broken core exits non-zero';
};

subtest '_banner pads to a consistent width' => sub {
    my $out = '';
    open my $fh, '>', \$out or die $!;
    {
        local *STDOUT = $fh;
        $apply->_banner('CONTROL PLANE DEPLOYED SUCCESSFULLY!');
    }
    # The box-drawing characters are multi-byte, so width has to be measured in
    # characters — the source emits them as UTF-8 bytes, like the rest of OCP.
    my @lines = map { Encode::decode_utf8($_) }
                grep { /\S/ } split /\n/, $out;
    is scalar @lines, 3, 'top, text, bottom';
    is length($lines[0]), length($lines[1]), 'text line matches the border width';
    is length($lines[1]), length($lines[2]), 'bottom border matches too';
};

subtest 'distribution label follows the configured distribution' => sub {
    # apply announced "Installing RKE2 server..." while install_k3s_server ran.
    is OCP::Cmd::Apply::_dist_label('k3s'),  'K3s',  'k3s is named k3s';
    is OCP::Cmd::Apply::_dist_label('rke2'), 'RKE2', 'rke2 is named rke2';
    is OCP::Cmd::Apply::_dist_label(undef),  '',     'no distribution, no claim';
};

done_testing;
