#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use POSIX qw(strftime);

use lib 'lib';

use OCP::Cmd::Apply::Health;

# k197, runtime half: the robocop image is amd64 only. Health reads the
# control-plane nodes and (a) warns when robocop is on and none is amd64,
# (b) names that as the reason of an unschedulable robocop pod instead of the
# bare Pending one. With an amd64 control plane the old reason stays.
#
# Interface under test:
#   OCP::Cmd::Apply::Health::robocop_arch_warning($self, $api) -> '[WARN] ...' | undef
#   OCP::Cmd::Apply::Health::classify_pod($self, $pod, $no_amd64_cp) -- optional
#       third arg true: no amd64 control plane known
#   scan_pods($self, $api) lists Node itself and passes that flag to classify_pod.

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
package FakeK8s  { sub new { bless {}, shift } sub object_to_struct { $_[1] } }
package FakeApi  {
    sub new { my ($c, %a) = @_; bless { %a, calls => [] }, $c }
    sub k8s { FakeK8s->new }
    sub list {
        my ($s, $kind, @rest) = @_;
        push @{ $s->{calls} }, [ $kind, @rest ];
        return FakeList->new($s->{ $kind eq 'Node' ? 'nodes' : 'pods' } // []);
    }
}
package FakeConfig { sub new { bless { on => $_[1] }, $_[0] } sub robocop_enabled { $_[0]{on} } }
package FakeApply  { sub new { bless { config => FakeConfig->new($_[1]) }, $_[0] } sub config { $_[0]{config} } }
package main;

sub node {
    my ($name, $arch, $cp) = @_;
    return { metadata => { name => $name, labels => {
        'kubernetes.io/arch' => $arch,
        ($cp ? ('node-role.kubernetes.io/control-plane' => 'true') : ()),
    } } };
}

sub created_ago { strftime('%Y-%m-%dT%H:%M:%SZ', gmtime(time - $_[0])) }

sub robocop_pod {
    return {
        metadata => { namespace => 'ocp-system', name => 'robocop-7d9f-abcde',
                      labels => { app => 'robocop' },
                      creationTimestamp => created_ago(16 * 60) },
        status => { phase => 'Pending', conditions => [
            { type => 'PodScheduled', status => 'False', reason => 'Unschedulable' } ] },
    };
}

my $ARM_ONLY = [ node('police1', 'arm64', 1), node('w1', 'amd64', 0) ];
my $WITH_AMD = [ node('police1', 'arm64', 1), node('police2', 'amd64', 1) ];
my $REASON   = 'robocop-Image nur amd64, keine amd64-Control-Plane';

subtest 'warning: robocop on, only arm64 control planes' => sub {
    my $api = FakeApi->new(nodes => $ARM_ONLY);
    my $w = OCP::Cmd::Apply::Health::robocop_arch_warning(FakeApply->new(1), $api);
    like $w, qr/^\[WARN\]/, 'a [WARN] line';
    like $w, qr/amd64/, 'names amd64';
    ok scalar(grep { $_->[0] eq 'Node' } @{ $api->{calls} }), 'read the Nodes through the api';
};

subtest 'no warning' => sub {
    is OCP::Cmd::Apply::Health::robocop_arch_warning(FakeApply->new(1), FakeApi->new(nodes => $WITH_AMD)),
        undef, 'an amd64 control plane exists';
    is OCP::Cmd::Apply::Health::robocop_arch_warning(FakeApply->new(0), FakeApi->new(nodes => $ARM_ONLY)),
        undef, 'robocop off';
};

subtest 'classify_pod: unschedulable robocop pod names the arch' => sub {
    my ($state, $reason) = OCP::Cmd::Apply::Health::classify_pod(undef, robocop_pod(), 1);
    is $state, 'failing', 'failing';
    like $reason, qr/\Q$REASON\E/, 'the arch reason';
};

subtest 'classify_pod: without the flag the old reason stays' => sub {
    is_deeply [ OCP::Cmd::Apply::Health::classify_pod(undef, robocop_pod()) ],
        [ 'failing', 'stuck in Pending for 16m (Unschedulable)' ], 'old reason';
};

subtest 'classify_pod: a different pod keeps its reason even with the flag' => sub {
    my $pod = robocop_pod();
    $pod->{metadata} = { namespace => 'default', name => 'other', labels => { app => 'other' },
                         creationTimestamp => created_ago(16 * 60) };
    is( (OCP::Cmd::Apply::Health::classify_pod(undef, $pod, 1))[1],
        'stuck in Pending for 16m (Unschedulable)', 'unchanged' );
};

subtest 'scan_pods: nodes decide' => sub {
    my $scan = OCP::Cmd::Apply::Health::scan_pods(FakeApply->new(1),
        FakeApi->new(nodes => $ARM_ONLY, pods => [ robocop_pod() ]));
    is scalar @{ $scan->{failing} }, 1, 'one failing';
    like $scan->{failing}[0]{reason}, qr/\Q$REASON\E/, 'arch reason without amd64 CP';

    $scan = OCP::Cmd::Apply::Health::scan_pods(FakeApply->new(1),
        FakeApi->new(nodes => $WITH_AMD, pods => [ robocop_pod() ]));
    is $scan->{failing}[0]{reason}, 'stuck in Pending for 16m (Unschedulable)',
        'old reason with an amd64 CP';
};

done_testing;
