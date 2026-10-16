#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use POSIX qw(strftime);

use lib 'lib';

use OCP::Cmd::Apply::Health;

#
# k228 point 4 (lab 2026-10-16): GPU pods on crag sat in Init with
# FailedCreatePodSandBox for over 15 minutes without a restart; apply called
# them "still starting" and reported SUCCESS. Past $STUCK_SECONDS a pod that is
# not up is failing, with what it is stuck on.
#

sub created_ago { strftime('%Y-%m-%dT%H:%M:%SZ', gmtime(time - $_[0])) }

sub classify { OCP::Cmd::Apply::Health::classify_pod(undef, $_[0]) }

sub init_pod {
    my ($age) = @_;
    return {
        metadata => { creationTimestamp => created_ago($age) },
        status   => {
            phase => 'Pending',
            initContainerStatuses => [ { ready => 0, restartCount => 0,
                state => { waiting => { reason => 'PodInitializing' } } } ],
            containerStatuses => [ { ready => 0, restartCount => 0,
                state => { waiting => { reason => 'PodInitializing' } } } ],
        },
    };
}

subtest 'a young pod in Init is still starting' => sub {
    is_deeply [ classify(init_pod(120)) ], ['starting'], '2 minutes';
    is_deeply [ classify(init_pod(899)) ], ['starting'], 'just under the limit';
};

subtest 'past the limit it is failing, with where and why' => sub {
    my ($state, $reason) = classify(init_pod(17 * 60 + 5));
    is $state, 'failing', 'failing';
    is $reason, 'stuck in Init for 17m (PodInitializing)', 'reason';
};

subtest 'ContainerCreating without any status (the sandbox never came up)' => sub {
    my $pod = { metadata => { creationTimestamp => created_ago(20 * 60) },
                status   => { phase => 'Pending' } };
    my ($state, $reason) = classify($pod);
    is $state, 'failing', 'failing';
    is $reason, 'stuck in Pending for 20m', 'no reason at hand: phase and time';
};

subtest 'unschedulable says so' => sub {
    my $pod = { metadata => { creationTimestamp => created_ago(16 * 60) },
                status   => { phase => 'Pending', conditions => [
                    { type => 'PodScheduled', status => 'False', reason => 'Unschedulable' } ] } };
    is( (classify($pod))[1], 'stuck in Pending for 16m (Unschedulable)', 'reason from PodScheduled');
};

subtest 'running but never ready' => sub {
    my $pod = { metadata => { creationTimestamp => created_ago(30 * 60) },
                status   => { phase => 'Running',
                              containerStatuses => [ { ready => 0, restartCount => 0,
                                                       state => { running => {} } } ] } };
    is_deeply [ classify($pod) ], ['failing', 'stuck not ready for 30m'], 'failing';
};

subtest 'healthy stays healthy however old' => sub {
    my $pod = { metadata => { creationTimestamp => created_ago(86400) },
                status   => { phase => 'Running',
                              containerStatuses => [ { ready => 1, restartCount => 0 } ] } };
    is_deeply [ classify($pod) ], ['healthy'], 'a day old and ready';
};

subtest 'no timestamp: starting, as before' => sub {
    my $pod = init_pod(0);
    delete $pod->{metadata}{creationTimestamp};
    is_deeply [ classify($pod) ], ['starting'], 'age unknown is not stuck';
};

done_testing;
