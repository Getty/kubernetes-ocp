#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use POSIX qw(strftime);

use lib 'lib';

use OCP::Cmd::Apply::Health;

# k202: a young pod that has crashed a few times is still starting up.
sub pod {
    my ($age, $restarts) = @_;
    return {
        metadata => { creationTimestamp => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime(time - $age)) },
        status   => {
            phase => 'Running',
            containerStatuses => [{
                ready => 0, restartCount => $restarts,
                state => { waiting => { reason => 'CrashLoopBackOff' } },
            }],
        },
    };
}

my $self = bless {}, 'OCP::Cmd::Apply';
is( (OCP::Cmd::Apply::Health::classify_pod($self, pod(60, 4)))[0], 'starting',
    '4 restarts within a minute: still starting' );
is( (OCP::Cmd::Apply::Health::classify_pod($self, pod(60, 6)))[0], 'failing',
    'too many restarts: failing' );
is( (OCP::Cmd::Apply::Health::classify_pod($self, pod(3600, 4)))[0], 'failing',
    'an hour old and still crash-looping: failing' );

# k202, lab 2026-10-16: a crash-looping container is only *waiting* in
# CrashLoopBackOff between crashes; in between it is briefly running or
# terminated. A scan that hits that window must still call it failing, or
# the verdict depends on timing (lab-202/crash-old: 6 restarts, 5m47s,
# reported "still starting").
sub pod_state {
    my ($age, $restarts, $state, %c) = @_;
    my $p = pod($age, $restarts);
    my $cs = $p->{status}{containerStatuses}[0];
    $cs->{state} = $state;
    $cs->{lastState} = { terminated => { reason => 'Error', exitCode => 1 } };
    $cs->{ready} = $c{ready} // 0;
    return $p;
}

is_deeply [ OCP::Cmd::Apply::Health::classify_pod($self,
        pod_state(347, 6, { running => {} })) ],
    [ 'failing', 'CrashLoopBackOff' ],
    'durable crash loop caught running between crashes: failing';
is_deeply [ OCP::Cmd::Apply::Health::classify_pod($self,
        pod_state(347, 6, { terminated => { reason => 'Error', exitCode => 1 } })) ],
    [ 'failing', 'CrashLoopBackOff' ],
    'durable crash loop caught terminated (Error) in phase Running: failing';
is( (OCP::Cmd::Apply::Health::classify_pod($self,
        pod_state(120, 4, { running => {} })))[0], 'starting',
    'young crash-looper caught running: still starting' );
is( (OCP::Cmd::Apply::Health::classify_pod($self,
        pod_state(600, 6, { running => {} }, ready => 1)))[0], 'healthy',
    'Ready after restarts (dcgm-exporter settled): healthy' );

done_testing;
