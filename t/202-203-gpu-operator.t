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

done_testing;
