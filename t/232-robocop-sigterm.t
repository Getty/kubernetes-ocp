#!/usr/bin/env perl
# karr k232 -- robocop's identity in the OCPNode leases, and what SIGTERM does.
#
# Lab 2026-10-16 (notes 20, 21): every robocop pod leased as 'robocop', so a
# successor took its predecessor's lease for its own; and robocop, PID 1 with
# no signal handler, ignored the kubelet's SIGTERM and ran out the whole grace
# period while an install went on in the dying pod.
#
# No cluster: the scheduler against a recording _spawn, the signal against the
# real loop and a real kill.

use strict;
use warnings;
use Test::More;
use Future;
use IO::Async::Loop;
use IO::Async::Timer::Countdown;

use lib 'lib';

use OCP::Robocop::Controller;

sub ocpnode {
    my ($name, $phase) = @_;
    return { apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
        metadata => { name => $name, namespace => 'ocp-system', resourceVersion => '1' },
        spec => { role => 'worker', providerRef => 'p' }, status => { phase => $phase } };
}

sub ctrl {
    return OCP::Robocop::Controller->new(ssh_key => 'K', server_url => 'U', join_token => 'T',
        distribution => 'rke2', pod_cidr => '10.42.0.0/16', @_);
}

sub recording_spawn {
    my ($log) = @_;
    return sub { my ($self, $cr) = @_; my $f = Future->new;
        push @$log, { name => $cr->{metadata}{name}, f => $f }; $f };
}

subtest 'the reconciler id is robocop@<pod>' => sub {
    local $ENV{POD_NAME} = 'robocop-7d9f-abcde';
    is ctrl()->reconciler_id, 'robocop@robocop-7d9f-abcde', 'from POD_NAME (Downward API)';

    local $ENV{POD_NAME};
    require Sys::Hostname;
    is ctrl()->reconciler_id, 'robocop@' . Sys::Hostname::hostname(), 'hostname without it';

    local $ENV{POD_NAME} = '';
    is ctrl()->reconciler_id, 'robocop@' . Sys::Hostname::hostname(), 'and when it is empty';
};

subtest 'the shipped Deployment hands the pod name in and sets the grace period' => sub {
    require YAML::PP;
    my $d = YAML::PP->new->load_file('share/robocop/deployment.yaml');
    my ($env) = grep { $_->{name} eq 'POD_NAME' } @{ $d->{spec}{template}{spec}{containers}[0]{env} };
    is $env->{valueFrom}{fieldRef}{fieldPath}, 'metadata.name', 'POD_NAME via the Downward API';
    cmp_ok $d->{spec}{template}{spec}{terminationGracePeriodSeconds}, '>=', 600,
        'terminationGracePeriodSeconds covers an install, not the 30 s default';
};

subtest 'shutdown: running reconciles finish, nothing new starts, then the loop stops' => sub {
    my @spawned; my @log;
    no warnings 'redefine';
    local *OCP::Robocop::Controller::_spawn = recording_spawn(\@spawned);
    local *OCP::Robocop::Controller::log    = sub { push @log, $_[1] };

    my $c = ctrl(max_reconciles => 1);
    my $stopped = 0;
    local *IO::Async::Loop::stop = sub { $stopped++ };

    $c->enqueue(ocpnode($_, 'Pending')) for qw(w1 w2);
    is scalar @spawned, 1, 'w1 runs, w2 waits';

    $c->shutdown('TERM');
    ok $c->stopping, 'stopping';
    is $stopped, 0, 'the loop keeps going while w1 runs';
    like "@log", qr/SIGTERM.*waiting for 1 running/, 'logged';

    $c->enqueue(ocpnode('w3', 'Pending'));
    is scalar @spawned, 1, 'a new event starts nothing';

    $spawned[0]{f}->done(0);
    is scalar @spawned, 1, 'neither does the freed slot start w2';
    is $stopped, 1, 'the last reconcile ended: the loop stops';

    $c->shutdown('TERM');
    is scalar(grep { /SIGTERM/ } @log), 1, 'a second signal changes nothing';
};

subtest 'shutdown with nothing running stops at once' => sub {
    my $c = ctrl();
    my $stopped = 0;
    no warnings 'redefine';
    local *IO::Async::Loop::stop = sub { $stopped++ };
    local *OCP::Robocop::Controller::log = sub { };
    $c->shutdown('TERM');
    is $stopped, 1, 'idle robocop exits right away';
};

subtest 'a real SIGTERM reaches shutdown through the loop' => sub {
    my $loop = IO::Async::Loop->new;
    my $c = ctrl(loop => $loop);
    my @log;
    no warnings 'redefine';
    local *OCP::Robocop::Controller::log = sub { push @log, $_[1] };

    $c->_watch_signals;
    my $guard = IO::Async::Timer::Countdown->new(delay => 10, on_expire => sub { $loop->stop });
    $loop->add($guard); $guard->start;
    $loop->later(sub { kill TERM => $$ });
    $loop->run;

    ok $c->stopping, 'SIGTERM was handled instead of ignored';
    like "@log", qr/SIGTERM/, 'and logged';
    $loop->remove($guard);
};

done_testing;
