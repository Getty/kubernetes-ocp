#!/usr/bin/env perl
# karr k159 -- robocop's reconcile must not block its loop, and nodes that got
# no event must still be picked up again.
#
# Before k159 the watch callback ran OCP::Node's reconcile inline, on the one
# IO::Async loop robocop has. An install is Rex over SSH and takes minutes;
# for that long no other watch event was handled and the inject listener
# (k2, 127.0.0.1:9999) did not answer, so `ocp inject-key` could run into its
# 30s timeout. And with only events as a trigger, a node whose problem sits
# outside the cluster -- or a Joining node waiting for its kubelet -- was never
# looked at again until something wrote to its CR (ADR 0029, Consequences).
#
# This file pins the fix:
#   - each reconcile runs in a forked child, the loop keeps answering;
#   - never two reconciles of the same OCPNode at once, events that arrive
#     meanwhile collapse into one rerun;
#   - a global limit on concurrent reconciles;
#   - the child re-reads the CR before it reconciles (never a stale event copy);
#   - a periodic resync re-enqueues the nodes still on their way to Ready.
#
# No cluster. The scheduler is tested against a recording _spawn; the process
# boundary and the listener against a real fork and a real loopback socket.

use strict;
use warnings;
use Test::More;
use Future;
use IO::Async::Loop;
use IO::Async::Stream;
use Path::Tiny ();
use Time::HiRes ();

use lib 'lib';

use OCP::Robocop::Controller;
use OCP::Robocop::KeyInjection;

# TEST FIXTURES ONLY -- the same throwaway pair t/87 uses, trusted nowhere.
my $ROBO_PRIV = <<'KEY';
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCjx1LAEqprX25BhoqMOTYatLiWTFUp5yZ3QeRVFERELAAAAJBghgLhYIYC
4QAAAAtzc2gtZWQyNTUxOQAAACCjx1LAEqprX25BhoqMOTYatLiWTFUp5yZ3QeRVFERELA
AAAEB4j2YTstm3JkTHirZKgotr5qZlJtYh9RdFBD1clvK63qPHUsASqmtfbkGGiow5Nhq0
uJZMVSnnJndB5FUUREQsAAAADGZpeHR1cmUtcm9ibwE=
-----END OPENSSH PRIVATE KEY-----
KEY
my $ROBO_PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKPHUsASqmtfbkGGiow5Nhq0uJZMVSnnJndB5FUUREQs fixture-robo';
my $ROBO_FP  = 'SHA256:nqNyKkWIC8O8E3VIvmGZ4SqG0Pq9iXqcUpZCIVpLsSk';

sub ocpnode {
    my ($name, $phase) = @_;
    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => $name, namespace => 'ocp-system', resourceVersion => '1' },
        spec       => { role => 'worker', providerRef => 'p' },
        status     => { defined $phase ? (phase => $phase) : () },
    };
}

sub ctrl {
    my (%over) = @_;
    return OCP::Robocop::Controller->new(
        ssh_key    => 'K',
        server_url => 'U',
        join_token => 'T',
        %over,
    );
}

# A _spawn that records instead of forking and hands back a Future the test
# resolves when it decides the "child" is done.
sub recording_spawn {
    my ($log) = @_;
    return sub {
        my ($self, $cr) = @_;
        my $f = Future->new;
        push @$log, { name => $cr->{metadata}{name}, cr => $cr, f => $f };
        return $f;
    };
}

sub names { [ map { $_->{name} } @{ $_[0] } ] }

# ---------------------------------------------------------------------------
# Scheduler: per-node serialization, coalescing, the global limit
# ---------------------------------------------------------------------------

subtest 'never two reconciles of the same OCPNode; events meanwhile collapse into one rerun' => sub {
    my @spawned;
    no warnings 'redefine';
    local *OCP::Robocop::Controller::_spawn = recording_spawn(\@spawned);

    my $c = ctrl(max_reconciles => 4);
    $c->enqueue(ocpnode('w1', 'Pending'));
    is_deeply names(\@spawned), ['w1'], 'the first event starts a reconcile';
    ok $c->reconciling(ocpnode('w1')), 'w1 is reconciling';

    $c->enqueue(ocpnode('w1', 'Pending'));
    $c->enqueue(ocpnode('w1', 'Installing'));
    is scalar @spawned, 1, 'further events for w1 do not start a second reconcile';

    $spawned[0]{f}->done(0);
    is_deeply names(\@spawned), ['w1', 'w1'],
        'when it finishes, exactly one rerun picks up what arrived meanwhile';
    is $spawned[1]{cr}{status}{phase}, 'Installing', 'with the latest copy';

    $spawned[1]{f}->done(0);
    is scalar @spawned, 2, 'nothing left: no further rerun';
    ok !$c->reconciling(ocpnode('w1')), 'and w1 is idle';
};

subtest 'a global limit on concurrent reconciles' => sub {
    my @spawned;
    no warnings 'redefine';
    local *OCP::Robocop::Controller::_spawn = recording_spawn(\@spawned);

    my $c = ctrl(max_reconciles => 2);
    $c->enqueue(ocpnode($_, 'Pending')) for qw(w1 w2 w3);
    is_deeply names(\@spawned), [qw(w1 w2)], 'only two run at once';

    $spawned[0]{f}->done(0);
    is_deeply names(\@spawned), [qw(w1 w2 w3)], 'a freed slot goes to the next in line';
};

subtest 'a failed child frees its slot and is logged' => sub {
    my @spawned;
    my @log;
    no warnings 'redefine';
    local *OCP::Robocop::Controller::_spawn = recording_spawn(\@spawned);
    local *OCP::Robocop::Controller::log    = sub { push @log, $_[1] };

    my $c = ctrl(max_reconciles => 1);
    $c->enqueue(ocpnode($_, 'Pending')) for qw(w1 w2);
    $spawned[0]{f}->done(255 << 8);

    is_deeply names(\@spawned), [qw(w1 w2)], 'the next node still gets its turn';
    ok scalar(grep { /w1/ && /255/ } @log), 'the abnormal exit is logged with its code';
};

# ---------------------------------------------------------------------------
# The child re-reads the CR before it reconciles
# ---------------------------------------------------------------------------

package FakeKube {
    sub new { my ($c, %a) = @_; bless { gets => [], %a }, $c }
    sub get {
        my ($self, $kind, %a) = @_;
        push @{ $self->{gets} }, "$kind/$a{name}";
        return $self->{on_get}->(%a);
    }
    sub k8s { bless {}, 'FakeIOK8s' }
    sub list {
        my ($self) = @_;
        return bless { items => $self->{items} }, 'FakeList';
    }
}
package FakeIOK8s { sub object_to_struct { $_[1] } }
package FakeList  { sub items { $_[0]{items} } }

package main;

subtest 'the child reconciles the CR as stored now, not the event copy' => sub {
    my $stored = ocpnode('w1', 'Joining');
    my $kube = FakeKube->new(on_get => sub { $stored });
    my @seen;
    no warnings 'redefine';
    local *OCP::Robocop::Controller::_reconcile_cr = sub { push @seen, $_[1] };

    ctrl(kube => $kube)->_reconcile_child(ocpnode('w1', 'Pending'));

    is_deeply $kube->{gets}, ['OCPNode/w1'], 'the CR is read fresh';
    is $seen[0]{status}{phase}, 'Joining',
        'and that copy is reconciled -- a stale Pending would provision twice';
};

subtest 'a CR deleted in the meantime is not reconciled' => sub {
    my $kube = FakeKube->new(on_get => sub { die "404 ocpnodes \"w1\" not found\n" });
    my @seen;
    no warnings 'redefine';
    local *OCP::Robocop::Controller::_reconcile_cr = sub { push @seen, $_[1] };
    local *OCP::Robocop::Controller::log           = sub { };

    ctrl(kube => $kube)->_reconcile_child(ocpnode('w1', 'Pending'));
    is scalar @seen, 0, 'nothing to reconcile';
};

# ---------------------------------------------------------------------------
# Periodic resync
# ---------------------------------------------------------------------------

subtest 'resync re-enqueues the nodes still on their way, and only those' => sub {
    my @spawned;
    no warnings 'redefine';
    local *OCP::Robocop::Controller::_spawn = recording_spawn(\@spawned);

    my $kube = FakeKube->new(items => [
        ocpnode('pending',    'Pending'),
        ocpnode('fresh'),                    # no phase yet = Pending
        ocpnode('installing', 'Installing'),
        ocpnode('joining',    'Joining'),
        ocpnode('ready',      'Ready'),
        ocpnode('failed',     'Failed'),
        ocpnode('terminating', 'Terminating'),
    ]);
    my $c = ctrl(kube => $kube, max_reconciles => 10);

    # 'installing' is already running when the resync comes round.
    $c->enqueue(ocpnode('installing', 'Installing'));
    @spawned = grep { $_->{name} ne 'installing' } @spawned;

    $c->_resync;

    is_deeply [ sort @{ names(\@spawned) } ], [qw(fresh joining pending)],
        'Pending and Joining are picked up; Ready, Failed and Terminating are not';
    ok !exists $c->_pending->{'ocp-system/installing'},
        'a node already reconciling is left alone, not queued for a rerun';
};

subtest 'the resync timer fires on the loop and picks up a stuck Pending node' => sub {
    my @spawned;
    no warnings 'redefine';
    local *OCP::Robocop::Controller::_spawn = recording_spawn(\@spawned);

    my $loop = IO::Async::Loop->new;
    my $kube = FakeKube->new(items => [ ocpnode('stuck', 'Pending') ]);
    my $c = ctrl(kube => $kube, loop => $loop, resync_interval => 0.2);

    $c->_start_resync;
    my $deadline = time + 5;
    $loop->loop_once(0.1) while !@spawned && time < $deadline;

    is_deeply names(\@spawned), ['stuck'], 'the stuck node is reconciled without an event';
};

subtest 'from_env: resync interval and concurrency limit, with defaults' => sub {
    local %ENV = %ENV;
    $ENV{ROBO_SSH_KEY}    = 'K';
    $ENV{RKE2_SERVER_URL} = 'U';
    $ENV{RKE2_TOKEN}      = 'T';
    delete @ENV{qw(ROBOCOP_RESYNC_INTERVAL ROBOCOP_MAX_RECONCILES ROBOCOP_SECURITY_LEVEL)};

    my $c = OCP::Robocop::Controller->from_env;
    is $c->resync_interval, 60, 'resync every 60s by default';
    is $c->max_reconciles,  2,  'two concurrent reconciles by default';

    $ENV{ROBOCOP_RESYNC_INTERVAL} = '300';
    $ENV{ROBOCOP_MAX_RECONCILES}  = '5';
    $c = OCP::Robocop::Controller->from_env;
    is $c->resync_interval, 300, 'ROBOCOP_RESYNC_INTERVAL';
    is $c->max_reconciles,  5,   'ROBOCOP_MAX_RECONCILES';

    $ENV{ROBOCOP_MAX_RECONCILES} = '0';
    my $err = do { local $@; eval { OCP::Robocop::Controller->from_env }; $@ };
    like $err, qr/ROBOCOP_MAX_RECONCILES/, 'a non-positive value is refused, naming the variable';
};

# ---------------------------------------------------------------------------
# The real thing: a forked reconcile, and the inject listener answering
# ---------------------------------------------------------------------------

subtest 'the inject listener answers while a reconcile is running' => sub {
    my $loop = IO::Async::Loop->new;
    my $dir  = Path::Tiny->tempdir;
    my $marker = $dir->child('child-done');

    my $c;
    my $srv = OCP::Robocop::KeyInjection->new(
        expected_public_key => $ROBO_PUB,
        port                => 0,
        on_key              => sub { $c->accept_key(@_) },
    );
    $c = OCP::Robocop::Controller->new(
        security_level      => 'inject',
        expected_public_key => $ROBO_PUB,
        server_url          => 'U',
        join_token          => 'T',
        loop                => $loop,
        key_injection       => $srv,
        ready_file          => $dir->child('ready')->stringify,
        kube                => FakeKube->new(items => []),
    );
    $c->_start_key_injection;
    my $port = $srv->{_listener}->read_handle->sockport;

    # The reconcile: a node install that takes a while. Inherited by the fork.
    no warnings 'redefine';
    local *OCP::Robocop::Controller::_reconcile_child = sub {
        Time::HiRes::sleep(3);
        $marker->spew('done');
    };
    local *OCP::Robocop::Controller::log = sub { };

    $c->enqueue(ocpnode('w1', 'Installing'));
    ok $c->reconciling(ocpnode('w1')), 'a reconcile is running';

    my $t0 = Time::HiRes::time;
    my $answer = '';
    my $got = $loop->new_future;
    my $stream = IO::Async::Stream->new(
        on_read => sub {
            my ($s, $buf, $eof) = @_;
            $answer .= $$buf; $$buf = '';
            $got->done if !$got->is_ready && ($answer =~ /\n/ || $eof);
            return 0;
        },
    );
    $loop->add($stream);
    my $cf = $stream->connect(host => '127.0.0.1', service => $port, socktype => 'stream')
        ->then(sub { $stream->write(OCP::Robocop::KeyInjection->encode_request($ROBO_PRIV)); Future->done });
    $loop->await(Future->wait_any($got, $loop->delay_future(after => 10)));
    my $took = Time::HiRes::time - $t0;

    is $answer, "OK $ROBO_FP\n", 'the key was accepted';
    cmp_ok $took, '<', 2, 'within well under the reconcile time';
    ok !-e $marker, 'while the reconcile was still running';
    ok $c->reconciling(ocpnode('w1')), 'and still counted as running';
    is $c->ssh_key, $ROBO_PRIV, 'the key is held by the parent';

    my $deadline = time + 15;
    $loop->loop_once(0.2) while $c->reconciling(ocpnode('w1')) && time < $deadline;
    ok !$c->reconciling(ocpnode('w1')), 'the child exit is noticed';
    ok -e $marker, 'the child ran to completion';
};

done_testing;
