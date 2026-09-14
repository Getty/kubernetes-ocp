#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use OCP::Exec qw(capture_command);
use OCP::SSH;
use OCP::Provider::Local;

#
# OCP::SSH->run, OCP::SSH->run_script and OCP::Provider::Local->run_command all
# used the same hand-rolled open3 loop, which had three defects. This file
# reproduces each against the shared helper they now route through, and against
# the Local provider end-to-end (real local exec, no network).
#
#   R1 DEADLOCK  reading stdout to EOF before stderr hangs when a child writes
#                more than a pipe buffer (~64KB) to stderr first (the uninstall
#                path can). Proven with an alarm guard: buggy code hangs, the
#                fix returns.
#   R2 TIMEOUT   a wedged child hung `ocp apply` forever; a deadline bounds it.
#   R3 SIGNAL    a signal-killed child decodes to exit 0 through `>> 8`, so the
#                old code called a killed command a success.
#

my $PERL = $^X;

#
# R1 -- concurrent drain, no deadlock
#

subtest 'R1: capture_command drains both pipes concurrently (>64KB on stderr)' => sub {
    my $deadlocked = 0;
    my $r;
    eval {
        local $SIG{ALRM} = sub { die "ALARM\n" };
        alarm 15;
        $r = capture_command(
            [ $PERL, '-e', 'print STDERR "x" x 200000; print STDOUT "done"' ]
        );
        alarm 0;
    };
    $deadlocked = 1 if $@ && $@ eq "ALARM\n";

    ok !$deadlocked, 'did not deadlock on a child that floods stderr before stdout';
  SKIP: {
        skip 'deadlocked', 3 if $deadlocked;
        is $r->{stdout}, 'done',            'stdout fully captured';
        is length($r->{stderr}), 200000,    'stderr fully captured, not truncated';
        is $r->{exit}, 0,                   'clean exit is 0';
    }
};

subtest 'R1: OCP::Provider::Local->run_command, end-to-end, does not deadlock' => sub {
    my $p = OCP::Provider::Local->new;
    my $flood = $PERL . q{ -e 'print STDERR "y" x 200000; print STDOUT "ok"'};

    my $deadlocked = 0;
    my $r;
    eval {
        local $SIG{ALRM} = sub { die "ALARM\n" };
        alarm 15;
        $r = $p->run_command('127.0.0.1', $flood);
        alarm 0;
    };
    $deadlocked = 1 if $@ && $@ eq "ALARM\n";

    ok !$deadlocked, 'local run_command does not deadlock on >64KB stderr';
  SKIP: {
        skip 'deadlocked', 2 if $deadlocked;
        is $r->{stdout}, 'ok',           'stdout captured through the provider';
        is length($r->{stderr}), 200000, 'stderr captured through the provider';
    }
};

#
# R2 -- deadline bounds a wedged child
#

subtest 'R2: a child past its deadline is killed, promptly, as a failure' => sub {
    my $start = time;
    my $r = capture_command([ $PERL, '-e', 'sleep 30' ], timeout => 1);
    my $elapsed = time - $start;

    ok $r->{timed_out},   'timed_out flag is set';
    ok $r->{exit} != 0,   'a timeout is a non-zero exit, not success';
    is $r->{exit}, $OCP::Exec::TIMEOUT_EXIT, 'timeout uses the conventional 124';
    is $r->{signal}, 0,   'a timeout reports no signal, though we TERM/KILLed it';
    ok $elapsed < 10, "returned promptly (${elapsed}s), did not wait out the 30s child";
};

subtest 'R2b: a child that closes both pipes then lingers still honours the deadline' => sub {
    # The read loop drains to EOF the moment the child closes stdout+stderr, but
    # the child is still alive and sleeping. The reap after the loop must respect
    # the same deadline instead of blocking forever on an unbounded waitpid.
    my $start = time;
    my $r = capture_command(
        [ 'sh', '-c', 'exec 1>&- 2>&-; sleep 30' ], timeout => 1
    );
    my $elapsed = time - $start;

    ok $r->{timed_out},   'timed_out flag is set even though both pipes hit EOF first';
    is $r->{exit}, $OCP::Exec::TIMEOUT_EXIT, 'timeout uses the conventional 124';
    is $r->{signal}, 0,   'no signal reported on the timeout';
    ok $elapsed < 10, "returned promptly (${elapsed}s), did not wait out the 30s child";
};

subtest 'R2: OCP::Provider::Local honours command_timeout' => sub {
    my $p = OCP::Provider::Local->new(command_timeout => 1);
    my $start = time;
    my $r = $p->run_command('127.0.0.1', $PERL . q{ -e 'sleep 30'});
    my $elapsed = time - $start;

    ok $r->{timed_out}, 'provider timed the wedged command out';
    ok $r->{exit} != 0, 'reported as a failure';
    ok $elapsed < 10, "returned promptly (${elapsed}s)";
};

#
# R3 -- a signal-killed child is a failure, not exit 0
#

subtest 'R3: signal death decodes to 128+signal, never 0 (no-shell path)' => sub {
    # Direct exec, no intervening shell -- this is the OCP::SSH->run shape,
    # where open3 execs `ssh` itself. Under the old `$? >> 8` decode this
    # returned exit 0; a killed command looked like a clean success.
    my $r = capture_command([ $PERL, '-e', 'kill 9, $$; sleep 10' ]);

    is $r->{signal}, 9,          'the terminating signal is recorded';
    is $r->{exit}, 128 + 9,      'exit is 128+signal (137), not 0';
    ok $r->{exit} != 0,          'a signal death is not reported as success';
    ok !$r->{timed_out},         'and it is not mistaken for a timeout';
};

subtest 'R3: a signal-killed command through Local is a failure' => sub {
    my $p = OCP::Provider::Local->new;
    my $r = $p->run_command('127.0.0.1', $PERL . q{ -e 'kill 9, $$; sleep 10'});
    ok $r->{exit} != 0, 'exit is non-zero for a command that died by signal';
};

#
# Wiring -- both public entry points route through the fixed helper, with the
# command they build and their configured timeout.
#

subtest 'OCP::SSH->run and run_script pass the built command and timeout to capture_command' => sub {
    my @calls;
    no warnings 'redefine';
    local *OCP::SSH::capture_command = sub {
        push @calls, [@_];
        return { stdout => '', stderr => '', exit => 0 };
    };

    my $ssh = OCP::SSH->new(host => 'h.example', command_timeout => 42);

    $ssh->run('uptime');
    my ($cmd, %opts) = @{ $calls[0] };
    is ref $cmd, 'ARRAY',              'run() hands capture_command an arrayref command';
    ok((grep { $_ eq 'ssh' } @$cmd),   'the command is the ssh invocation');
    is $cmd->[-1], 'uptime',           'with the remote command last';
    is $opts{timeout}, 42,             'and the configured command_timeout';

    $ssh->run_script("#!/bin/bash\necho hi\n");
    my (undef, %sopts) = @{ $calls[1] };
    is $sopts{stdin}, "#!/bin/bash\necho hi\n", 'run_script feeds the script on stdin';
    is $sopts{timeout}, 42,            'run_script passes the timeout too';
};

subtest 'OCP::Provider::Local->run_command routes through capture_command' => sub {
    my @calls;
    no warnings 'redefine';
    local *OCP::Provider::Local::capture_command = sub {
        push @calls, [@_];
        return { stdout => '', stderr => '', exit => 0 };
    };

    OCP::Provider::Local->new(command_timeout => 7)->run_command('127.0.0.1', 'uptime');

    my ($cmd, %opts) = @{ $calls[0] };
    is_deeply $cmd, [ 'sh', '-c', 'uptime' ], 'runs the command through sh -c';
    is $opts{timeout}, 7, 'with the provider command_timeout';
};

done_testing;
