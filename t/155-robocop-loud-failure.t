#!/usr/bin/env perl
# karr k170 -- a robocop whose watch cannot reach the API must say so and die.
#
# In the field robocop ran with no log output at all and never touched an
# OCPNode. Two things hid that:
#
#   * Net::Async::Kubernetes::Watcher (0.008 then) answered a failed watch
#     request by retrying it a second later, forever, without calling any
#     callback. With IO::Async::SSL missing every request failed that way.
#     Since 0.009 it backs off up to 30s and reports every failed attempt to
#     on_error, which robocop logs (k247).
#   * print to a piped STDOUT is block-buffered, so even the startup lines
#     never reached the pod log.
#
# This file pins the answer: a startup banner, an API check over the watch
# client before the watch starts and repeated while it runs, failures on
# STDERR, and a run() that dies -- which bin/robocop turns into exit 1.
use strict;
use warnings;
use Test::More;

use File::Temp ();
use Future;
use IO::Async::Loop;
use Path::Tiny ();

use OCP;
use OCP::Robocop::Controller;

# The async client as run() uses it: a Notifier (run adds it to the loop),
# list() for the API check, watcher() for the watch. list answers from a
# script, one entry per call, the last one repeating.
package FakeAsyncKube {
    use parent 'IO::Async::Notifier';

    sub script   { $_[0]{script} }
    sub lists    { $_[0]{lists} // 0 }
    sub watchers { $_[0]{watchers} // 0 }

    sub set_script { $_[0]{script} = $_[1] }

    sub list {
        my ($self) = @_;
        my $n = $self->{lists}++;
        my @s = @{ $self->script };
        my $answer = $n < @s ? $s[$n] : $s[-1];
        my $f = $self->loop->new_future;
        return defined $answer ? $f->fail($answer) : $f->done([]);
    }

    # Keeps the arguments run() hands the watcher; a test's on_watch gets them
    # once the loop runs.
    sub watcher {
        my ($self, $kind, %args) = @_;
        $self->{watchers}++;
        $self->{watcher_args} = \%args;
        my $w = IO::Async::Notifier->new;
        $self->add_child($w);
        if (my $cb = $self->{on_watch}) {
            $self->loop->later(sub { $cb->(%args) });
        }
        return $w;
    }
}

# The sync client: run() builds it once, the resync pass lists with it.
package FakeKube {
    sub new  { bless {}, shift }
    sub list { bless { items => [] }, 'FakeList' }
    sub k8s  { $_[0] }
    sub object_to_struct { $_[1] }
}
package FakeList { sub items { $_[0]{items} } }

package main;

sub controller {
    my (%over) = @_;
    my $async = FakeAsyncKube->new;
    $async->set_script(delete $over{script});
    return OCP::Robocop::Controller->new(
        ssh_key     => "PRIVATE-KEY\n",
        server_url  => 'https://police1:9345',
        join_token  => 'JOIN-TOKEN',
        distribution => 'rke2',
        pod_cidr    => '10.42.0.0/16',
        namespace   => 'ocp-test',
        loop        => IO::Async::Loop->new,
        kube        => FakeKube->new,
        async_kube  => $async,
        %over,
    );
}

# run() with STDOUT and STDERR captured; returns what it died with.
sub run_captured {
    my ($c) = @_;
    my ($out, $err) = ('', '');
    open my $out_fh, '>', \$out or die $!;
    open my $err_fh, '>', \$err or die $!;
    my $died;
    {
        local *STDOUT = $out_fh;
        local *STDERR = $err_fh;
        local $SIG{ALRM} = sub { die "run() did not return\n" };
        alarm 20;
        $died = eval { $c->run; 1 } ? undef : $@;
        alarm 0;
    }
    return { died => $died, stdout => $out, stderr => $err,
             autoflush => $out_fh->autoflush(0) };
}

subtest 'a failing API check at startup: banner, reason on STDERR, run dies' => sub {
    my $c = controller(script => ["Can't locate IO/Async/SSL.pm in \@INC\n"]);
    my $r = run_captured($c);

    my ($first) = split /\n/, $r->{stdout};
    like($first, qr/robocop \Q$OCP::VERSION\E starting: security_level=secret namespace=ocp-test/,
        'the first log line names version, security_level and namespace');
    ok($r->{autoflush}, 'STDOUT is unbuffered, so the pod log gets it at once');

    like($r->{died}, qr/not reachable over the watch client: Can't locate IO\/Async\/SSL\.pm/,
        'run() dies with the reason');
    unlike($r->{died}, qr/did not return/, 'instead of retrying silently');
    like($r->{stderr}, qr/FATAL: .*IO\/Async\/SSL\.pm/, 'the reason is on STDERR');
    unlike($r->{stdout}, qr/FATAL/, 'and not on STDOUT');
    is($c->async_kube->watchers, 0, 'no watch is started');
};

subtest 'a startup check that hangs is a failure too' => sub {
    my $c = controller(script => [undef], api_check_timeout => 0.2);
    no warnings 'redefine';
    local *FakeAsyncKube::list = sub { $_[0]->loop->new_future };   # never answers
    my $r = run_captured($c);
    like($r->{died}, qr/no answer within 0\.2s/, 'run() dies naming the timeout');
};

subtest 'API checks failing in a row while running end the process' => sub {
    my $c = controller(
        script                 => [undef, 'connection refused', 'connection refused'],
        resync_interval        => 0.05,
        max_api_check_failures => 2,
    );
    my $r = run_captured($c);

    is($c->async_kube->watchers, 1, 'the watch had started');
    like($r->{stderr}, qr{API check over the watch client failed \(1/2\): connection refused},
        'every failed check is logged to STDERR');
    like($r->{died}, qr/not reachable over the watch client \(2 checks in a row\): connection refused/,
        'the second failure in a row makes run() die');
};

subtest 'a successful check resets the count' => sub {
    my $c = controller(
        script                 => [undef, 'blip', undef, 'down', 'down'],
        resync_interval        => 0.05,
        max_api_check_failures => 2,
    );
    my $r = run_captured($c);

    like($r->{stderr}, qr{\(1/2\): blip}, 'the single failure was logged');
    like($r->{died}, qr/\(2 checks in a row\): down/,
        'only two failures in a row end it, not two in total');
    is($c->async_kube->lists, 5, 'after exactly that many checks');
};

# k247: what Net::Async::Kubernetes::Watcher (0.012 in cpanfile.snapshot) hands
# on_error -- the Status it builds for a failed watch attempt, and the API
# server's raw Status for an ERROR event on the stream. The fake reports both
# the way the watcher does: to on_error, or as a warning without one.
subtest 'a failing watch reaches the log on its own' => sub {
    my $c = controller(script => [undef]);
    my @reports = (
        {
            kind       => 'Status',
            apiVersion => 'v1',
            status     => 'Failure',
            reason     => 'WatchFailed',
            code       => 0,
            message    => 'watch OCPNode failed, retrying in 3.2s: Connection refused',
            details    => { kind => 'OCPNode', retryAfterSeconds => 3.2 },
        },
        {
            kind       => 'Status',
            apiVersion => 'v1',
            status     => 'Failure',
            reason     => 'Forbidden',
            code       => 403,
            message    => 'ocpnodes.ocp.internal is forbidden: cannot watch',
        },
    );
    $c->async_kube->{on_watch} = sub {
        my (%args) = @_;
        for my $status (@reports) {
            if (my $cb = $args{on_error}) { $cb->($status) }
            else                          { warn $status->{message} . "\n" }
        }
        $c->shutdown('TERM');
    };
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    my $r = run_captured($c);

    is($r->{died}, undef, 'a failed watch attempt does not end run()');
    ok(!exists $c->async_kube->{watcher_args}{max_retries},
        'the watch has no max_retries, so it retries for as long as robocop runs');
    like($r->{stderr},
        qr/^\[[^\]]+\] watch ERROR: watch OCPNode failed, retrying in 3\.2s: Connection refused$/m,
        'a failed watch attempt is a timestamped line on STDERR');
    like($r->{stderr}, qr/^\[[^\]]+\] watch ERROR: ocpnodes\.ocp\.internal is forbidden: cannot watch$/m,
        'so is an ERROR event on the stream');
    unlike($r->{stdout}, qr/watch ERROR/, 'and neither is on STDOUT');
    is_deeply(\@warnings, [], 'nothing is left to a bare warning');
};

# bin/robocop turns the dying run() into exit 1. No kubeconfig, no service
# account: the watch client has no server, and the check fails before any
# connection is attempted.
subtest 'bin/robocop controller exits 1 with the reason on STDERR' => sub {
    my $home = File::Temp->newdir;
    my $out  = File::Temp->new;
    my $err  = File::Temp->new;

    my $pid = fork // die "fork: $!";
    if ($pid == 0) {
        delete @ENV{qw( KUBECONFIG KUBERNETES_SERVICE_HOST KUBERNETES_SERVICE_PORT
                        ROBOCOP_SECURITY_LEVEL NAMESPACE )};
        $ENV{HOME}            = $home->dirname;
        $ENV{ROBO_SSH_KEY}    = "PRIVATE-KEY\n";
        $ENV{RKE2_SERVER_URL} = 'https://police1:9345';
        $ENV{RKE2_TOKEN}      = 'JOIN-TOKEN';
        $ENV{OCP_DISTRIBUTION} = 'rke2';
        $ENV{OCP_POD_CIDR}     = '10.42.0.0/16';
        open STDOUT, '>', $out->filename or die $!;
        open STDERR, '>', $err->filename or die $!;
        exec $^X, '-Ilib', 'bin/robocop', 'controller';
        exit 127;
    }
    local $SIG{ALRM} = sub { kill 'KILL', $pid };
    alarm 60;
    waitpid $pid, 0;
    alarm 0;

    my $stdout = Path::Tiny::path($out->filename)->slurp;
    my $stderr = Path::Tiny::path($err->filename)->slurp;
    is($? >> 8, 1, 'exit status 1') or diag("stdout: $stdout\nstderr: $stderr");
    like($stdout, qr/robocop \S+ starting: security_level=secret namespace=ocp-system/,
        'the banner reached the log');
    like($stderr, qr/^robocop: fatal: robocop controller: the Kubernetes API is not reachable/m,
        'the reason is on STDERR');
};

done_testing;
