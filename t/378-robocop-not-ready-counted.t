#!/usr/bin/env perl
use strict;
use warnings;

# The waits below run against a clock this file moves (wait_seconds advances
# $NOW): installed before OCP::Cmd::Apply::CR is compiled, with the empty
# prototype of the builtin so `time + $timeout` still parses as a sum (t/330).
our $NOW;
BEGIN { *CORE::GLOBAL::time = sub () { defined $main::NOW ? $main::NOW : CORE::time() } }

use Test::More;
use Kubernetes::REST::APIError;
use Scalar::Util ();

use lib 'lib';

use OCP::Cmd::Apply;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Deploy;

#
# k378, left over from k367: two STDERR [WARN]s say robocop was not seen
# Ready, and neither counted for the closing banner --
#
#   wait_robocop_ready (CR.pm)   "robocop not seen ready: <why>"   (k330)
#   worker_step (Deploy.pm)      "robocop not ready after 60s -- falling back
#                                 to CLI reconcile"                 (k318)
#
# The CLI fallback brings the workers up, so the apply did its job; but
# robocop does not run, and every later worker change through it waits on
# that. One cause, so one tag in {_apply_warnings}, however many of the two
# lines a run prints: the banner reads WITH WARNINGS, the exit code stays 0
# (OCP::Cmd::Apply::Health::finish, as k367).
#
# Not counted: wait_robocop_ready's look that ends on a readable Deployment
# with no pod Ready yet. robocop_step looks once, right after the rollout
# ("[..] robocop rolled out, not ready yet"), and the inject level cannot be
# Ready in this run at all; neither prints a [WARN]. worker_step's 60 s wait
# that follows does, and counts.
#

sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my ($rv, $died);
    {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $code->() };
        $died = $@;
    }
    return { rv => $rv, out => $out, err => $err, died => $died };
}

sub refused {
    my ($code, $reason) = @_;
    return Kubernetes::REST::APIError->new(code => $code, context => 'get',
        body => qq({"kind":"Status","reason":"$reason","code":$code}));
}

# The next answer of a queue, the last one repeating.
sub next_answer { my ($q) = @_; @$q > 1 ? shift @$q : $q->[0] }

{
    package FakeStatus;
    sub readyReplicas { $_[0]{readyReplicas} }

    package FakeDeployment;
    sub new    { bless { status => { readyReplicas => $_[1] } }, $_[0] }
    sub status { bless { %{ $_[0]{status} } }, 'FakeStatus' }

    # get('Deployment', 'robocop'): the next of {answers}, a Deployment or
    # the error it dies with.
    package Api;
    sub new { my ($c, @a) = @_; bless { answers => [@a], reads => 0 }, $c }
    sub get {
        my ($s) = @_;
        $s->{reads}++;
        my $a = main::next_answer($s->{answers});
        die $a if Scalar::Util::blessed($a) && $a->isa('Kubernetes::REST::APIError');
        return $a;
    }

    package Fake::Config;
    sub new                    { bless {}, shift }
    sub name                   { 'k378' }
    sub api_url                { 'https://x:6443' }
    sub robocop_security_level { 'secret' }
}

my $CLEAN        = { critical => [], warnings => [], starting => [] };
my $WARNED       = 'CONTROL PLANE DEPLOYED — WITH WARNINGS';
my $CLEAN_BANNER = 'CONTROL PLANE DEPLOYED SUCCESSFULLY!';
my $TAG          = 'robocop not ready';

# The single exit over a clean health check: the banner text and the exit code.
sub verdict {
    my ($apply) = @_;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_check_cluster_health = sub { $CLEAN };
    local *OCP::Cmd::Apply::_stamp_ocp_version    = sub { };
    my $r = capture { $apply->_finish_apply(config => Fake::Config->new, api => undef) };
    die "finish died: $r->{died}" if $r->{died};
    my ($banner) = $r->{out} =~ /^║  (.*?) *║$/m;
    return { rc => $r->{rv}, banner => $banner // '' };
}

# Runs $site with a fresh OCP::Cmd::Apply on the fake clock, then the exit.
sub run_site {
    my ($site) = @_;
    my $apply = bless {}, 'OCP::Cmd::Apply';
    local $NOW = 1_000_000;
    no warnings 'redefine';
    local *OCP::Cmd::Apply::wait_seconds = sub { $NOW += $_[1] };
    my $r = capture { $site->($apply) };
    $r->{tags}    = [ @{ $apply->{_apply_warnings} // [] } ];
    $r->{verdict} = verdict($apply);
    return $r;
}

sub counted {
    my ($r, $what) = @_;
    is $r->{died}, '', "$what: no death";
    is_deeply $r->{tags}, [ $TAG ], "$what: one tag, '$TAG'";
    is $r->{verdict}{banner}, $WARNED, "$what: the banner reads WITH WARNINGS";
    is $r->{verdict}{rc}, 0, "$what: the exit code stays 0";
}

sub clean {
    my ($r, $what) = @_;
    is $r->{died}, '', "$what: no death";
    is_deeply $r->{tags}, [], "$what: no tag";
    is $r->{verdict}{banner}, $CLEAN_BANNER, "$what: SUCCESSFULLY";
    is $r->{verdict}{rc}, 0, "$what: exit 0";
}

# --- wait_robocop_ready (CR.pm) ------------------------------------------------

sub wait_once {
    my (@answers) = @_;
    my $api = Api->new(@answers);
    return run_site(sub { OCP::Cmd::Apply::CR::wait_robocop_ready($_[0], $api, 0) });
}

subtest 'k378 wait_robocop_ready: a wait that ends on a failed read is counted' => sub {
    my $r = wait_once(FakeDeployment->new(1));
    is $r->{rv}, 1, 'control: Ready';
    is $r->{err}, '', 'control: nothing on STDERR';
    clean($r, 'control, Ready');

    $r = wait_once(FakeDeployment->new(0));
    is $r->{rv}, 0, 'readable, no pod Ready: not ready';
    is $r->{err}, '', 'readable, no pod Ready: no [WARN] -- robocop_step says [..] for it';
    clean($r, 'readable, no pod Ready');

    $r = wait_once(refused(500, 'InternalError'));
    is $r->{rv}, 0, 'read 500: not ready';
    like $r->{err}, qr/\A  \[WARN\] robocop not seen ready: could not read Deployment ocp-system\/robocop: .*\b500\b/s,
        'read 500: the [WARN] on STDERR, as before';
    counted($r, 'read 500');
};

# --- worker_step (Deploy.pm): the fallback to the CLI ----------------------------

sub step {
    my (@answers) = @_;
    my $api = Api->new(@answers);
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_ensure_worker_ocpnodes = sub { };
    local *OCP::Cmd::Apply::_drive_workers = sub { ({ name => 'w1', phase => 'Ready' }) };
    local *OCP::Cmd::Apply::_print_worker_status = sub { };
    my $r = run_site(sub {
        [ OCP::Cmd::Apply::Deploy::worker_step($_[0], $api, Fake::Config->new, {
            robocop      => { state => 'pending' },
            ssh_key_path => '/nonexistent/k378.key',
            names        => [ 'w1' ],
        }) ];
    });
    $r->{reads} = $api->{reads};
    return $r;
}

my $FALLBACK = qr/\[WARN\] robocop not ready after 60s — falling back to CLI reconcile\n/;

subtest 'k378 worker_step: falling back to the CLI is counted' => sub {
    my $r = step(FakeDeployment->new(0), FakeDeployment->new(1));
    like $r->{out}, qr/\[ok\] robocop ready/, 'control: Ready within the wait';
    is $r->{err}, '', 'control: nothing on STDERR';
    clean($r, 'control, Ready within the wait');

    $r = step(FakeDeployment->new(0));
    ok $r->{reads} > 1, 'the wait read more than once (the clock moved)';
    like $r->{err}, $FALLBACK, 'never Ready: the fallback [WARN] on STDERR, as before';
    unlike $r->{err}, qr/not seen ready/, 'never Ready: every read answered, so no read [WARN]';
    is_deeply $r->{rv}, [ { name => 'w1', phase => 'Ready' } ], 'the CLI brought the worker up';
    counted($r, 'never Ready');
};

subtest 'k378 both [WARN]s in one run: one cause, one tag' => sub {
    my $r = step(refused(403, 'Forbidden'));
    like $r->{err}, qr/\[WARN\] robocop not seen ready: .*\b403\b/s, 'the read [WARN]';
    like $r->{err}, $FALLBACK, 'and the fallback [WARN]';
    counted($r, 'both');
};

done_testing;
