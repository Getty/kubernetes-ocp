#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP::Cmd::Apply::Workloads;
use OCP::Cmd::Apply::K8s;

#
# k149: the very first `ocp apply` on a fresh cluster died with "nfd-master not
# ready within 120s". Root cause was not a broken deployment — the NFD image
# (registry.k8s.io/nfd/node-feature-discovery, 83 MB) was still being pulled
# cold through the pull-through cache. That pull was measured at ~2m31s (151s)
# on ocp-police1; the readiness gate gave it 120s. The second apply, with the
# image cached, went green in seconds.
#
# setup_nfd's readiness wait is already condition-based: poll_deployment_ready
# returns the instant the Deployment reports an available replica and only
# sleeps between polls. The bug was purely that the TOTAL budget was smaller
# than a cold external pull. The fix raises that budget
# (OCP::Cmd::Apply::Workloads::nfd_ready_timeout), which setup_nfd passes to the
# poll; a warm cluster is unaffected because the poll still returns on the
# first cycle.
#
# These tests drive the real poll (OCP::Cmd::Apply::K8s::poll_deployment_ready)
# against a virtual clock: wait_seconds advances the clock instead of sleeping,
# and the fake Deployment reports an available replica only once the clock has
# passed a chosen "image finished pulling" instant. No wall-clock time is spent.
#

# nfd-master reported ready this many virtual seconds in — past the old 120s
# gate, inside the cold-pull range that broke the first apply.
my $COLD_PULL_READY_AT = 155;
my $OLD_BUDGET         = 120;   # the gate that failed in k149

package FakeStatus {
    sub new { my ($c, $ar) = @_; bless { ar => $ar }, $c }
    sub availableReplicas { $_[0]{ar} }
}
package FakeDeployment {
    sub new { my ($c, $ar) = @_; bless { status => FakeStatus->new($ar) }, $c }
    sub status { $_[0]{status} }
}
package FakeApi {
    # Reads the shared virtual clock on every get: the deployment has an
    # available replica only once the clock has reached ready_at.
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub get {
        my ($self, $kind, $name, %opts) = @_;
        my $ready = ${ $self->{clock} } >= $self->{ready_at} ? 1 : 0;
        return FakeDeployment->new($ready);
    }
}
package FakeApply {
    # Only poll_deployment_ready's needs: a wait_seconds that advances the clock
    # rather than sleeping, and a poll counter so the happy path can be checked.
    sub new { my ($c, %a) = @_; bless { clock => $a{clock}, waits => 0 }, $c }
    sub wait_seconds {
        my ($self, $s) = @_;
        $self->{waits}++;
        ${ $self->{clock} } += $s;
        return;
    }
    sub waits { $_[0]{waits} }
}

package main;

sub poll {
    my ($budget, $ready_at) = @_;
    my $clock = 0;
    my $apply = FakeApply->new(clock => \$clock);
    my $api   = FakeApi->new(clock => \$clock, ready_at => $ready_at);
    my $ok = OCP::Cmd::Apply::K8s::poll_deployment_ready(
        $apply, $api, 'nfd-master', 'node-feature-discovery', $budget);
    return ($ok, $apply, $clock);
}

subtest 'the reported bug: the old 120s gate misses a cold pull' => sub {
    # Claim: with the budget k149 shipped, a deployment that only becomes ready
    # at 155s (a cold NFD image pull) is never seen — poll returns false, which
    # is exactly the "nfd-master not ready within 120s" that killed apply.
    my ($ok) = poll($OLD_BUDGET, $COLD_PULL_READY_AT);
    ok !$ok, 'a 155s cold pull overruns the old 120s budget — the k149 failure';
};

subtest 'the fix: the NFD budget clears a cold pull' => sub {
    # Claim: the budget setup_nfd now passes (nfd_ready_timeout) is large enough
    # that the SAME 155s cold pull is caught — poll returns true. This is the
    # regression: run against the real value the code uses, not a copy of it.
    my $budget = OCP::Cmd::Apply::Workloads::nfd_ready_timeout();
    my ($ok) = poll($budget, $COLD_PULL_READY_AT);
    ok $ok, "nfd_ready_timeout() ($budget s) tolerates a 155s cold pull";
};

subtest 'the budget clears the measured cold pull with headroom' => sub {
    # Claim: the pin is chosen against the measured ~151s worst case, not shaved
    # to just above 120. It has to stay comfortably over the observation so a
    # slower or flaky external registry (cf. k144) does not reintroduce k149.
    my $budget = OCP::Cmd::Apply::Workloads::nfd_ready_timeout();
    cmp_ok $budget, '>', 151,
        'budget clears the ~2m31s cold pull measured on ocp-police1';
    cmp_ok $budget, '>=', 180,
        'with real headroom above it, not shaved to just past the old gate';
};

subtest 'a warm cluster pays nothing for the larger ceiling' => sub {
    # Claim: raising the ceiling does not slow the common case. When the image
    # is cached the deployment is ready on the first check, so the poll returns
    # before it ever sleeps — the wider budget only bounds the cold-start wait.
    my $budget = OCP::Cmd::Apply::Workloads::nfd_ready_timeout();
    my ($ok, $apply, $clock) = poll($budget, 0);
    ok $ok, 'a ready deployment is reported ready';
    is $apply->waits, 0, 'poll returns on the first check, without a single wait';
    is $clock, 0, 'no virtual time elapsed on a warm cluster';
};

done_testing;
