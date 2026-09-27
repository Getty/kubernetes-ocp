#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 't/lib';
use OCPTest::UninstallHost;

#
# `ocp destroy` on a pre-existing host runs the vendor uninstaller, which stops
# at its own footprint. Everything OCP layered on top stayed behind -- most
# importantly /usr/local/bin/cilium, installed by the install_cilium task.
#
# That is not cosmetic: the Rexfile keeps an existing CLI when its version
# matches what is wanted, so a stale binary from a previous cluster could
# survive a destroy and be adopted by the next bootstrap.
#
# Since k196 the uninstall line is Rex::Rancher's
# (Rex::Rancher::Uninstall::uninstall_cmd, rex-rancher k71), and what it is
# made of is held there (rex-rancher t/uninstall.t). What this file holds is
# what OCP's uninstall does -- OCP::Role::Provider::ExistingHost::delete_server
# running that line over the provider's channel -- on hosts made of stubs
# (t/lib/OCPTest/UninstallHost.pm).
#

plan skip_all => 'needs a POSIX /bin/sh' unless -x '/bin/sh';

# The warnings delete_server gives (warn, i.e. STDERR) come back fourth.
sub uninstall {
    my (%stubs) = @_;
    my $h = OCPTest::UninstallHost->new(stubs => \%stubs, real => [qw( grep sed )]);
    my @warn;
    local $SIG{__WARN__} = sub { push @warn, $_[0] };
    my $res = eval { $h->delete_server(undef, host => '10.0.0.5') };
    return ($h, $res, $@, \@warn);
}

# Every path an `rm` in the uninstall was handed, from the stub log.
sub removed {
    my ($log) = @_;
    return map { grep { m{^/} } split ' ', $_ } grep { /^rm / } split /\n/, $log;
}

subtest 'what OCP installed on top is removed too' => sub {
    my ($h) = uninstall(rm => "exit 0\n");
    my %rm = map { $_ => 1 } removed($h->log);
    ok $rm{'/usr/local/bin/cilium'},
        'the Cilium CLI -- a stale one gets adopted by the next bootstrap';
    ok $rm{'/opt/cni'},  'the CNI binaries';
    ok $rm{'/run/k3s'},  'the runtime dir both distributions share';
};

subtest 'cleanup never removes a bare system directory' => sub {
    my ($h) = uninstall(rm => "exit 0\n");
    my @rm = removed($h->log);
    ok scalar @rm, 'the uninstall removes paths' or return;
    for my $path (@rm) {
        # Anything here must be a path OCP, its distribution or Cilium created.
        # Root, /usr, /etc and friends are not removable by a cluster teardown.
        unlike $path, qr{^/(usr|etc|var|opt|run|bin|sbin|lib|home|root|sys)?/?$},
            "$path is not a bare system directory";
    }
};

subtest 'a failing uninstaller does not abort the cleanup' => sub {
    # Every external the line names -- the uninstallers and the cleanup tools --
    # fails, and no distribution binary is on the host: destroying a host where
    # the distribution was already gone must still remove the leftovers and
    # report success.
    my ($h, $res, $err) = uninstall(
        map { $_ => "exit 1\n" } qw( rke2-uninstall.sh k3s-uninstall.sh rm ip )
    );
    ok $res, 'delete_server succeeds' or diag $err;
    like $h->log, qr/^rke2-uninstall\.sh/m,
        'the uninstaller was attempted (and, per the stub, failed)';
    like $h->log, qr/^rm /m,
        'leftover paths are still removed after the uninstaller failed';
    like $h->log, qr/^ip /m,
        'the Cilium ip-rule flush still runs after the uninstaller failed';
};

subtest 'a distribution still installed afterwards fails delete_server (k175)' => sub {
    # Every step is guarded, so the chain used to exit 0 whatever happened --
    # an uninstaller that was missing or failed left rke2 running and reported
    # success. The line checks its own outcome instead, and delete_server dies.
    my ($h, $res, $err) = uninstall(
        ( map { $_ => "exit 1\n" } qw( rke2-uninstall.sh k3s-uninstall.sh rm ip ) ),
        rke2 => "exit 1\n",
    );
    ok !$res, 'rke2 still on PATH after the uninstall: delete_server dies';
    like $err, qr/^10\.0\.0\.5: /, 'naming the host';
    like $err, qr/still installed/, 'and why';
    like $err, qr/\bexit 1\b/, 'with the exit status';
};

# A k3s agent's installer names its uninstaller after the service:
# k3s-agent-uninstall.sh, and no k3s-uninstall.sh. The chain only knew the
# server name, so on a k3s worker nothing ran and the k175 check failed the
# destroy (k183). RKE2 ships rke2-uninstall.sh for both roles.
subtest 'a k3s agent is uninstalled through k3s-agent-uninstall.sh (k183)' => sub {
    plan skip_all => 'needs /bin/rm' unless -x '/bin/rm';

    my ($h, $res, $err) = uninstall(
        'k3s'                    => "exit 0\n",
        'k3s-agent-uninstall.sh' => "/bin/rm -f \"\$OCP_STUB_BIN/k3s\" \"\$0\"\nexit 0\n",
    );
    like $h->log, qr/^k3s-agent-uninstall\.sh/m, 'the agent uninstaller ran';
    ok $res, 'k3s is gone afterwards: the uninstall succeeds' or diag $err;
};

subtest 'every uninstaller present runs, a failing one does not stop the next' => sub {
    my ($h) = uninstall(
        map { $_ => "exit 1\n" }
          qw( rke2-uninstall.sh k3s-uninstall.sh k3s-agent-uninstall.sh )
    );
    like $h->log, qr/^rke2-uninstall\.sh/m,      'rke2 uninstaller attempted';
    like $h->log, qr/^k3s-uninstall\.sh/m,       'k3s uninstaller attempted';
    like $h->log, qr/^k3s-agent-uninstall\.sh/m, 'k3s agent uninstaller attempted';
};

# The line warns, with a marker, for a cleanup step the host has no tool for:
# no tc (Rocky/RHEL without iproute-tc), no iptables backend with both -save
# and -restore. That part of Cilium's datapath went unchecked; a reboot clears
# it. Not a failure (rex-rancher k79): OCP says it on STDERR and goes on.
subtest 'a cleanup step the host has no tool for is a warning on STDERR, not a failure' => sub {
    # The stub PATH has neither tc nor any iptables-save/-restore.
    my ($h, $res, $err, $warn) = uninstall(rm => "exit 0\n");
    ok $res, 'delete_server succeeds' or diag $err;
    ok((grep { /^10\.0\.0\.5: tc is not installed: .*a reboot clears them$/ } @$warn),
        'the missing tc, with the host in front') or diag explain $warn;
    ok((grep { /^10\.0\.0\.5: no iptables backend with both -save and -restore/ } @$warn),
        'the missing iptables backend');
    ok !(grep { /rex-rancher-uninstall-warning/ } @$warn), 'said without the library\'s marker';

    ($h, $res, $err, $warn) = uninstall(
        ( map { $_ => "exit 1\n" } qw( rke2-uninstall.sh k3s-uninstall.sh rm ip ) ),
        rke2 => "exit 1\n",
    );
    ok !$res, 'a failed uninstall still dies';
    like $err, qr/still installed/, 'for its reason';
    unlike $err, qr/tc is not installed|uninstall-warning/, 'and the warnings are not part of it';
    ok((grep { /tc is not installed/ } @$warn), 'they went to STDERR all the same');
};

done_testing;
