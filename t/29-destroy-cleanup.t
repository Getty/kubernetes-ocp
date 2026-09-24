#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny ();

use OCP::Role::Provider::ExistingHost;

#
# `ocp destroy` on a pre-existing host runs the vendor uninstaller, which stops
# at its own footprint. Everything OCP layered on top stayed behind — most
# importantly /usr/local/bin/cilium, installed by the install_cilium task.
#
# That is not cosmetic: the Rexfile keeps an existing CLI when its version
# matches what is wanted, so a stale binary from a previous cluster could
# survive a destroy and be adopted by the next bootstrap.
#

my $cmd = $OCP::Role::Provider::ExistingHost::UNINSTALL_CMD;

subtest 'both distributions are still uninstalled' => sub {
    like $cmd, qr/rke2-uninstall\.sh/,  'rke2 uninstaller is called';
    like $cmd, qr/k3s-uninstall\.sh/,   'k3s uninstaller is called';
    like $cmd, qr/k3s-agent-uninstall\.sh/,
        'k3s agent uninstaller is called -- a k3s worker has only this one (k183)';
};

subtest 'what OCP installed on top is removed too' => sub {
    my @paths = @OCP::Role::Provider::ExistingHost::LEFTOVER_PATHS;
    ok scalar(@paths), 'leftover paths are declared';

    for my $path (@paths) {
        like $cmd, qr/\Q$path\E/, "$path is cleaned up";
    }

    like $cmd, qr{/usr/local/bin/cilium},
        'the Cilium CLI specifically — a stale one gets adopted by the next bootstrap';
};

subtest 'cleanup never touches anything outside its own footprint' => sub {
    my @paths = @OCP::Role::Provider::ExistingHost::LEFTOVER_PATHS;

    for my $path (@paths) {
        ok $path =~ m{^/}, "$path is absolute";
        unlike $path, qr/\s/, "$path has no whitespace to split on";
        unlike $path, qr/[*?]/, "$path is not a glob — no accidental wide match";

        # Anything here must be a path OCP or its distribution creates. Root,
        # /usr, /etc and friends are not removable by a cluster teardown.
        unlike $path, qr{^/(usr|etc|var|opt|run|bin|sbin|lib|home|root)?/?$},
            "$path is not a bare system directory";
    }
};

subtest 'a failing uninstaller does not abort the cleanup' => sub {
    # The command is one shell string run on the host, and the promise is that
    # no single failing step aborts the rest: destroying a host where the
    # distribution was already gone must still remove the leftovers.
    #
    # We can't check that by splitting on ';'. The ip-rule flush (k147) is a
    # for/while loop whose internal ';' are not statement boundaries, so a naive
    # split shatters it — and even a correct split only proves a syntactic
    # proxy. So assert the behaviour itself: run the command under `set -e` with
    # every external it names replaced by a stub that records its call and
    # FAILS, then prove the chain still runs to completion and the leftover
    # cleanup still happens after the uninstaller has failed.
    #
    # This is the sharp form of the invariant. Because it runs under `set -e`,
    # dropping any `|| true` guard from $UNINSTALL_CMD makes the chain abort
    # mid-way, so $status goes non-zero and this subtest fails — a real
    # regression guard, not a rubber stamp.

    plan skip_all => 'needs a POSIX /bin/sh' unless -x '/bin/sh';

    my $dir  = Path::Tiny->tempdir;
    my $stub = $dir->child('bin');
    $stub->mkpath;
    my $log  = $dir->child('log');

    # Every external the command names — the two uninstallers and the cleanup
    # tools — stubbed to log its call and exit non-zero, so the run simulates
    # "everything failed".
    for my $name (qw( rke2-uninstall.sh k3s-uninstall.sh rm ip grep )) {
        my $f = $stub->child($name);
        $f->spew_utf8("#!/bin/sh\necho $name >> \"\$OCP_STUB_LOG\"\nexit 1\n");
        $f->chmod(0755);
    }

    my $status = do {
        local $ENV{PATH}         = "$stub";   # nothing but the failing stubs
        local $ENV{OCP_STUB_LOG} = "$log";
        system('/bin/sh', '-e', '-c', $cmd);
    };

    is $status, 0,
        'the chain runs to completion under set -e though every command fails';

    my $ran = $log->exists ? $log->slurp : '';
    like $ran, qr/^rke2-uninstall\.sh$/m,
        'the uninstaller was attempted (and, per the stub, failed)';
    like $ran, qr/^rm$/m,
        'leftover paths are still removed after the uninstaller failed';
    like $ran, qr/^ip$/m,
        'the Cilium ip-rule flush still runs after the uninstaller failed';
};

subtest 'a distribution still installed afterwards fails the command (k175)' => sub {
    # Every step above is guarded, so the chain used to exit 0 whatever
    # happened -- an uninstaller that was missing or failed left rke2 running
    # and reported success. The last statement checks the outcome instead.
    plan skip_all => 'needs a POSIX /bin/sh' unless -x '/bin/sh';

    my $dir  = Path::Tiny->tempdir;
    my $stub = $dir->child('bin');
    $stub->mkpath;
    for my $name (qw( rke2-uninstall.sh k3s-uninstall.sh rm ip grep rke2 )) {
        my $f = $stub->child($name);
        $f->spew_utf8("#!/bin/sh\nexit 1\n");
        $f->chmod(0755);
    }

    my $err = $dir->child('stderr');
    my $status = do {
        local $ENV{PATH} = "$stub";
        system('/bin/sh', '-c', '{ ' . $cmd . ' ; } 2>' . $err);
    };
    isnt $status, 0, 'rke2 still on PATH after the uninstall: the command fails';
    like $err->slurp, qr/still installed/, 'and says why on stderr';
};

# A k3s agent's installer names its uninstaller after the service:
# k3s-agent-uninstall.sh, and no k3s-uninstall.sh. The chain only knew the
# server name, so on a k3s worker nothing ran and the k175 check failed the
# destroy (k183). RKE2 ships rke2-uninstall.sh for both roles.
sub run_with_stubs {
    my (%stubs) = @_;
    my $dir  = Path::Tiny->tempdir;
    my $stub = $dir->child('bin');
    $stub->mkpath;
    my $log  = $dir->child('log');
    for my $name (sort keys %stubs) {
        my $f = $stub->child($name);
        $f->spew_utf8("#!/bin/sh\necho $name >> \"\$OCP_STUB_LOG\"\n".$stubs{$name});
        $f->chmod(0755);
    }
    my $status = do {
        local $ENV{PATH}         = "$stub";
        local $ENV{OCP_STUB_LOG} = "$log";
        local $ENV{OCP_STUB_BIN} = "$stub";
        system('/bin/sh', '-c', $cmd . ' 2>/dev/null');
    };
    return ($status, $log->exists ? $log->slurp : '');
}

subtest 'a k3s agent is uninstalled through k3s-agent-uninstall.sh (k183)' => sub {
    plan skip_all => 'needs a POSIX /bin/sh and /bin/rm'
      unless -x '/bin/sh' && -x '/bin/rm';

    my ($status, $ran) = run_with_stubs(
        'k3s'                    => "exit 0\n",
        'k3s-agent-uninstall.sh' =>
            "/bin/rm -f \"\$OCP_STUB_BIN/k3s\" \"\$0\"\nexit 0\n",
    );
    like $ran, qr/^k3s-agent-uninstall\.sh$/m, 'the agent uninstaller ran';
    is $status, 0, 'k3s is gone afterwards: the uninstall succeeds';
};

subtest 'every uninstaller present runs, a failing one does not stop the next' => sub {
    plan skip_all => 'needs a POSIX /bin/sh' unless -x '/bin/sh';

    my ($status, $ran) = run_with_stubs(
        map { $_ => "exit 1\n" }
          qw( rke2-uninstall.sh k3s-uninstall.sh k3s-agent-uninstall.sh )
    );
    like $ran, qr/^rke2-uninstall\.sh$/m,      'rke2 uninstaller attempted';
    like $ran, qr/^k3s-uninstall\.sh$/m,       'k3s uninstaller attempted';
    like $ran, qr/^k3s-agent-uninstall\.sh$/m, 'k3s agent uninstaller attempted';
};

done_testing;
