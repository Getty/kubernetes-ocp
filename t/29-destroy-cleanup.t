#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

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
    # Both halves are guarded, so destroying a host where the distribution was
    # already gone still removes the leftovers instead of dying early.
    my @parts = split /\s*;\s*/, $cmd;
    is scalar(@parts), 2, 'uninstall and cleanup are separate statements';

    for my $part (@parts) {
        like $part, qr/\|\|\s*true\s*$/,
            'each statement swallows its own failure';
    }
};

done_testing;
