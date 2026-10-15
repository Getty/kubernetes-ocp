#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

#
# k212 (lab 2026-10-15): a Leitstand added with `ocp keys recipients add` checks
# its access with `sops -d kubeconfig.yaml`, but the image carried neither sops
# nor age -- OCP itself needs neither (File::SOPS, Crypt::Age), so nothing
# noticed. Both are operator tools now, like kubectl: age from Debian, sops as a
# release binary pinned by version and sha256 for each architecture the image
# is built for.
#

my $root = path(__FILE__)->parent->parent;

subtest 'the Dockerfile installs age and a pinned sops' => sub {
    my $file = $root->child('Dockerfile');
    plan skip_all => 'Dockerfile not found' unless -f $file;
    my $df = $file->slurp_utf8;

    ok $df =~ m{apt-get \s+ install [^\n]*(?:\\\n[^\n]*)*? \b age \b}x, 'age comes from the Debian packages';
    ok $df =~ m{^ARG \s+ SOPS_VERSION=\d+\.\d+\.\d+ \s*$}mx, 'sops is pinned to an exact version';
    for my $arch (qw(amd64 arm64)) {
        ok $df =~ m{\b$arch\) \s+ SUM=[0-9a-f]{64} \s* ;;}x, "a sha256 for $arch";
    }
    ok $df =~ m{sha256sum \s+ -c}x, 'the download is checked against it';
    ok $df =~ m{\*\) [^\n]* exit \s+ 1}x, 'an architecture without a pin fails the build';
};

subtest 'inside the image both run' => sub {
    plan skip_all => 'not inside the OCP image' unless -x '/usr/local/bin/sops';
    like scalar(`sops --version 2>&1`), qr/sops \d+\.\d+\.\d+/, 'sops --version';
    like scalar(`age --version 2>&1`), qr/\d+\.\d+\.\d+/, 'age --version';
    like scalar(`age-keygen 2>/dev/null`), qr/^AGE-SECRET-KEY-/m, 'age-keygen makes an identity';
};

done_testing;
