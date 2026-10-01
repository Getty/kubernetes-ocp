#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

#
# k222: vendor/ is how a sibling dist's unreleased fix reaches the image
# without waiting for CPAN ("only the local state counts"). It used to be a
# TEMP block that k214 removed once Rex::GPU/Rex::Rancher were released; the
# next unreleased fix (IO::K8s k196, needed by k221) had nowhere to go. Now it
# is permanent: the Makefile's VENDOR list names sibling checkouts,
# `make vendor` dzil-builds each one into vendor/ and records the install
# order in vendor/ORDER, and the Dockerfile installs them, in that order,
# before the snapshot pass. VENDOR= is CPAN-only.
#
# `make vendor` is exercised for real here, against throwaway sibling
# repositories and a stand-in `dzil` at the front of PATH — never against the
# real siblings and never with the real Dist::Zilla.
#

my $root = path(__FILE__)->parent->parent->absolute;
my $makefile = $root->child('Makefile');
plan skip_all => 'Makefile not found' unless -f $makefile;
plan skip_all => 'make or git not available'
    unless system('make --version >/dev/null 2>&1') == 0
        && system('git --version >/dev/null 2>&1') == 0;

# A sibling checkout whose `dzil build` (the mock) writes <Dist>-<ver>.tar.gz
# into the directory it is run in, the way Dist::Zilla does.
sub make_sibling {
    my ($dir, $dist, $ver) = @_;
    $dir->mkpath;
    $dir->child('dist.ini')->spew("name = $dist\nversion = $ver\n");
    for my $cmd (['init', '-q'], ['config', 'user.email', 't@t'],
                 ['config', 'user.name', 't'], ['add', '.'],
                 ['commit', '-q', '-m', 'init']) {
        system('git', '-C', "$dir", @$cmd) == 0 or die "git @$cmd: $?";
    }
}

sub sandbox {
    my $tmp = path(tempdir(CLEANUP => 1));
    my $proj = $tmp->child('ocp');
    $proj->mkpath;
    $makefile->copy($proj->child('Makefile'));

    my $bin = $tmp->child('bin');
    $bin->mkpath;
    my $log = $tmp->child('dzil.log');
    $bin->child('dzil')->spew(<<"EOS");
#!/bin/sh
set -e
[ "\$1" = build ] || { echo "mock dzil: unexpected \$*" >&2; exit 2; }
name=\$(sed -n 's/^name = //p' dist.ini)
ver=\$(sed -n 's/^version = //p' dist.ini)
echo "\$name \$PWD" >> "$log"
mkdir -p "\$name-\$ver" && echo x > "\$name-\$ver/README"
tar czf "\$name-\$ver.tar.gz" "\$name-\$ver"
EOS
    $bin->child('dzil')->chmod(0755);

    my $sib = $tmp->child('siblings');
    make_sibling($sib->child('io-k8s-p5'),    'IO-K8s',    '1.110');
    make_sibling($sib->child('rex-gpu'),      'Rex-GPU',   '0.004');
    make_sibling($sib->child('p5-crypt-age'), 'Crypt-Age', '0.005');

    return ($proj, $sib, $bin, $log);
}

sub run_make {
    my ($proj, $bin, @args) = @_;
    local $ENV{PATH} = "$bin:$ENV{PATH}";
    my $out = `make -s -C '$proj' vendor @args 2>&1`;
    return ($? >> 8, $out);
}

subtest 'make vendor builds the VENDOR list into vendor/, in list order' => sub {
    my ($proj, $sib, $bin, $log) = sandbox();
    my ($rc, $out) = run_make($proj, $bin, "SIBLINGS_DIR=$sib",
        "VENDOR='io-k8s-p5 rex-gpu p5-crypt-age'");
    is $rc, 0, 'make vendor succeeds' or diag $out;

    my $vendor = $proj->child('vendor');
    ok -f $vendor->child('.keep'), 'vendor/.keep exists';
    is_deeply [ $vendor->child('ORDER')->lines_utf8({ chomp => 1 }) ],
        [ 'IO-K8s-1.110.tar.gz', 'Rex-GPU-0.004.tar.gz', 'Crypt-Age-0.005.tar.gz' ],
        'vendor/ORDER lists the tarballs in VENDOR order';
    ok -f $vendor->child($_), "$_ is in vendor/"
        for qw(IO-K8s-1.110.tar.gz Rex-GPU-0.004.tar.gz Crypt-Age-0.005.tar.gz);

    # The sibling's own checkout is left alone: built in a clone, so neither
    # a tarball nor a build dir lands in a working tree someone may be using.
    for my $s (qw(io-k8s-p5 rex-gpu p5-crypt-age)) {
        my @junk = grep { !/^(\.git|dist\.ini)$/ } map { $_->basename }
            $sib->child($s)->children;
        is_deeply \@junk, [], "$s working tree untouched";
    }
    unlike $log->slurp_utf8, qr{\Q$sib\E}, 'dzil never ran inside a sibling checkout';
};

subtest 'VENDOR picks and orders the list' => sub {
    my ($proj, $sib, $bin) = sandbox();
    my ($rc, $out) = run_make($proj, $bin, "SIBLINGS_DIR=$sib",
        "VENDOR='p5-crypt-age io-k8s-p5'");
    is $rc, 0, 'make vendor succeeds' or diag $out;
    is_deeply [ $proj->child('vendor/ORDER')->lines_utf8({ chomp => 1 }) ],
        [ 'Crypt-Age-0.005.tar.gz', 'IO-K8s-1.110.tar.gz' ],
        'ORDER follows the given list';
};

subtest 'VENDOR= leaves an empty vendor/ (CPAN-only)' => sub {
    my ($proj, $sib, $bin) = sandbox();
    run_make($proj, $bin, "SIBLINGS_DIR=$sib");   # stale tarballs first
    my ($rc, $out) = run_make($proj, $bin, "SIBLINGS_DIR=$sib", 'VENDOR=');
    is $rc, 0, 'make vendor VENDOR= succeeds' or diag $out;
    my @left = sort map { $_->basename } $proj->child('vendor')->children;
    is_deeply \@left, [ '.keep', 'ORDER' ], 'only .keep and an ORDER remain';
    is $proj->child('vendor/ORDER')->slurp_utf8, '', 'ORDER is empty';
};

subtest 'a missing sibling fails loud' => sub {
    my ($proj, $sib, $bin) = sandbox();
    my ($rc, $out) = run_make($proj, $bin, "SIBLINGS_DIR=$sib", 'VENDOR=nope');
    isnt $rc, 0, 'make vendor fails';
    like $out, qr{nope}, 'and names the missing sibling';
};

# Nothing pending since the 2026-10-01 releases (IO::K8s 1.110, Rex::GPU 0.004,
# Crypt::Age 0.005): the default is empty, a plain `make vendor` is CPAN-only.
subtest 'the default list' => sub {
    ok $makefile->slurp_utf8 =~ m{^VENDOR \s* \?= \s*$}mx,
        'VENDOR defaults to nothing -- everything the image needs is on CPAN';
    my ($proj, $sib, $bin) = sandbox();
    my ($rc, $out) = run_make($proj, $bin, "SIBLINGS_DIR=$sib");
    is $rc, 0, 'a plain make vendor succeeds' or diag $out;
    is $proj->child('vendor/ORDER')->slurp_utf8, '', 'and vendors nothing';
    ok $makefile->slurp_utf8 =~ m{^SIBLINGS_DIR \s* \?= \s* \.\. \s*$}mx,
        'SIBLINGS_DIR defaults to ..';
};

subtest 'the Dockerfile installs vendor/ORDER before the snapshot pass' => sub {
    my $df = $root->child('Dockerfile')->slurp_utf8;
    my $vendor   = index $df, 'vendor/ORDER';
    my $snapshot = index $df, '--snapshot=./cpanfile.snapshot';
    ok $vendor > 0, 'the Dockerfile reads vendor/ORDER';
    ok $snapshot > 0 && $vendor < $snapshot, 'before the snapshot pass';
    ok $df =~ m{COPY \s+ --chown=ocp:ocp \s+ \./vendor/ \s+ \$OCP_ROOT/src/vendor/}x,
        'vendor/ is copied into the build';
    ok $df =~ m{--local-lib-contained=\$PERL_LOCAL_LIB_ROOT \s+ "\./vendor/\$}x,
        'into the same contained local-lib';
    ok $df =~ m{\[ \s+ -s \s+ vendor/ORDER \s+ \]}x,
        'an empty vendor/ installs nothing';
};

subtest 'build context and git' => sub {
    my $di = $root->child('.dockerignore')->slurp_utf8;
    ok $di =~ m{^!vendor/\*\.tar\.gz$}m, '.dockerignore lets vendor tarballs in';
    my $gi = $root->child('.gitignore')->slurp_utf8;
    ok $gi =~ m{^/?vendor/\*\.tar\.gz$}m, '.gitignore keeps vendor tarballs out';
    ok $gi =~ m{^/?vendor/ORDER$}m, '.gitignore keeps the generated ORDER out';
    ok -f $root->child('vendor/.keep'), 'vendor/.keep is tracked, so COPY ./vendor/ always works';
};

subtest 'CI builds the same list and hands it to both image jobs' => sub {
    my $ci = $root->child('.github/workflows/ci.yml')->slurp_utf8;
    ok $ci =~ m{^  vendor:$}m, 'there is a vendor job';
    ok $ci =~ m{repository: \s+ \Q$_\E \s}x, "it checks out $_"
        for qw(pplu/io-k8s-p5 Getty/rex-gpu Getty/p5-crypt-age);
    ok $ci =~ m{make \s+ vendor \s+ SIBLINGS_DIR=}x, 'it runs make vendor';
    for my $job (qw(dockerhub ghcr)) {
        my ($body) = $ci =~ m{^  $job:\n(.*?)(?=^  \S|\z)}ms;
        ok $body && $body =~ m{needs: \s+ vendor}x, "$job needs vendor";
        ok $body && $body =~ m{download-artifact}, "$job downloads the vendor artifact";
    }
};

subtest 'cpanfile: IO::K8s floor 1.110 (k221, k196 fix)' => sub {
    ok $root->child('cpanfile')->slurp_utf8 =~ m{^requires 'IO::K8s', '1\.110';$}m,
        'requires IO::K8s 1.110';
};

done_testing;
