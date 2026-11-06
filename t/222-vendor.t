#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use version ();
use YAML::XS ();

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
# k404: CI vendors that same list. Its vendor job used to hard-code three
# sibling checkouts and install Dist::Zilla even with VENDOR empty. Now it
# reads VENDOR from the Makefile (`make vendor-list`), clones exactly those
# siblings from their homes in SIBLING_HOMES (`make vendor-siblings`), and
# skips the clone and Dist::Zilla when the list is empty.
#
# k406: the default list is no longer empty by rule. cpanfile pins every
# sibling at the version its tree releases next, cpanfile.snapshot pins only
# what CPAN has, and VENDOR names exactly the siblings whose pin the snapshot
# does not reach -- so a pin bumped ahead of CPAN without vendoring fails
# here, and so does a VENDOR entry left behind after the release day.
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
#
# The version is also a tag one commit behind HEAD, the way a release leaves
# it: a clone without the full history loses the tag, and with it the version
# dzil reads.
sub make_sibling {
    my ($dir, $dist, $ver) = @_;
    $dir->mkpath;
    $dir->child('dist.ini')->spew("name = $dist\nversion = $ver\n");
    for my $cmd (['init', '-q'], ['config', 'user.email', 't@t'],
                 ['config', 'user.name', 't'], ['add', '.'],
                 ['-c', 'commit.gpgSign=false', 'commit', '-q', '-m', 'init'],
                 ['-c', 'tag.gpgSign=false', 'tag', $ver],
                 ['-c', 'commit.gpgSign=false', 'commit', '-q', '--allow-empty',
                  '-m', 'after the release']) {
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

sub run_target {
    my ($proj, $bin, $target, @args) = @_;
    local $ENV{PATH} = "$bin:$ENV{PATH}";
    # make reads these from the environment too; only the arguments count here
    delete local @ENV{qw(VENDOR SIBLINGS_DIR SIBLINGS_REMOTE)};
    my $out = `make -s -C '$proj' $target @args 2>&1`;
    return ($? >> 8, $out);
}

sub run_make { my ($proj, $bin, @args) = @_; run_target($proj, $bin, 'vendor', @args) }

# A stand-in for GitHub: for each owner/repo given, a bare copy of the named
# sandbox sibling at <remote>/<owner/repo>.git. Handed out as a file:// URL so
# git clones it like a real remote (from a plain path it would ignore --depth).
sub make_remote {
    my ($sib, %home) = @_;
    my $remote = path(tempdir(CLEANUP => 1));
    for my $repo (sort keys %home) {
        my $bare = $remote->child("$repo.git");
        $bare->parent->mkpath;
        system('git', 'clone', '-q', '--bare', $sib->child($home{$repo}) . '', "$bare") == 0
            or die "git clone --bare $home{$repo}: $?";
    }
    return "file://$remote";
}

sub git_out {
    my ($dir, @cmd) = @_;
    my $out = `git -C '$dir' @cmd 2>&1`;
    chomp $out;
    return $out;
}

# What a directory holds, by name; nothing when it does not exist.
sub names_in { my ($dir) = @_; -d $dir ? [ sort map { $_->basename } $dir->children ] : [] }

# The module each sibling checkout builds (k406).
my %SIBLING = (
    'Crypt::Age'             => 'p5-crypt-age',
    'File::SOPS'             => 'p5-file-sops',
    'IO::K8s'                => 'io-k8s-p5',
    'Kubernetes::REST'       => 'kubernetes-rest',
    'MooX::Cmd'              => 'p5-moox-cmd',
    'Net::Async::Kubernetes' => 'p5-net-async-kubernetes',
    'Rex::GPU'               => 'rex-gpu',
    'Rex::LibSSH'            => 'rex-libssh',
    'Rex::Rancher'           => 'rex-rancher',
    'WWW::Hetzner'           => 'p5-www-hetzner',
);

# A variable of the real Makefile as make expands it, split into words; the
# environment does not count.
sub make_var {
    my ($var) = @_;
    delete local $ENV{$var};
    open my $mk, '-|', 'make', '-s', '-f', "$makefile",
        '--eval', "print-var: ; \@echo \$($var)", 'print-var'
        or die "make: $!";
    my $out = do { local $/; <$mk> };
    close $mk or die "make print-var $var: $?";
    return split ' ', $out;
}

# requires 'Module', 'version'; from cpanfile, as module => version.
sub cpanfile_pins {
    my %pin = $root->child('cpanfile')->slurp_utf8
        =~ m{^requires \s+ '([^']+)', \s* '([^']+)';}mxg;
    delete $pin{perl};
    return \%pin;
}

# The version cpanfile.snapshot installs of each module, from the provides:
# block of each distribution.
sub snapshot_versions {
    my (%have, $provides);
    for ($root->child('cpanfile.snapshot')->lines_utf8({ chomp => 1 })) {
        if (/^ {4}(\S+):/) { $provides = $1 eq 'provides'; next }
        $have{$1} = $2 if $provides && /^ {6}(\S+) (\S+)$/;
    }
    return \%have;
}

sub reaches {
    my ($have, $want) = @_;
    return defined $have && $have ne 'undef'
        && version->parse($have) >= version->parse($want);
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

# The default is the difference between cpanfile and cpanfile.snapshot: the
# siblings whose pin only their tree has, until the release day moves the
# snapshot (k406). Empty again once everything pinned is on CPAN.
subtest 'the default list is what cpanfile pins beyond the snapshot' => sub {
    my $pin    = cpanfile_pins();
    my $have   = snapshot_versions();
    my @vendor = make_var('VENDOR');

    is_deeply [ sort values %SIBLING ],
        [ sort map { (split /=/)[0] } make_var('SIBLING_HOMES') ],
        'every sibling with a home is one this test knows the module of';
    ok defined $pin->{$_}, "cpanfile pins a version of $_" for sort keys %SIBLING;

    my @beyond = grep { !reaches($have->{$_}, $pin->{$_}) } sort keys %$pin;
    is_deeply [ grep { !$SIBLING{$_} } @beyond ], [],
        'every pin the snapshot does not reach is a sibling, so vendor/ can carry it';
    is_deeply [ sort @vendor ], [ sort map { $SIBLING{$_} // () } @beyond ],
        'VENDOR names exactly the siblings of those pins (' . join(' ', @vendor) . ')';
    my %seen;
    is_deeply [ grep { $seen{$_}++ } @vendor ], [], 'each one once';

    # A plain `make vendor` builds that list, in its order.
    my ($proj, undef, $bin) = sandbox();
    my %module = reverse %SIBLING;
    my %dist = map { ($_ => $module{$_} =~ s/::/-/gr) } @vendor;
    my $sib = path(tempdir(CLEANUP => 1));
    make_sibling($sib->child($_), $dist{$_}, $pin->{$module{$_}}) for @vendor;
    my ($rc, $out) = run_make($proj, $bin, "SIBLINGS_DIR=$sib");
    is $rc, 0, 'a plain make vendor succeeds' or diag $out;
    is_deeply [ $proj->child('vendor/ORDER')->lines_utf8({ chomp => 1 }) ],
        [ map { "$dist{$_}-$pin->{$module{$_}}.tar.gz" } @vendor ],
        'and builds the default list, in its order';
};

# With VENDOR set by default, a plain `make build` vendors -- also in a fresh
# worktree under .claude/worktrees/, where `..` holds no sibling (k406). The
# default is the directory next to the main checkout, from the main checkout
# and from its worktrees alike; `..` where there is no git.
subtest 'SIBLINGS_DIR defaults to the directory that holds the main checkout' => sub {
    my $tmp  = path(tempdir(CLEANUP => 1))->realpath;
    my $main = $tmp->child('dev', 'ocp');
    make_sibling($main, 'OCP', '0.001');
    my $worktree = $main->child('.claude', 'worktrees', 'x');
    system('git', '-C', "$main", 'worktree', 'add', '-q', "$worktree") == 0
        or die "git worktree add: $?";
    my $plain = $tmp->child('plain');
    $plain->mkpath;
    $makefile->copy($_->child('Makefile')) for $main, $worktree, $plain;

    # git looks no further up than $tmp, so the plain directory has no git
    # even when the temp dir lies inside some repository.
    local $ENV{GIT_CEILING_DIRECTORIES} = "$tmp";
    delete local @ENV{qw(SIBLINGS_DIR GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR)};
    my $siblings_dir = sub {
        my ($dir, @args) = @_;
        my $out = `make -s -C '$dir' --eval 'print-var: ; \@echo \$(SIBLINGS_DIR)' print-var @args 2>&1`;
        chomp $out;
        return $out;
    };
    my $dev = $tmp->child('dev') . '';
    is $siblings_dir->($worktree), $dev,
        'from a worktree under .claude/worktrees/: next to the main checkout';
    is $siblings_dir->($main), $dev, 'from the main checkout: the same';
    is $siblings_dir->($plain), '..', 'without git: ..';
    is $siblings_dir->($worktree, 'SIBLINGS_DIR=/given'), '/given',
        'given on the command line, it wins';
    local $ENV{SIBLINGS_DIR} = 'siblings';
    is $siblings_dir->($worktree), 'siblings', 'and from the environment, as CI sets it';
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

# ─── CI: the same list, from the Makefile (k404) ─────────────────────────────

subtest 'make vendor-list prints VENDOR on one line' => sub {
    my ($proj, $sib, $bin) = sandbox();
    my ($rc, $out) = run_target($proj, $bin, 'vendor-list');
    is $rc, 0, 'make vendor-list succeeds' or diag $out;
    is $out, join(' ', make_var('VENDOR')) . "\n", 'the default list, as the Makefile names it';
    ($rc, $out) = run_target($proj, $bin, 'vendor-list', "VENDOR=' rex-gpu   io-k8s-p5 '");
    is $out, "rex-gpu io-k8s-p5\n", 'a given list comes out as one line';
};

subtest 'make vendor-siblings clones exactly VENDOR, with full history' => sub {
    my ($proj, $sib, $bin) = sandbox();
    my $remote = make_remote($sib, 'Getty/rex-gpu' => 'rex-gpu',
        'pplu/io-k8s-p5' => 'io-k8s-p5', 'Getty/p5-crypt-age' => 'p5-crypt-age');
    my $dest = path(tempdir(CLEANUP => 1))->child('siblings');
    my @list = ("VENDOR='rex-gpu io-k8s-p5'", "SIBLINGS_DIR=$dest");
    my ($rc, $out) = run_target($proj, $bin, 'vendor-siblings', @list,
        "SIBLINGS_REMOTE=$remote");
    is $rc, 0, 'make vendor-siblings succeeds' or diag $out;
    is_deeply names_in($dest), [ 'io-k8s-p5', 'rex-gpu' ],
        'it clones the VENDOR siblings and no other';
    for my $s ([ 'rex-gpu', '0.004' ], [ 'io-k8s-p5', '1.110' ]) {
        my ($name, $ver) = @$s;
        is git_out($dest->child($name), qw(rev-parse --is-shallow-repository)), 'false',
            "$name: full history";
        is git_out($dest->child($name), qw(describe --tags --abbrev=0)), $ver,
            "$name: its release tag came along";
    }

    # The CI path end to end: the same `make vendor` builds from those clones.
    ($rc, $out) = run_make($proj, $bin, @list);
    is $rc, 0, 'make vendor builds from the clones' or diag $out;
    is_deeply [ $proj->child('vendor/ORDER')->lines_utf8({ chomp => 1 }) ],
        [ 'Rex-GPU-0.004.tar.gz', 'IO-K8s-1.110.tar.gz' ],
        'in VENDOR order';
};

# Each sibling OCP depends on has its home, so vendoring it before its release
# is a Makefile change and never a ci.yml one.
subtest 'SIBLING_HOMES knows where each sibling lives' => sub {
    my %home = (
        'io-k8s-p5'       => 'pplu/io-k8s-p5',
        'kubernetes-rest' => 'pplu/kubernetes-rest',
        map { ($_ => "Getty/$_") } qw(p5-crypt-age p5-file-sops p5-moox-cmd
            p5-net-async-kubernetes p5-www-hetzner rex-gpu rex-libssh rex-rancher),
    );
    my ($proj, $sib, $bin) = sandbox();
    my $remote = make_remote($sib, map { ($home{$_} => 'rex-gpu') } keys %home);
    my $dest = path(tempdir(CLEANUP => 1))->child('siblings');
    my $list = join ' ', sort keys %home;
    my ($rc, $out) = run_target($proj, $bin, 'vendor-siblings', "VENDOR='$list'",
        "SIBLINGS_DIR=$dest", "SIBLINGS_REMOTE=$remote");
    is $rc, 0, 'each one clones from its home' or diag $out;
    is_deeply names_in($dest), [ sort keys %home ],
        'into a directory of its own name';
};

subtest 'a VENDOR entry without a home fails loud' => sub {
    my ($proj, $sib, $bin) = sandbox();
    my $dest = path(tempdir(CLEANUP => 1))->child('siblings');
    my ($rc, $out) = run_target($proj, $bin, 'vendor-siblings', 'VENDOR=nope',
        "SIBLINGS_DIR=$dest", 'SIBLINGS_REMOTE=file:///nonexistent');
    isnt $rc, 0, 'make vendor-siblings fails';
    like $out, qr{\bnope\b.*\bSIBLING_HOMES\b}, 'naming the sibling and where its home goes';
    ok !-e $dest, 'and clones nothing';
};

subtest 'VENDOR= clones nothing' => sub {
    my ($proj, $sib, $bin) = sandbox();
    my $dest = path(tempdir(CLEANUP => 1))->child('siblings');
    my ($rc, $out) = run_target($proj, $bin, 'vendor-siblings', 'VENDOR=',
        "SIBLINGS_DIR=$dest", 'SIBLINGS_REMOTE=file:///nonexistent');
    is $rc, 0, 'make vendor-siblings VENDOR= succeeds' or diag $out;
    ok !-e $dest, 'and creates nothing';
};

# Run outside CI with the default SIBLINGS_DIR, the target meets the real
# checkouts. They must come out of that unchanged.
subtest 'an existing checkout is never cloned over' => sub {
    my ($proj, $sib, $bin) = sandbox();
    my $remote = make_remote($sib, 'Getty/rex-gpu' => 'rex-gpu');
    my $checkout = $sib->child('rex-gpu');
    my $head = git_out($checkout, qw(rev-parse HEAD));
    my ($rc, $out) = run_target($proj, $bin, 'vendor-siblings', 'VENDOR=rex-gpu',
        "SIBLINGS_DIR=$sib", "SIBLINGS_REMOTE=$remote");
    isnt $rc, 0, 'make vendor-siblings onto the checkouts fails';
    like $out, qr{rex-gpu}, 'naming the sibling';
    is git_out($checkout, qw(rev-parse HEAD)), $head, 'the checkout keeps its HEAD';
    is_deeply names_in($checkout), [ '.git', 'dist.ini' ], 'and its files';
};

subtest 'the CI vendor job follows the Makefile list and keeps none of its own' => sub {
    my $ci_file = $root->child('.github/workflows/ci.yml');
    my $job = YAML::XS::LoadFile("$ci_file")->{jobs}{vendor};
    ok $job, 'there is a vendor job' or return;
    my @steps = @{ $job->{steps} || [] };
    my $run = sub { $_[0]{run} // '' };

    # No copy of the list: no checkout of another repository, no sibling named.
    is_deeply [ grep { $_->{with} && $_->{with}{repository} } @steps ], [],
        'no step checks out a sibling repository';
    open my $mk, '-|', 'make', '-s', '-f', "$makefile",
        '--eval', 'homes: ; @echo $(SIBLING_HOMES)', 'homes'
        or die "make: $!";
    my @names = map { (split /=/)[0] } split ' ', do { local $/; <$mk> };
    close $mk;
    ok @names >= 2, 'SIBLING_HOMES names the siblings (' . scalar(@names) . ')';
    my ($text) = $ci_file->slurp_utf8 =~ m{^  vendor:\n(.*?)(?=^  \S|\z)}ms;
    is_deeply [ grep { $text =~ m{(?<![\w-])\Q$_\E(?![\w-])} } @names ], [],
        'and the job names none of them';

    my ($list) = grep { $run->($_) =~ m{\bmake \s+ -s \s+ vendor-list\b}x } @steps;
    ok $list && $list->{id}, 'a step with an id reads the list with make vendor-list'
        or return;

    # That step, run the way the runner runs it, against a Makefile that names
    # two siblings and against one that names none.
    for my $vendor ('', 'rex-gpu io-k8s-p5') {
        my $dir = path(tempdir(CLEANUP => 1));
        (my $mf = $makefile->slurp_utf8) =~ s{^VENDOR \s* \?= .*$}{VENDOR ?= $vendor}mx
            or die 'no VENDOR line in the Makefile';
        $dir->child('Makefile')->spew_utf8($mf);
        $dir->child('step.sh')->spew_utf8($run->($list));
        my $output = $dir->child('github_output');
        $output->touch;
        local $ENV{GITHUB_OUTPUT} = "$output";
        delete local $ENV{VENDOR};
        my $log = `cd '$dir' && bash --noprofile --norc -eo pipefail step.sh 2>&1`;
        is $? >> 8, 0, "the step runs with VENDOR ?= '$vendor'" or diag $log;
        is $output->slurp_utf8, "vendor=$vendor\n", "and outputs vendor=$vendor";
    }

    # Cloning and Dist::Zilla only when that output names siblings.
    my $gate = "steps.$list->{id}.outputs.vendor != ''";
    my @work = grep { YAML::XS::Dump($_) =~ m{\b(?:cpanm|dzil|Dist::Zilla|vendor-siblings)\b} }
        @steps;
    ok scalar(grep { $run->($_) =~ m{\bmake \s+ vendor-siblings\b}x } @work),
        'a step clones the siblings with make vendor-siblings';
    ok scalar(grep { $run->($_) =~ m{\bcpanm\b .* \bDist::Zilla\b}x } @work),
        'a step installs Dist::Zilla';
    for my $step (@work) {
        (my $if = $step->{if} // '') =~ s{^\s*\$\{\{\s*|\s*\}\}\s*$}{}g;
        is $if, $gate, "'" . ($step->{name} // $run->($step)) . "' runs only then";
    }

    # One SIBLINGS_DIR for the whole job: the clones are what make vendor reads.
    ok $job->{env} && $job->{env}{SIBLINGS_DIR}, 'the job sets SIBLINGS_DIR';
    is_deeply [ grep { $run->($_) =~ m{SIBLINGS_DIR=} || ($_->{env} && exists $_->{env}{SIBLINGS_DIR}) }
        @steps ], [], 'and no step sets another';

    # The artifact exists either way.
    my ($build) = grep { $run->($_) =~ m{\bmake \s+ vendor (?:\s|$)}x } @steps;
    ok $build && !$build->{if}, 'make vendor runs whatever VENDOR is';
    my ($upload) = grep { ($_->{uses} // '') =~ m{^actions/upload-artifact@} } @steps;
    ok $upload && !$upload->{if} && ($upload->{with}{path} // '') eq 'vendor/',
        'and vendor/ is uploaded';

    my $ci = $ci_file->slurp_utf8;
    for my $job (qw(dockerhub ghcr)) {
        my ($body) = $ci =~ m{^  $job:\n(.*?)(?=^  \S|\z)}ms;
        ok $body && $body =~ m{needs: \s+ vendor}x, "$job needs vendor";
        ok $body && $body =~ m{download-artifact}, "$job downloads the vendor artifact";
    }
};

subtest 'cpanfile: IO::K8s floor at least 1.110 (k221, k196 fix)' => sub {
    my ($floor) = $root->child('cpanfile')->slurp_utf8
        =~ m{^requires 'IO::K8s', '([0-9.]+)';$}m;
    ok defined $floor && $floor >= 1.110,
        'requires IO::K8s 1.110 or newer (' . ($floor // 'none') . ')';
};

done_testing;
