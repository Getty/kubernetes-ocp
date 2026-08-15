#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use Path::Tiny qw(path);
#
# share/bin/ocp-build-image builds and (by default) pushes the OCP image for
# the architecture of the machine it runs on, idempotent, CI-friendly. The
# only thing this test actually exercises is the script's command line — it
# must not require a running docker daemon, a logged-in registry, or even
# `docker` in $PATH, because those are precisely the things CI wants to
# assert are *not* needed.
#
# Almost everything below runs the script with --dry-run, so docker is never
# invoked. The `mock docker` further down proves that point by recording
# every invocation: in --dry-run mode the log stays empty. The two
# failure-mode subtests at the end are the exception — they need the real
# code path to reach `docker`, and get there against the mock, never against
# a daemon.
#
my $root   = path(__FILE__)->parent->parent->absolute;
my $script = $root->child('share/bin/ocp-build-image');
plan skip_all => 'share/bin/ocp-build-image not found' unless -f $script;

# Run the script in a fresh sandbox and return (exit, stdout, stderr,
# whether the mock docker was touched). Invocations are forced into
# --dry-run mode unless the caller passes no_dry_run — the mock at the
# front of PATH exists to catch and log any invocation that slips through,
# so the `--dry-run` claim has a witness, not just trust, and to stand in
# for docker in the no_dry_run failure-mode tests.
sub run_ocp_build {
    my (%opts) = @_;
    $opts{args} = [@{$opts{args} // []}, '--dry-run']
        unless $opts{no_dry_run};
    my $cwd = tempdir(CLEANUP => 1);
    path($cwd)->child('VERSION')->spew($opts{version})
        if defined $opts{version};
    if ($opts{git_init}) {
        system('git', '-C', $cwd, 'init', '-q') == 0
            or die "git init failed in $cwd: $?";
        system('git', '-C', $cwd, 'config', 'user.email', 't@t');
        system('git', '-C', $cwd, 'config', 'user.name',  't');
        if ($opts{commit}) {
            system('git', '-C', $cwd, 'commit', '-q', '--allow-empty',
                   '-m', 'init') == 0
                or die "git commit failed: $?";
        }
    }

    # Mock docker in a bin/ dir we put at the FRONT of PATH. The mock
    # always records its argv; the script must not call it under --dry-run.
    # docker_mock appends shell to that recorder, which is how the
    # failure-mode tests make a specific subcommand fail.
    my $mockbin  = path($cwd)->child('mockbin');
    my $mock_log = $mockbin->child('.docker.log');
    $mockbin->mkpath;
    $mock_log->spew('');
    my $mock = <<'EOS';
#!/bin/sh
printf '%s\n' "$0" "$@" >> "$(dirname "$0")/.docker.log"
EOS
    $mock .= $opts{docker_mock} // "exit 0\n";
    $mockbin->child('docker')->spew($mock);
    $mockbin->child('docker')->chmod(0755);

    # A docker config that says "logged in" — would matter only without
    # --dry-run, but having it here means a test that forgets to add
    # --dry-run still exits 1 with a sensible error rather than 3 with
    # a confusing login-check one.
    my $cfgdir = path($cwd)->child('.docker');
    $cfgdir->mkpath;
    $cfgdir->child('config.json')->spew(q[{"auths":{"docker.io":{"auth":""}}}]);

    # One shell command line, env assignments + redirection. `cd` and the
    # env-prefixed command are separated with `&&` — without it, `cd $dir
    # PATH=… bash …` parses as `cd $dir PATH=…` taking `bash` as a second
    # directory argument. Quoting uses single-quote-with-'\''-escape so
    # an argument containing a quote cannot break out into the shell.
    my @args = map { my $a = $_; $a =~ s/'/'\\''/g; "'$a'" } @{$opts{args}};
    my $env_repo = defined $opts{repo_env}
        ? "OCP_IMAGE_REPO='$opts{repo_env}' "
        : '';
    my $shell_cmd = join(' ',
        "cd " . shellquote($cwd) . " &&",
        "PATH=" . shellquote("$mockbin:/usr/bin:/bin"),
        "HOME="   . shellquote($cwd),
        "DOCKER_CONFIG=" . shellquote("$cfgdir"),
        $env_repo,
        "bash " . shellquote($script->stringify),
        @args,
        '>' . shellquote("$cwd/stdout"),
        '2>' . shellquote("$cwd/stderr"),
    );
    system('sh', '-c', $shell_cmd);
    my $exit = $? >> 8;
    return {
        exit   => $exit,
        stdout => path($cwd)->child('stdout')->slurp,
        stderr => path($cwd)->child('stderr')->slurp,
        docker_invoked => $mock_log->slurp ne '',
        docker_log     => $mock_log->slurp,
    };
}

sub shellquote {
    my $s = shift;
    $s =~ s/'/'\\''/g;
    return "'$s'";
}

subtest 'script defaults to raudssus/ocp with the standard tag triple' => sub {
    my $r = run_ocp_build(version => '1.2.3');
    is $r->{exit}, 0, 'dry-run exits 0';
    like $r->{stdout}, qr/^\s*raudssus\/ocp:latest$/m,
        'latest tag is part of the summary';
    like $r->{stdout}, qr/^\s*raudssus\/ocp:1\.2\.3$/m,
        'version tag is part of the summary';
    like $r->{stdout}, qr/^\s*raudssus\/ocp:(?:[a-f0-9]{7}|unknown)$/m,
        'short git sha tag is part of the summary (7 hex chars, or "unknown" outside git)';
    like $r->{stdout}, qr/-t 'raudssus\/ocp:latest'/,
        'latest tag is on the docker build line';
    like $r->{stdout}, qr/-t 'raudssus\/ocp:1\.2\.3'/,
        'version tag is on the docker build line';
    like $r->{stdout}, qr/docker push 'raudssus\/ocp:latest'/,
        'latest tag gets its own docker push line';
    like $r->{stdout}, qr/docker push 'raudssus\/ocp:1\.2\.3'/,
        'version tag gets its own docker push line';
    unlike $r->{stdout}, qr/^other\/x/m,
        'no leaked default-name override';
};

# The image is built for the architecture of the machine running the
# script, which is what a plain `docker build` does on its own.
subtest 'the build command is a plain docker build' => sub {
    my $r = run_ocp_build(version => '0.0.1');
    like $r->{stdout}, qr/\[dry-run\] docker build -t /,
        'the build line is `docker build` with tags';
    unlike $r->{stdout}, qr/--platform\b/,
        'no platform selection — the build host decides the architecture';
    unlike $r->{stdout}, qr/--builder\b/,
        'no builder selection';
};

subtest '--repo= overrides the default repository' => sub {
    my $r = run_ocp_build(
        version => '9.9.9',
        args    => ['--repo=other/x'],
    );
    is $r->{exit}, 0, 'still exits 0';
    unlike $r->{stdout}, qr/raudssus\/ocp/,
        'default repo is gone once --repo= is set';
    like $r->{stdout}, qr/-t 'other\/x:latest'/,
        'latest tag uses the overridden repo';
    like $r->{stdout}, qr/-t 'other\/x:9\.9\.9'/,
        'version tag uses the overridden repo';
    like $r->{stdout}, qr/--cache-from 'type=registry,ref=other\/x:cache'/,
        'cache-from follows the repo override';
};

subtest 'OCP_IMAGE_REPO env var matches --repo=' => sub {
    my $r = run_ocp_build(
        version  => '0.1.0',
        repo_env => 'env/foo',
    );
    like $r->{stdout}, qr/-t 'env\/foo:latest'/,
        'env var overrides the default just like --repo= does';
};

subtest '--no-push drops the docker push commands' => sub {
    my $r = run_ocp_build(
        version => '1.0.0',
        args    => ['--no-push'],
    );
    is $r->{exit}, 0, 'still exits 0';
    unlike $r->{stdout}, qr/docker push/,
        'no push command anywhere in the printed output';
    like $r->{stdout}, qr/\[dry-run\] docker build/,
        'the build itself is still printed';
    like $r->{stdout}, qr/^\s*raudssus\/ocp:latest$/m,
        'tags are still announced';
    like $r->{stdout}, qr/--cache-from/,
        'cache-from is present even without --push';
};

subtest '--dry-run never invokes docker' => sub {
    # Mock docker is in PATH and logs every call. The script must not
    # touch it under --dry-run — otherwise a "dry-run" that already
    # pinged the daemon is not a dry-run.
    my $r = run_ocp_build(version => '0.0.1');
    is $r->{exit}, 0, 'exits 0 in dry-run';
    ok !$r->{docker_invoked},
        'docker was never executed' . ($r->{docker_invoked}
            ? " (log was:\n$r->{docker_log}\n)" : '');
    like $r->{stdout}, qr/\[dry-run\] docker build/,
        'a build command is printed under [dry-run] prefix';
    like $r->{stdout}, qr/\[dry-run\] docker push/,
        'a push command is printed under [dry-run] prefix';
};

subtest 'missing VERSION file falls back, does not crash' => sub {
    my $r = run_ocp_build();
    is $r->{exit}, 0, 'still exits 0 with no VERSION and no git';
    like $r->{stdout}, qr/:develop$/m,
        'version falls back to "develop" when neither VERSION nor git describe works';
};

subtest 'OCP_IMAGE_REPO env beats default but not --repo=' => sub {
    my $r = run_ocp_build(
        version  => '1.0.0',
        repo_env => 'env/foo',
        args     => ['--repo=cli/bar'],
    );
    like $r->{stdout}, qr/-t 'cli\/bar:latest'/,
        '--repo= on the command line wins over the env var';
    unlike $r->{stdout}, qr/env\/foo/,
        'env var is overridden when --repo= is given';
};

subtest '--tag= overrides VERSION' => sub {
    my $r = run_ocp_build(
        version => 'should-be-ignored',
        args    => ['--tag=from-cli'],
    );
    like $r->{stdout}, qr/-t 'raudssus\/ocp:from-cli'/,
        '--tag= value is used, not the VERSION file';
    unlike $r->{stdout}, qr/should-be-ignored/,
        'VERSION file is bypassed by --tag=';
};

subtest 'unknown option exits non-zero and prints usage' => sub {
    my $r = run_ocp_build(args => ['--no-such-flag']);
    isnt $r->{exit}, 0, 'exits non-zero on unknown option';
    like $r->{stderr}, qr/unknown option/i,
        'says so on stderr';
    like $r->{stderr}, qr/Usage:/,
        'prints usage on stderr';
};

subtest '--help exits 0 and documents exit codes' => sub {
    my $r = run_ocp_build(args => ['--help']);
    is $r->{exit}, 0, 'exits 0 on --help';
    like $r->{stdout}, qr/Exit codes:/,
        'documents the exit-code contract';
    like $r->{stdout}, qr/\b1\b.*build failed/s,
        'mentions build-fail exit code 1';
    like $r->{stdout}, qr/\b2\b.*push failed/s,
        'mentions push-fail exit code 2';
    like $r->{stdout}, qr/\b3\b.*not logged in/s,
        'mentions no-login exit code 3';
};

# The exit-code contract is only worth documenting if the script honours it.
# Build and push are two separate docker invocations, so which one failed is
# simply which command returned non-zero — these two subtests run the real
# code path (no --dry-run) against the mock docker, never a daemon.
subtest 'a failing build exits 1 and never reaches the push' => sub {
    my $r = run_ocp_build(
        version     => '1.0.0',
        no_dry_run  => 1,
        docker_mock => <<'EOS',
case "$1" in
  build) echo "failed to solve: something in the Dockerfile" >&2; exit 1 ;;
esac
exit 0
EOS
    );
    is $r->{exit}, 1, 'exit code 1 is the build failure';
    like $r->{stderr}, qr/build failed/,
        'says the build failed';
    unlike $r->{docker_log}, qr/^push$/m,
        'no push was attempted after a failed build';
};

subtest 'a failing push exits 2 after a successful build' => sub {
    my $r = run_ocp_build(
        version     => '1.0.0',
        no_dry_run  => 1,
        docker_mock => <<'EOS',
case "$1" in
  push) echo "denied: requested access to the resource is denied" >&2; exit 1 ;;
esac
exit 0
EOS
    );
    is $r->{exit}, 2, 'exit code 2 is the push failure, not the build failure';
    like $r->{stderr}, qr/push failed/,
        'says the push failed';
    unlike $r->{stderr}, qr/build failed/,
        'a push failure is never reported as a build failure';
    like $r->{docker_log}, qr/^build$/m,
        'the build itself did run';
};

done_testing;
