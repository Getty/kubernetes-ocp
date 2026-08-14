#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use Path::Tiny qw(path);
#
# share/bin/ocp-build-image builds and (by default) pushes the OCP image,
# multi-arch, idempotent, CI-friendly. The only thing this test actually
# exercises is the script's command line — it must not require a running
# docker daemon, a logged-in registry, or even `docker` in $PATH, because
# those are precisely the things CI wants to assert are *not* needed.
#
# Everything below runs the script with --dry-run, so docker is never
# invoked. The `mock docker` further down proves that point by recording
# every invocation: in --dry-run mode the log stays empty.
#
my $root   = path(__FILE__)->parent->parent->absolute;
my $script = $root->child('share/bin/ocp-build-image');
plan skip_all => 'share/bin/ocp-build-image not found' unless -f $script;

# Run the script in a fresh sandbox and return (exit, stdout, stderr,
# whether the mock docker was touched). Every invocation is forced into
# --dry-run mode so docker is never actually called — the mock at the
# front of PATH exists only to catch and log any invocation that slips
# through, so the `--dry-run` claim has a witness, not just trust.
sub run_ocp_build {
    my (%opts) = @_;
    $opts{args} = [@{$opts{args} // []}, '--dry-run'];
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
    # only records its argv; the script must not call it under --dry-run.
    my $mockbin  = path($cwd)->child('mockbin');
    my $mock_log = $mockbin->child('.docker.log');
    $mockbin->mkpath;
    $mock_log->spew('');
    $mockbin->child('docker')->spew(<<'EOS');
#!/bin/sh
printf '%s\n' "$0" "$@" >> "$(dirname "$0")/.docker.log"
EOS
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
        'latest tag is on the docker buildx build line';
    like $r->{stdout}, qr/-t 'raudssus\/ocp:1\.2\.3'/,
        'version tag is on the docker buildx build line';
    unlike $r->{stdout}, qr/^other\/x/m,
        'no leaked default-name override';
};

subtest 'platforms default to linux/amd64 and linux/arm64' => sub {
    my $r = run_ocp_build(version => '0.0.1');
    like $r->{stdout}, qr/--platform 'linux\/amd64,linux\/arm64'/,
        'multi-arch comma-separated platforms (not space-separated)';
    like $r->{stdout}, qr/\bamd64\b/, 'amd64 is in the platforms list';
    like $r->{stdout}, qr/\barm64\b/, 'arm64 is in the platforms list';
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

subtest '--no-push strips --push from the buildx command' => sub {
    my $r = run_ocp_build(
        version => '1.0.0',
        args    => ['--no-push'],
    );
    is $r->{exit}, 0, 'still exits 0';
    unlike $r->{stdout}, qr/--push\b/,
        'no --push anywhere in the printed command';
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
    like $r->{stdout}, qr/\[dry-run\] docker buildx build/,
        'a buildx command is printed under [dry-run] prefix';
    like $r->{stdout}, qr/\[dry-run\] docker buildx.*create/,
        'a builder-create command is printed under [dry-run] prefix (as part of the inspect-or-create conditional)';
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

done_testing;
