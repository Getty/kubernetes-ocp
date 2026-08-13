#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use Cwd qw(getcwd);
use FindBin;

use OCP::Cmd::Init;

# `ocp init` is the one command that has to work before anything else does,
# and it is the one command no test ever ran. Three things had drifted:
#
#   - the provider default was ssh while the option help said hetzner, so a
#     bare `ocp init` died on a missing --host instead of scaffolding
#   - --single was declared, referenced nowhere, and passed by xt/smoke.sh
#   - the generated .gitignore still carried .kube/, from back when the
#     kubeconfig was written into the project
#
# The last one is the dangerous shape: an over-broad entry here silently
# keeps an encrypted file out of the repo, and that only surfaces when a
# colleague clones the project and cannot reach the cluster. Hence the
# git check-ignore assertion below rather than a regex over the text.

my $BIN = "$FindBin::Bin/../bin/ocp";
my $LIB = "$FindBin::Bin/../lib";

# Run bin/ocp in a fresh project directory. Always --nopassword: the default
# path prompts for PIN1/PIN2 and would hang the suite.
sub run_init {
    my (@args) = @_;
    my $dir = tempdir(CLEANUP => 1);
    my $cwd = getcwd();

    local $ENV{HETZNER_API_TOKEN} = '';    # never inherit a real token

    chdir $dir or die "chdir: $!";
    my $out = `$^X -I'$LIB' '$BIN' init --nopassword @args 2>&1`;
    my $rc  = $? >> 8;
    chdir $cwd or die "chdir back: $!";

    return ($rc, $out, path($dir));
}

subtest 'the default provider is the one the option help advertises' => sub {
    is(OCP::Cmd::Init->new->_provider, 'hetzner',
        'no --provider means hetzner');
    is(OCP::Cmd::Init->new(provider => 'ssh')->_provider, 'ssh',
        '--provider still wins');
    is(OCP::Cmd::Init->new(hetzner => 1)->_provider, 'hetzner',
        '--hetzner is about the token, not about overriding the provider');

    my %declared = OCP::Cmd::Init->_options_data;
    like $declared{provider}{doc}, qr/hetzner \(default\)/,
        'the option help names hetzner as the default';
};

subtest 'a bare ocp init scaffolds instead of dying' => sub {
    plan skip_all => 'needs ssh-keygen' unless _have('ssh-keygen');

    my ($rc, $out, $dir) = run_init('--nogit', '--name', 'bare');

    is $rc, 0, 'exits 0 with no flags but --name'
        or diag $out;

    my $spec = $dir->child('ocp.yaml')->slurp;
    like $spec, qr/provider: hetzner/, 'ocp.yaml names the hetzner provider';
    like $out, qr/API Token Required/,
        'and says a token is still missing rather than leaving it for apply';
};

subtest 'ssh without a host names every way out' => sub {
    plan skip_all => 'needs ssh-keygen' unless _have('ssh-keygen');

    my ($rc, $out) = run_init('--nogit', '--provider', 'ssh');

    is $rc, 1, '--provider ssh without --host still fails';
    like $out, qr/--host yourserver\.com/, 'points at --host';
    like $out, qr/--provider local/,       'offers local';
    like $out, qr/the default provider/,   'offers the hetzner default';
};

subtest 'the generated .gitignore keeps encrypted files committable' => sub {
    plan skip_all => 'needs git and ssh-keygen'
        unless _have('git') && _have('ssh-keygen');

    my ($rc, $out, $dir) = run_init('--name', 'ignored');
    is $rc, 0, 'init succeeded' or diag $out;

    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";

    # check-ignore echoes back only the paths git would ignore.
    my @encrypted = qw(keys.yaml secrets.yaml age.key.enc kubeconfig.yaml);
    my $swallowed = `git check-ignore @encrypted 2>/dev/null`;
    my $state     = `git check-ignore .ocp/age.key 2>/dev/null`;

    chdir $cwd or die "chdir back: $!";

    is $swallowed, '', 'no encrypted file is ignored — all four must reach git';
    like $state, qr{\.ocp/age\.key}, 'decrypted state under .ocp/ stays out';

    my $content = $dir->child('.gitignore')->slurp;
    unlike $content, qr{\.kube/}, 'no .kube/ — nothing writes a project-local one';
};

subtest 'an existing .gitignore only gains .ocp/' => sub {
    plan skip_all => 'needs ssh-keygen' unless _have('ssh-keygen');

    my $dir = tempdir(CLEANUP => 1);
    path($dir)->child('.gitignore')->spew("*.log\n");

    my $cwd = getcwd();
    local $ENV{HETZNER_API_TOKEN} = '';
    chdir $dir or die "chdir: $!";
    my $out = `$^X -I'$LIB' '$BIN' init --nopassword --name kept 2>&1`;
    chdir $cwd or die "chdir back: $!";

    my $content = path($dir)->child('.gitignore')->slurp;
    like $content, qr/^\*\.log$/m, 'what was there is left alone' or diag $out;
    like $content, qr{^\.ocp/$}m,  '.ocp/ appended';
    unlike $content, qr{\.kube/},  '.kube/ is not appended either';
};

subtest '--single is gone, and so is its caller' => sub {
    ok(!OCP::Cmd::Init->can('single'), 'the dead option is removed');

    my %declared = OCP::Cmd::Init->_options_data;
    ok(!exists $declared{single}, 'and it is no longer declared as an option');

    # A fresh init writes one control plane and no workers, which is what
    # OCP::Config::single_node already derives — the flag had nothing to set.
    my $smoke = path("$FindBin::Bin/../xt/smoke.sh");
  SKIP: {
        skip 'no xt/smoke.sh', 1 unless -f $smoke;
        unlike $smoke->slurp, qr/--single/,
            'xt/smoke.sh no longer passes it (MooX::Options would reject it)';
    }
};

sub _have {
    my ($cmd) = @_;
    return system("command -v $cmd >/dev/null 2>&1") == 0;
}

done_testing;
