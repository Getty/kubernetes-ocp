#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use Cwd qw(getcwd);
use FindBin;

# k215: `ocp init --nogit` used to skip the .gitignore together with git init.
# An OCP project living in a subdirectory of another repository (citiai-core/
# cluster/) then had .ocp/ -- the plaintext age.key and the decrypted SSH keys
# -- unignored in the surrounding repository, and the next `git add .` there
# committed them.
#
# The claim of this test: whatever git situation init finds, nothing under
# .ocp/ is visible to git. Asserted with git itself (check-ignore, status),
# not with a regex over .gitignore, because the parent repo's rules are what
# decides.

my $BIN = "$FindBin::Bin/../bin/ocp";
my $LIB = "$FindBin::Bin/../lib";

plan skip_all => 'needs git and ssh-keygen'
    unless _have('git') && _have('ssh-keygen');

sub run_init_in {
    my ($dir, @args) = @_;
    my $cwd = getcwd();
    local $ENV{HETZNER_API_TOKEN} = '';
    chdir $dir or die "chdir: $!";
    my $out = `$^X -I'$LIB' '$BIN' init --nopassword @args 2>&1`;
    my $rc  = $? >> 8;
    chdir $cwd or die "chdir back: $!";
    return ($rc, $out);
}

sub git_in {
    my ($dir, $cmd) = @_;
    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    my $out = `git $cmd 2>/dev/null`;
    chdir $cwd or die "chdir back: $!";
    return $out;
}

sub parent_repo {
    my $root = path(tempdir(CLEANUP => 1));
    git_in($root, 'init --quiet');
    my $project = $root->child('cluster');
    $project->mkpath;
    return ($root, $project);
}

subtest '--nogit in a fresh directory still writes a .gitignore with .ocp/' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    my ($rc, $out) = run_init_in($dir, '--nogit', '--name', 'bare');
    is $rc, 0, 'init succeeded' or diag $out;

    ok !-d $dir->child('.git'), '--nogit still does not git init';
    ok -f $dir->child('.gitignore'), '.gitignore written anyway';
    like _slurp($dir->child('.gitignore')), qr{^\.ocp/$}m, 'and it ignores .ocp/';
    ok -f $dir->child('.ocp', '.gitignore'), '.ocp/ carries its own .gitignore';
    like _slurp($dir->child('.ocp', '.gitignore')), qr{^\*$}m,
        'which ignores everything inside .ocp/';
};

subtest '--nogit in a subdirectory of an existing repo keeps .ocp/ out of it' => sub {
    my ($root, $project) = parent_repo();
    my ($rc, $out) = run_init_in($project, '--nogit', '--name', 'sub');
    is $rc, 0, 'init succeeded' or diag $out;

    ok -f $project->child('.ocp', 'age.key'), 'init wrote the plaintext age key'
        or diag $out;

    like git_in($root, 'check-ignore cluster/.ocp/age.key'),
        qr{cluster/\.ocp/age\.key}, 'the parent repo ignores .ocp/age.key';

    my $status = git_in($root, 'status --porcelain --untracked-files=all');
    unlike $status, qr{\.ocp/}, 'git status of the parent shows nothing under .ocp/'
        or diag $status;
    like $status, qr{cluster/ocp\.yaml}, 'while ocp.yaml is visible to commit';
};

subtest 'even with the project .gitignore gone, .ocp/ ignores itself' => sub {
    my ($root, $project) = parent_repo();
    my ($rc, $out) = run_init_in($project, '--nogit', '--name', 'gone');
    is $rc, 0, 'init succeeded' or diag $out;

    $project->child('.gitignore')->remove;
    my $status = git_in($root, 'status --porcelain --untracked-files=all');
    unlike $status, qr{\.ocp/}, 'nothing under .ocp/ shows up' or diag $status;
};

subtest 'an existing .ocp/ without a .gitignore gains one on the next init' => sub {
    my ($root, $project) = parent_repo();
    $project->child('.ocp')->mkpath;
    $project->child('.ocp', 'status.yaml')->spew("phase: x\n");

    my ($rc, $out) = run_init_in($project, '--nogit', '--name', 'old');
    is $rc, 0, 'init succeeded' or diag $out;
    ok -f $project->child('.ocp', '.gitignore'), '.ocp/.gitignore added';

    my $status = git_in($root, 'status --porcelain --untracked-files=all');
    unlike $status, qr{\.ocp/}, 'nothing under .ocp/ shows up' or diag $status;
};

subtest 'without --nogit an existing .ocp/.gitignore is left alone' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('.ocp', '.gitignore')->spew("*\n# mine\n");

    my ($rc, $out) = run_init_in($dir, '--name', 'kept');
    is $rc, 0, 'init succeeded' or diag $out;
    like $dir->child('.ocp', '.gitignore')->slurp, qr/# mine/, 'not overwritten';
};

sub _slurp { -f $_[0] ? $_[0]->slurp : '' }

sub _have {
    my ($cmd) = @_;
    return system("command -v $cmd >/dev/null 2>&1") == 0;
}

done_testing;
