#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use Cwd qw( getcwd );

use lib 'lib';

use OCP;
use OCP::Config;
use OCP::Keys;
use OCP::KnownHosts;
use OCP::Password;
use OCP::Secrets;
use OCP::Cmd::Apply::DeployedHash;

#
# k371: only `ocp init` wrote .ocp/.gitignore. A clone's .ocp/ is made by
# whatever writes into it first -- since k360 the first PIN1 unlock, or
# status.yaml, known_hosts, deployed.yaml -- and got none, so keeping the
# plaintext age key out of git rested on the project's own .gitignore alone
# (k215 is why that is not enough: a project in a subdirectory of another
# repository, a .gitignore lost). The claims:
#   1. a clone's first unlock gives its .ocp/ the .gitignore init writes, with
#      init's content, and git sees nothing under .ocp/;
#   2. every writer that can make .ocp/ first does the same: the read unlock
#      (k370), the write that caches the key (k360), generate_age_key,
#      generate_ssh_key, status.yaml, deployed.yaml, the project's
#      known_hosts;
#   3. a .gitignore that is there is never replaced; a .ocp/ without one (made
#      before this) gains one on the next write;
#   4. only a .ocp/ gets one: a kubeconfig decrypted elsewhere does not;
#   5. ocp init writes it with the same helper, says so, and writes it back on
#      a project that is set up and has lost it -- where init's own write is
#      the only one, since nothing else lands in .ocp/ on that run.
#

umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{HETZNER_API_TOKEN};

my $PIN1 = 'pin1-k371';
my $INIT = "# Decrypted OCP state - never commit (written by ocp init)\n*\n";

plan skip_all => 'needs git and ssh-keygen'
    unless _have('git') && _have('ssh-keygen');

# A secure-mode project as the machine that made it has it.
sub origin {
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);
    OCP::Keys->new(project_dir => $dir, ocp => $ocp)->add_key(
        name => 'robo-ssh-k371', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO PRIVATE k371\n", public => 'ssh-ed25519 AAAArobo k371');
    $s->create_secrets(registry_password => 'pw-k371');
    $s->save_kubeconfig("apiVersion: v1\nkind: Config\nclusters: []\n");
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k371',
        control_planes => { provider => 'ssh', host => 'cp.k371.invalid' },
    });
    return $dir;
}

# What a clone gets: every committed file, no .ocp/ -- into $dst when given.
sub clone_of {
    my ($src, $dst) = @_;
    $dst //= path(tempdir(CLEANUP => 1));
    $dst->mkpath;
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    return $dst;
}

sub prompted {
    my ($pin, $code) = @_;
    my @asked;
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { push @asked, $_[0]; $pin };
    $code->();
    return \@asked;
}

sub git_in {
    my ($dir, $cmd) = @_;
    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    my $out = `git $cmd 2>/dev/null`;
    chdir $cwd or die "chdir back: $!";
    return $out;
}

sub ignore_of { my $f = $_[0]->child('.ocp', '.gitignore'); -f $f ? $f->slurp : undef }

my $origin = origin();

subtest "a clone's first unlock: .ocp/ ignores itself, and git sees nothing in it" => sub {
    # The project in a subdirectory of a repository with no .gitignore of its
    # own (k215's case): only .ocp/.gitignore stands between the key and git.
    my $root = path(tempdir(CLEANUP => 1));
    git_in($root, 'init --quiet');
    my $clone = clone_of($origin, $root->child('cluster'));
    ok !-e $clone->child('.ocp'), 'precondition: no .ocp/';

    my $asked = prompted($PIN1, sub {
        ok eval { OCP::Secrets->new(project_dir => $clone, ocp => $ocp)->ensure_age_key; 1 },
            'ensure_age_key unlocks' or diag $@;
    });
    is_deeply $asked, ['Enter PIN1 (cluster access): '], 'PIN1 asked';
    ok -f $clone->child('.ocp', 'age.key'), 'the key is in .ocp/';
    is ignore_of($clone), $INIT, ".ocp/.gitignore is there, with init's content";

    my $status = git_in($root, 'status --porcelain --untracked-files=all');
    unlike $status, qr{\.ocp/}, 'git status shows nothing under .ocp/' or diag $status;
    like $status, qr{cluster/keys\.yaml}, 'while the committed files are there to commit';
};

# Every writer that can be the first into .ocp/, each on a project with none.
my $apply = bless {}, 'Local::Apply';
sub Local::Apply::ocp { $ocp }

my @writers = (
    [ 'the read unlock (k370): read_kubeconfig' => sub {
          my ($dir) = @_;
          prompted($PIN1, sub { OCP::Secrets->new(project_dir => $dir, ocp => $ocp)->read_kubeconfig });
      }, 1 ],
    [ 'the write that caches the key (_spew_secure, k360)' => sub {
          my ($dir) = @_;
          OCP::Secrets->new(project_dir => $dir, ocp => $ocp)
              ->_spew_secure($dir->child('.ocp', 'age.key'), "AGE-SECRET-KEY-1K371\n");
      } ],
    [ 'generate_age_key' => sub {
          OCP::Secrets->new(project_dir => $_[0], ocp => $ocp)->generate_age_key } ],
    [ 'generate_ssh_key' => sub {
          OCP::Secrets->new(project_dir => $_[0], ocp => $ocp)->generate_ssh_key } ],
    [ 'status.yaml (OCP::Config)' => sub {
          OCP::Config->new(file => $_[0]->child('ocp.yaml')->stringify)->save_status } ],
    [ 'deployed.yaml (DeployedHash)' => sub {
          my $config = OCP::Config->new(file => $_[0]->child('ocp.yaml')->stringify);
          OCP::Cmd::Apply::DeployedHash::save($apply, $config, 'k371', 'hash-k371') } ],
    [ 'known_hosts (OCP::KnownHosts)' => sub {
          OCP::KnownHosts->new(file => OCP::KnownHosts->project_file($_[0]))->ensure_dir } ],
);

for my $w (@writers) {
    my ($name, $write, $clone) = @$w;
    subtest "$name makes .ocp/ with its .gitignore" => sub {
        my $dir = $clone ? clone_of($origin) : path(tempdir(CLEANUP => 1));
        $ocp->dump_file($dir->child('ocp.yaml')->stringify, { name => 'k371' })
            unless -f $dir->child('ocp.yaml');
        ok !-e $dir->child('.ocp'), 'precondition: no .ocp/';
        ok eval { $write->($dir); 1 }, 'it writes' or diag $@;
        ok -d $dir->child('.ocp'), '.ocp/ made';
        is ignore_of($dir), $INIT, ".ocp/.gitignore, init's content";
    };
}

subtest 'a .gitignore that is there is never replaced' => sub {
    my $clone = clone_of($origin);
    $clone->child('.ocp')->mkpath;
    $clone->child('.ocp', '.gitignore')->spew("*\n# mine\n");
    prompted($PIN1, sub { OCP::Secrets->new(project_dir => $clone, ocp => $ocp)->ensure_age_key });
    ok -f $clone->child('.ocp', 'age.key'), 'the key is in .ocp/';
    is ignore_of($clone), "*\n# mine\n", 'the .gitignore is as it was';

    my $old = clone_of($origin);
    $old->child('.ocp')->mkpath;
    $old->child('.ocp', 'status.yaml')->spew("phase: x\n");
    prompted($PIN1, sub { OCP::Secrets->new(project_dir => $old, ocp => $ocp)->ensure_age_key });
    is ignore_of($old), $INIT, 'a .ocp/ made before, without one, gains it on the next write';
};

subtest 'only a .ocp/ gets one' => sub {
    my $clone = clone_of($origin);
    prompted($PIN1, sub { OCP::Secrets->new(project_dir => $clone, ocp => $ocp)->ensure_age_key });
    my $out = path(tempdir(CLEANUP => 1))->child('out', 'kc.yaml');
    OCP::Secrets->new(project_dir => $clone, ocp => $ocp)->decrypt_kubeconfig_to_file($out);
    ok -f $out, 'the kubeconfig is written';
    ok !-e $out->parent->child('.gitignore'), 'and no .gitignore next to it';
};

# As t/215 runs it: bin/ocp init, dev mode, no git, no token, nothing on STDIN.
sub run_init_in {
    my ($dir, @args) = @_;
    my ($bin, $lib) = (path('bin/ocp')->absolute, path('lib')->absolute);
    my $cwd = getcwd();
    local $ENV{HETZNER_API_TOKEN} = '';
    chdir $dir or die "chdir: $!";
    my $out = `$^X -I'$lib' '$bin' init --nopassword --nogit @args 2>&1 </dev/null`;
    my $rc  = $? >> 8;
    chdir $cwd or die "chdir back: $!";
    return ($rc, $out);
}

subtest 'ocp init writes it, and writes it back on a set-up project that lost it' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    my ($rc, $out) = run_init_in($dir, '--name', 'k371');
    is $rc, 0, 'init succeeded' or diag $out;
    like $out, qr{^\[ok\] Created \.ocp/\.gitignore$}m, 'and says it wrote .ocp/.gitignore';
    is ignore_of($dir), $INIT, "init's content";

    my $key = $dir->child('.ocp', 'age.key')->slurp;
    $dir->child('.ocp', '.gitignore')->remove;
    ($rc, $out) = run_init_in($dir, '--name', 'k371');
    is $rc, 0, 'init again succeeded' or diag $out;
    is $dir->child('.ocp', 'age.key')->slurp, $key, 'the same project: its key kept';
    is ignore_of($dir), $INIT, 'the .gitignore is back';
    like $out, qr{^\[ok\] Created \.ocp/\.gitignore$}m, 'and init says so';
};

sub _have {
    my ($cmd) = @_;
    return system("command -v $cmd >/dev/null 2>&1") == 0;
}

done_testing;
