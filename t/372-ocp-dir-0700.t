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
use OCP::Kubeconfig;
use OCP::KnownHosts;
use OCP::Password;
use OCP::Secrets;
use OCP::StateDir;
use OCP::Cmd::Apply::DeployedHash;

#
# k372: .ocp/ was made with Path::Tiny's mkpath default, 0777 less the umask
# -- 0755 under umask 022 -- by every one of its creators. The secrets in it
# are each 0600, but other local users could list it and read their names.
# The maintainer's decision: a NEW .ocp/ is made 0700, everywhere, through
# one helper (OCP::StateDir); a .ocp/ that is there keeps its mode. The
# claims:
#   1. every writer that can make .ocp/ first makes it 0700 under umask 022:
#      ocp init's step 3, generate_age_key, generate_ssh_key, the first PIN1
#      unlock on a clone (_spew_secure), decrypt_kubeconfig_to_file into
#      .ocp/, status.yaml (OCP::Config), deployed.yaml (DeployedHash), the
#      project's known_hosts, a kubeconfig merged or written (-o) into .ocp/;
#   2. each of them leaves a 0755 .ocp/ that is there at 0755 -- and so does
#      restore_age_recipient, which needs .ocp/age.key and so never makes it;
#   3. only .ocp/ gets 0700: the directories made above it, and a directory
#      written into that is not a .ocp/, keep the umask default;
#   4. 0700 whatever the umask: 077, 027 and 002 as well, and one that takes
#      the owner's own bits away (0277) -- a umask never adds a bit.
#

# Every mode below is for this umask, the common one, unless a test says.
umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{HETZNER_API_TOKEN};
delete local $ENV{KUBECONFIG};

my $PIN1 = 'pin1-k372';
my $KUBE = "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n";

plan skip_all => 'needs ssh-keygen' unless _have('ssh-keygen');

sub mode_of { sprintf '%04o', (stat $_[0])[2] & 07777 }

# A secure-mode project as the machine that made it has it.
sub origin {
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);
    OCP::Keys->new(project_dir => $dir, ocp => $ocp)->add_key(
        name => 'robo-ssh-k372', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO PRIVATE k372\n", public => 'ssh-ed25519 AAAArobo k372');
    $s->create_secrets(registry_password => 'pw-k372');
    $s->save_kubeconfig($KUBE);
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k372',
        control_planes => { provider => 'ssh', host => 'cp.k372.invalid' },
    });
    return $dir;
}

# What a clone gets: every committed file, no .ocp/.
sub clone_of {
    my ($src) = @_;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    return $dst;
}

sub prompted {
    my ($pin, $code) = @_;
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { $pin };
    return $code->();
}

# bin/ocp in $dir, nothing on STDIN; as t/215 and t/371 run it.
sub run_ocp_in {
    my ($dir, @args) = @_;
    my ($bin, $lib) = (path('bin/ocp')->absolute, path('lib')->absolute);
    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    my $out = `$^X -I'$lib' '$bin' @args 2>&1 </dev/null`;
    my $rc  = $? >> 8;
    chdir $cwd or die "chdir back: $!";
    return ($rc, $out);
}

my $origin = origin();

# The project key outside any .ocp/: under SOPS_AGE_KEY_FILE nothing caches a
# key into .ocp/, so the kubeconfig writers below are the first into it.
my $keyfile = path(tempdir(CLEANUP => 1))->child('age.key');
$origin->child('.ocp', 'age.key')->copy($keyfile);

my $apply = bless {}, 'Local::Apply';
sub Local::Apply::ocp { $ocp }

# [ name, writer, what the project needs first ]: nothing for an empty
# directory with an ocp.yaml, 'bare' for one without, 'clone' for the
# committed files of a secure-mode project, 'sops' for that and
# SOPS_AGE_KEY_FILE.
my @writers = (
    [ 'ocp init (step 3)' => sub {
          local $ENV{HETZNER_API_TOKEN} = '';
          my ($rc, $out) = run_ocp_in($_[0], qw( init --nopassword --nogit --name k372 ));
          die "ocp init exited $rc:\n$out" if $rc;
      }, 'bare' ],
    [ 'generate_age_key' => sub {
          OCP::Secrets->new(project_dir => $_[0], ocp => $ocp)->generate_age_key } ],
    [ 'generate_ssh_key' => sub {
          OCP::Secrets->new(project_dir => $_[0], ocp => $ocp)->generate_ssh_key } ],
    [ 'the first PIN1 unlock on a clone (_spew_secure)' => sub {
          my ($dir) = @_;
          prompted($PIN1, sub { OCP::Secrets->new(project_dir => $dir, ocp => $ocp)->ensure_age_key });
      }, 'clone' ],
    [ 'decrypt_kubeconfig_to_file into .ocp/' => sub {
          my ($dir) = @_;
          OCP::Secrets->new(project_dir => $dir, ocp => $ocp)
              ->decrypt_kubeconfig_to_file($dir->child('.ocp', 'kubeconfig'));
      }, 'sops' ],
    [ 'status.yaml (OCP::Config)' => sub {
          OCP::Config->new(file => $_[0]->child('ocp.yaml')->stringify)->save_status } ],
    [ 'deployed.yaml (DeployedHash)' => sub {
          my $config = OCP::Config->new(file => $_[0]->child('ocp.yaml')->stringify);
          OCP::Cmd::Apply::DeployedHash::save($apply, $config, 'k372', 'hash-k372') } ],
    [ 'known_hosts (OCP::KnownHosts)' => sub {
          OCP::KnownHosts->new(file => OCP::KnownHosts->project_file($_[0]))->ensure_dir } ],
    [ 'a kubeconfig merged into .ocp/ (OCP::Kubeconfig)' => sub {
          OCP::Kubeconfig->export(kubeconfig => $KUBE, name => 'k372',
              target => $_[0]->child('.ocp', 'config')->stringify) } ],
    [ 'ocp kubeconfig -o .ocp/kubeconfig' => sub {
          my ($rc, $out) = run_ocp_in($_[0], qw( kubeconfig -o .ocp/kubeconfig ));
          die "ocp kubeconfig exited $rc:\n$out" if $rc;
          die "no .ocp/kubeconfig:\n$out" unless -f $_[0]->child('.ocp', 'kubeconfig');
      }, 'sops' ],
);

# A project for $needs, with an ocp.yaml for the writers that read one.
sub project_for {
    my ($needs) = @_;
    $needs //= '';
    my $dir = $needs =~ /\A(?:clone|sops)\z/ ? clone_of($origin) : path(tempdir(CLEANUP => 1));
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, { name => 'k372' })
        unless $needs eq 'bare' || -f $dir->child('ocp.yaml');
    return $dir;
}

for my $w (@writers) {
    my ($name, $write, $needs) = @$w;
    local $ENV{SOPS_AGE_KEY_FILE} = "$keyfile" if ($needs // '') eq 'sops';

    subtest "$name makes .ocp/ 0700" => sub {
        my $dir = project_for($needs);
        ok !-e $dir->child('.ocp'), 'precondition: no .ocp/';
        ok eval { $write->($dir); 1 }, 'it writes' or diag $@;
        ok -d $dir->child('.ocp'), '.ocp/ made';
        is mode_of($dir->child('.ocp')), '0700', '.ocp/ is 0700';
    };

    subtest "$name leaves a 0755 .ocp/ at 0755" => sub {
        my $dir = project_for($needs);
        $dir->child('.ocp')->mkpath;
        $dir->child('.ocp')->chmod(0755);
        ok eval { $write->($dir); 1 }, 'it writes' or diag $@;
        is mode_of($dir->child('.ocp')), '0755', '.ocp/ is 0755 still';
    };
}

subtest 'restore_age_recipient leaves a 0755 .ocp/ at 0755' => sub {
    # It writes .ocp/age.pub only beside a .ocp/age.key, so it never makes
    # .ocp/ itself; what it can do is change one that is there.
    my $dir = project_for();
    $dir->child('.ocp')->mkpath;
    $dir->child('.ocp')->chmod(0755);
    $origin->child('.ocp', 'age.key')->copy($dir->child('.ocp', 'age.key'));
    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    ok eval { $s->restore_age_recipient }, 'age.pub restored' or diag $@;
    ok -f $dir->child('.ocp', 'age.pub'), '.ocp/age.pub is there';
    is mode_of($dir->child('.ocp')), '0755', '.ocp/ is 0755 still';
};

subtest 'only .ocp/ gets 0700' => sub {
    my $root = path(tempdir(CLEANUP => 1));
    OCP::StateDir::make_parent($root->child('a', 'b', '.ocp', 'status.yaml'));
    is mode_of($root->child('a')), '0755', 'a directory made above it: the default';
    is mode_of($root->child('a', 'b')), '0755', 'and the next one';
    is mode_of($root->child('a', 'b', '.ocp')), '0700', '.ocp/ itself: 0700';

    my $clone = clone_of($origin);
    local $ENV{SOPS_AGE_KEY_FILE} = "$keyfile";
    my $out = path(tempdir(CLEANUP => 1))->child('out', 'kc.yaml');
    OCP::Secrets->new(project_dir => $clone, ocp => $ocp)->decrypt_kubeconfig_to_file($out);
    ok -f $out, 'a kubeconfig decrypted elsewhere is written';
    is mode_of($out->parent), '0755', 'into a directory with the default';
    is mode_of($out), '0600', 'the file itself 0600, as always';
};

subtest '0700 whatever the umask' => sub {
    for my $mask (0077, 0027, 0002, 0277) {
        my $root = path(tempdir(CLEANUP => 1));
        my $old  = umask $mask;
        my $ok   = eval { OCP::StateDir::make_parent($root->child('.ocp', 'status.yaml')); 1 };
        my $err  = $@;
        umask $old;
        ok $ok, sprintf('umask %04o: made', $mask) or diag $err;
        is mode_of($root->child('.ocp')), '0700', sprintf('umask %04o: .ocp/ is 0700', $mask);
    }
};

sub _have {
    my ($cmd) = @_;
    return system("command -v $cmd >/dev/null 2>&1") == 0;
}

done_testing;
