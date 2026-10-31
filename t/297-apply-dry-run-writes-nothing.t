#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Digest::MD5 ();
use File::Temp qw( tempdir );
use FindBin;
use Path::Tiny qw( path );

use lib 'lib';
use OCP;
use OCP::Keys;
use OCP::Secrets;

#
# k297: on a fresh dev-mode project `ocp apply --dry-run` wrote .ocp/age.key
# (and .ocp/age.pub) before it stopped, under a banner that ends "[Dry run -
# no changes made]". The claims:
#   1. a dry run leaves the project directory as it found it: the same files,
#      .ocp/ and every dotfile included, with the same content -- no age key,
#      and none of what a first real run creates (secrets.yaml, keys.yaml,
#      kubeconfig.yaml);
#   2. it says on STDOUT that a real run would generate the age key, and gets
#      to its own end;
#   3. a project that has its age key already is left alone as before, and a
#      dry run that stops on a missing SSH key has written nothing either.
#
# k349: the same for a secure-mode project, PINs over --pins-stdin. A clone
# has keys.yaml, secrets.yaml and age.key.enc, and no .ocp/ (gitignored); the
# one way to the project key was ensure_age_key, which caches it -- PIN1,
# then .ocp/age.key and .ocp/age.pub. On a clone without .ocp/ that died
# after PIN1; since k360 makes .ocp/, it exits 0 and leaves both behind.
# The claims:
#   4. PIN1 opens the project key into memory and PIN2 the admin key with
#      it; the dry run gets to its end, and the project directory is as it
#      was -- no .ocp/ on a clone without one, no age.key or age.pub in an
#      .ocp/ that holds other local state;
#   5. a checkout with .ocp/age.key and no .ocp/age.pub asks no PIN1, and a
#      dry run does not restore age.pub;
#   6. a wrong PIN1 is refused as before: no PIN2 asked, nothing written.
#

my $bin = "$FindBin::Bin/../bin/ocp";
my $lib = "$FindBin::Bin/../lib";

local @ARGV = ();
my $ocp = OCP->new;    # load/dump for the secure-mode fixture

my $PIN1 = 'pin1-k349';
my $PIN2 = 'pin2-k349';

# A dev-mode project as a first `ocp apply` finds it: ocp.yaml and, unless
# told otherwise, the bootstrap key in .ocp/. No keys.yaml (that is dev
# mode), no secrets.yaml, no kubeconfig.yaml, no age key.
sub project {
    my (%o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8(<<'YAML');
name: k297
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: cp.k297.test
YAML
    unless ($o{no_ssh_key}) {
        $dir->child('.ocp')->mkpath;
        $dir->child('.ocp', 'id_ed25519')->spew("FAKE PRIVATE KEY\n");
        $dir->child('.ocp', 'id_ed25519.pub')->spew("ssh-ed25519 AAAAFAKE k297\n");
    }
    OCP::Secrets->new(project_dir => $dir)->generate_age_key if $o{age_key};
    return $dir;
}

# k349: a secure-mode project as the machine that made it has it -- the
# project key in .ocp/ and behind PIN1 in age.key.enc, an admin key (PIN2)
# and a robo key in keys.yaml, a token in secrets.yaml. No kubeconfig.yaml:
# no cluster yet, so the dry run takes the first apply's path.
sub secure_origin {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8(<<'YAML');
name: k349
kubernetes:
  dist: k3s
control_planes:
  provider: ssh
  host: cp.k349.test
YAML
    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);

    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    $keys->add_key(name => 'admin-ssh-k349', type => 'ssh_ed25519', purpose => 'admin',
        private => "ADMIN PRIVATE k349\n", public => 'ssh-ed25519 AAAAadmin k349', pin2 => $PIN2);
    $keys->add_key(name => 'robo-ssh-k349', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO PRIVATE k349\n", public => 'ssh-ed25519 AAAArobo k349');

    $s->create_secrets(hetzner_token => 'token-k349');
    return $dir;
}

# What a clone of it gets: every committed file, no .ocp/.
sub clone_of {
    my ($src) = @_;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    return $dst;
}

# Every path under $dir, directories too, with the digest of each file:
# what a write anywhere in the project changes.
sub listing {
    my ($dir) = @_;
    my %seen;
    $dir->visit(sub {
        my ($p) = @_;
        $seen{ $p->relative($dir)->stringify } = -d $p ? 'dir' : Digest::MD5::md5_hex($p->slurp_raw);
    }, { recurse => 1 });
    return \%seen;
}

# `ocp @args` in $dir as a user runs it, no terminal, HOME the project itself
# so that a write to HOME shows up in the listing: (stdout, stderr, exit).
# A leading { stdin => TEXT } is fed to it -- the PINs for --pins-stdin;
# otherwise STDIN is /dev/null.
sub ocp_in {
    my ($dir, @args) = @_;
    my $stdin = ref $args[0] eq 'HASH' ? shift(@args)->{stdin} : undef;
    my $io  = path(tempdir(CLEANUP => 1));
    my ($in, $out, $err) = map { $io->child($_) } qw( in out err );
    $in->spew_utf8($stdin) if defined $stdin;
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        delete local $ENV{SOPS_AGE_KEY_FILE};
        open STDIN,  '<', defined $stdin ? "$in" : '/dev/null' or die;
        open STDOUT, '>', "$out"      or die;
        open STDERR, '>', "$err"      or die;
        exec $^X, "-I$lib", $bin, @args or die "exec: $!";
    }
    waitpid $pid, 0;
    return ($out->slurp_utf8, $err->slurp_utf8, $? >> 8);
}

subtest 'a fresh dev-mode project: the dry run writes nothing and says what a real run would' => sub {
    my $dir    = project();
    my $before = listing($dir);
    ok !-e $dir->child('.ocp', 'age.key'), 'precondition: no age key';

    my ($out, $err, $rc) = ocp_in($dir, 'apply', '--dry-run');

    is $rc, 0, 'exit 0' or diag $err;
    is_deeply listing($dir), $before, 'the project directory, .ocp/ included, as it was'
        or diag explain listing($dir);
    ok !-e $dir->child('.ocp', $_), "no .ocp/$_" for qw( age.key age.pub );
    ok !-e $dir->child($_), "no $_" for qw( secrets.yaml keys.yaml kubeconfig.yaml );

    like $out, qr/^\[\.\.\] No age key in \.ocp\/ yet: a real run generates one for kubeconfig encryption$/m,
        'STDOUT: a real run would generate the age key';
    unlike $out, qr/Generat(?:ing|ed) age key/, 'and none is generated';
    like $out, qr/^\[ok\] SSH key loaded \(dev mode\)$/m, 'the run goes on';
    like $out, qr/\[Dry run - no changes made\]\n\z/, 'to its own end';
    is $err, '', 'nothing on STDERR';
};

subtest 'a dev-mode project with its age key: left alone, as before' => sub {
    my $dir    = project(age_key => 1);
    my $before = listing($dir);

    my ($out, $err, $rc) = ocp_in($dir, 'apply', '--dry-run');

    is $rc, 0, 'exit 0' or diag $err;
    is_deeply listing($dir), $before, 'the project directory as it was';
    unlike $out, qr/age key/i, 'no word about the age key: there is one';
    like $out, qr/\[Dry run - no changes made\]\n\z/, 'to its end';
};

subtest 'no SSH key: the dry run stops on it, having written nothing' => sub {
    my $dir    = project(no_ssh_key => 1);
    my $before = listing($dir);

    my ($out, $err, $rc) = ocp_in($dir, 'apply', '--dry-run');

    isnt $rc, 0, 'exit non-zero';
    like $err, qr/SSH private key not found/, 'on the missing key';
    is_deeply listing($dir), $before, 'and the project directory as it was: no .ocp/, no age key';
};

my $SECURE = secure_origin();

# k349 (4): a clone without .ocp/, and one whose .ocp/ holds local state but
# no age key -- the second is where ensure_age_key's writes land and stay.
for my $case (
    [ 'without .ocp/' => sub { } ],
    [ 'with an .ocp/ that holds no age key' => sub {
        $_[0]->child('.ocp')->mkpath;
        $_[0]->child('.ocp', 'known_hosts')->spew("cp.k349.test ssh-ed25519 AAAAhost\n");
    } ],
) {
    my ($what, $setup) = @$case;
    subtest "k349: a secure-mode clone $what -- PIN1 into memory, the directory as it was" => sub {
        my $dir = clone_of($SECURE);
        $setup->($dir);
        my $before = listing($dir);
        ok !-e $dir->child('.ocp', $_), "precondition: no .ocp/$_" for qw( age.key age.pub );

        my ($out, $err, $rc) = ocp_in($dir, { stdin => "$PIN1\n$PIN2\n" },
            'apply', '--dry-run', '--pins-stdin');

        is $rc, 0, 'exit 0' or diag $err;
        is_deeply listing($dir), $before, 'the project directory, .ocp/ included, as it was'
            or diag explain listing($dir);
        ok !-e $dir->child('.ocp', $_), "no .ocp/$_" for qw( age.key age.pub );
        is $err, "Enter PIN1 (cluster access): \nEnter PIN2 (admin-key): \n",
            'STDERR: PIN1, then PIN2, and nothing else';
        like $out, qr/^\[ok\] Secrets unlocked$/m, 'PIN1 opened the project key';
        like $out, qr/^\[ok\] admin-key decrypted: admin-ssh-k349$/m,
            'and PIN2 the admin key, read with it';
        like $out, qr/\[Dry run - no changes made\]\n\z/, 'to its own end';
    };
}

subtest 'k349: a checkout with .ocp/age.key and no .ocp/age.pub -- no PIN1, age.pub not restored' => sub {
    my $dir = clone_of($SECURE);
    $dir->child('.ocp')->mkpath;
    $SECURE->child('.ocp', 'age.key')->copy($dir->child('.ocp', 'age.key'));
    my $before = listing($dir);
    ok !-e $dir->child('.ocp', 'age.pub'), 'precondition: no .ocp/age.pub';

    my ($out, $err, $rc) = ocp_in($dir, { stdin => "$PIN2\n" },
        'apply', '--dry-run', '--pins-stdin');

    is $rc, 0, 'exit 0' or diag $err;
    is_deeply listing($dir), $before, 'the project directory as it was'
        or diag explain listing($dir);
    ok !-e $dir->child('.ocp', 'age.pub'), 'no .ocp/age.pub';
    is $err, "Enter PIN2 (admin-key): \n", 'STDERR: PIN2 alone -- the key on disk needs no PIN1';
    like $out, qr/^\[ok\] admin-key decrypted: admin-ssh-k349$/m, 'the admin key read';
    like $out, qr/\[Dry run - no changes made\]\n\z/, 'to its own end';
};

subtest 'k349: a wrong PIN1 is refused -- no PIN2 asked, nothing written' => sub {
    my $dir    = clone_of($SECURE);
    my $before = listing($dir);

    my ($out, $err, $rc) = ocp_in($dir, { stdin => "wrong-k349\n$PIN2\n" },
        'apply', '--dry-run', '--pins-stdin');

    isnt $rc, 0, 'exit non-zero';
    like $err, qr/\AEnter PIN1 \(cluster access\): \nError: Decryption failed\. Wrong password\?/,
        'refused on PIN1';
    unlike $err, qr/PIN2/, 'PIN2 not asked';
    unlike $out, qr/Secrets unlocked|Dry run - no changes made/, 'the run went no further';
    is_deeply listing($dir), $before, 'the project directory as it was: no .ocp/'
        or diag explain listing($dir);
};

done_testing;
