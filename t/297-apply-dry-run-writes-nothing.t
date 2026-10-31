#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Digest::MD5 ();
use File::Temp qw( tempdir );
use FindBin;
use Path::Tiny qw( path );

use lib 'lib';
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

my $bin = "$FindBin::Bin/../bin/ocp";
my $lib = "$FindBin::Bin/../lib";

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
sub ocp_in {
    my ($dir, @args) = @_;
    my $io  = path(tempdir(CLEANUP => 1));
    my ($out, $err) = map { $io->child($_) } qw( out err );
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        delete local $ENV{SOPS_AGE_KEY_FILE};
        open STDIN,  '<', '/dev/null' or die;
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

done_testing;
