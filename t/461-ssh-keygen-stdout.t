#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use Cwd qw( getcwd );

use lib 'lib';

use OCP;
use OCP::Cmd::Init;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

#
# k461: ssh-keygen prints "Generating public/private ed25519 key pair.", the
# file names, the fingerprint and the randomart on STDOUT, and OCP ran it with
# STDOUT inherited -- so every SSH key OCP made (ocp init, ocp keys secure)
# dropped that into the command's STDOUT, against the output-channel rule.
#
# The claims, with STDOUT caught at the file descriptor (a child writes to
# fd 1, not to Perl's selected handle):
#   1. OCP::Secrets::generate_ssh_key writes nothing to STDOUT, and the key
#      pair is there;
#   2. OCP::Keys::add_cluster_keys -- the pair ocp init and ocp keys secure
#      make -- writes nothing to STDOUT;
#   3. a secure-mode `ocp init` prints its own narrative and none of
#      ssh-keygen's;
#   4. a failing ssh-keygen still writes nothing to STDOUT; what it said
#      is on STDERR, and the run dies by name.
#

plan skip_all => 'needs ssh-keygen'
    unless system('command -v ssh-keygen >/dev/null 2>&1') == 0;

umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{HETZNER_API_TOKEN};

my $SSH_KEYGEN = qr/randomart|key fingerprint|identification has been saved|public\/private/i;

# Run $code with fd 1 on a file; returns (what landed there, the result, $@).
sub fd_stdout {
    my ($code) = @_;
    my $file = path(tempdir(CLEANUP => 1))->child('stdout');
    open my $save, '>&', \*STDOUT or die "dup STDOUT: $!";
    open STDOUT, '>', "$file"     or die "STDOUT to file: $!";
    my @r    = eval { $code->() };
    my $died = $@;
    STDOUT->flush;
    open STDOUT, '>&', $save or die "restore STDOUT: $!";
    return ($file->slurp, \@r, $died);
}

subtest 'generate_ssh_key' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    my ($out, $r, $died) = fd_stdout(sub { $s->generate_ssh_key });
    is $died, '', 'no error';
    is $out, '', 'nothing on STDOUT';
    ok -f $r->[0]{private_key}, 'the private half is there';
    ok -f $r->[0]{public_key},  'the public half is there';
};

subtest 'add_cluster_keys (ocp init, ocp keys secure)' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    OCP::Secrets->new(project_dir => $dir, ocp => $ocp)->generate_age_key;
    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    my ($out, $r, $died) = fd_stdout(sub { $keys->add_cluster_keys(pin2 => 'pin2-k461') });
    is $died, '', 'no error';
    is $out, '', 'nothing on STDOUT';
    ok $r->[0]{admin} && $r->[0]{automation}, 'both keys made';
};

subtest 'secure-mode ocp init' => sub {
    my $dir  = tempdir(CLEANUP => 1);
    my $init = OCP::Cmd::Init->new(
        command_chain => [$ocp],
        nogit         => 1,
        name          => 'k461',
        provider      => 'ssh',
        host          => '10.0.0.1',
        pins_stdin    => 1,
    );
    my $input = "pin1-k461\npin1-k461\npin2-k461\npin2-k461\n";
    open my $in, '<', \$input or die "stdin: $!";
    my $err = '';
    open my $efh, '>', \$err or die "stderr: $!";

    no warnings 'redefine';
    local *OCP::Password::ReadMode = sub { die "the terminal was reached\n" };
    local *OCP::Password::ReadLine = sub { die "the terminal was reached\n" };
    local $OCP::Password::PINS_STDIN = 1;
    local *STDIN  = $in;
    local *STDERR = $efh;

    my $cwd = getcwd();
    chdir $dir or die "chdir: $!";
    my ($out, undef, $died) = fd_stdout(sub { $init->execute([], []) });
    chdir $cwd or die "chdir back: $!";

    is $died, '', 'init completes';
    ok -f path($dir)->child('keys.yaml'), 'keys.yaml written';
    like $out, qr/\S/, 'init says what it did on STDOUT';
    unlike $out, $SSH_KEYGEN, "none of ssh-keygen's output on STDOUT";
    unlike $err, $SSH_KEYGEN, 'nor on STDERR';
};

subtest 'a failing ssh-keygen' => sub {
    my $bin = path(tempdir(CLEANUP => 1));
    $bin->child('ssh-keygen')->spew(
        "#!/bin/sh\necho 'ssh-keygen: no space left' >&2\nexit 1\n");
    $bin->child('ssh-keygen')->chmod(0755);
    local $ENV{PATH} = "$bin:$ENV{PATH}";

    # STDERR at the file descriptor too: what the child says lands there.
    my $errfile = path(tempdir(CLEANUP => 1))->child('stderr');
    open my $save, '>&', \*STDERR or die "dup STDERR: $!";
    open STDERR, '>', "$errfile"  or die "STDERR to file: $!";
    my $s = OCP::Secrets->new(project_dir => path(tempdir(CLEANUP => 1)), ocp => $ocp);
    my ($out, undef, $died) = fd_stdout(sub { $s->generate_ssh_key });
    open STDERR, '>&', $save or die "restore STDERR: $!";

    is $out, '', 'nothing on STDOUT';
    like $died, qr/\AFailed to generate SSH key: /, 'the run dies by name';
    like $errfile->slurp, qr/no space left/, "ssh-keygen's error is on STDERR";
};

done_testing;
