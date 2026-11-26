#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';

use OCP;
use OCP::ClusterKey;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

#
# k450: before k390 a PIN2 of "0" was read as none, so the admin key was
# stored under the age layer alone, purpose still admin -- and no PIN2 opened
# it again. `ocp keys add-pin2` re-adds such a key under age + a new PIN2.
#
# The claims:
#   1. OCP::Keys::has_pin2_layer tells such a key (0) from a layered one (1);
#   2. `ocp keys add-pin2 --pins-stdin` (through run_cli, so the spelling
#      resolves) re-encrypts every admin key without the layer: afterwards it
#      opens with the new PIN2 to the very same private key, refuses a wrong
#      one, and has the layer; an admin key that had its layer and the robo
#      key are left byte for byte as they were;
#   3. run again, it says there is nothing to do, asks nothing, changes
#      nothing, exits 0;
#   4. with nobody to ask, or PIN2 and its confirmation differing, it
#      refuses and writes nothing;
#   5. add_pin2_layer refuses a key that has its layer, an automation key and
#      an empty PIN2, writing nothing.
#

plan skip_all => 'needs ssh-keygen'
    unless system('command -v ssh-keygen >/dev/null 2>&1') == 0;

umask 022;

delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{HETZNER_API_TOKEN};

my $ocp  = do { local @ARGV = (); OCP->new };
my $PIN2 = 'pin2-k450';

# A secure-mode project as an `ocp init` with PIN2 "0" left it before k390:
# the admin key stored as add_key stored it for that PIN2 -- without one. A
# second admin key with its layer and a robo key beside it.
sub project {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew(
        "name: k450\ncontrol_planes:\n  provider: ssh\n  host: 10.0.0.1\n");
    my $s = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);

    my %pem;
    for my $k ([ 'admin-ssh-bare', 'admin', undef ],
               [ 'admin-ssh-old',  'admin', 'pin2-old' ],
               [ 'robo-ssh-x',     'automation', undef ]) {
        my ($name, $purpose, $pin) = @$k;
        my $f = $s->generate_ssh_key(name => $name);
        $pem{$name} = path($f->{private_key})->slurp;
        my $pub = path($f->{public_key})->slurp;
        chomp $pub;
        path($_)->remove for @$f{qw( private_key public_key )};
        $keys->add_key(name => $name, type => 'ssh_ed25519', purpose => $purpose,
            private => $pem{$name}, public => $pub, pin2 => $pin);
    }
    return ($dir, $keys, \%pem);
}

sub stored { my ($keys, $name) = @_; return $keys->get_key($name)->{private} }

# bin/ocp's way in, STDIN as given, STDOUT/STDERR caught.
sub cli {
    my ($dir, $stdin, @words) = @_;
    my ($out, $err) = ('', '');
    open my $in,  '<', \$stdin or die $!;
    open my $ofh, '>', \$out   or die $!;
    open my $efh, '>', \$err   or die $!;
    no warnings 'redefine';
    local *OCP::Password::ReadMode = sub { die "the terminal was reached\n" };
    local *OCP::Password::ReadLine = sub { die "the terminal was reached\n" };
    local $OCP::Password::PINS_STDIN;
    local *STDIN  = $in;
    local *STDOUT = $ofh;
    local *STDERR = $efh;
    local @ARGV = ('-c', $dir->child('ocp.yaml')->stringify, 'keys', 'add-pin2', @words);
    my $rc = OCP->run_cli;
    return { rc => $rc, out => $out, err => $err, left => do { local $/; <$in> } // '' };
}

subtest 'has_pin2_layer' => sub {
    my (undef, $keys) = project();
    is $keys->has_pin2_layer('admin-ssh-bare'), 0, 'the pre-k390 admin key has none';
    is $keys->has_pin2_layer('admin-ssh-old'),  1, 'a layered admin key has one';
    is $keys->has_pin2_layer('robo-ssh-x'),     0, 'the robo key has none';
    # k466: refused naming add-pin2, where it used to come back as nothing,
    # which every caller words as "Wrong PIN2".
    ok !eval { $keys->unlock_admin_key($PIN2, 'admin-ssh-bare'); 1 },
        'the problem: no PIN2 opens the bare admin key';
    like $@, qr/ocp keys add-pin2/, '... and the refusal names the repair';
};

subtest 'ocp keys add-pin2' => sub {
    my ($dir, $keys, $pem) = project();
    my %before = map { $_ => stored($keys, $_) } qw( admin-ssh-old robo-ssh-x );

    my $r = cli($dir, "$PIN2\n$PIN2\n", '--pins-stdin');
    is $r->{rc}, 0, 'exit 0' or diag $r->{err};
    like $r->{out}, qr/admin-ssh-bare is stored under PIN1 alone/, 'names the key it fixes';
    like $r->{out}, qr/^\[ok\] admin-ssh-bare: re-encrypted under age \+ PIN2$/m, 'says it did';
    unlike $r->{out}, qr/admin-ssh-old:/, 'the layered one is not touched';
    like $r->{err}, qr/Enter PIN2 \(admin SSH access\): .*Confirm PIN2: /s, 'prompts on STDERR';

    my $after = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    is $after->has_pin2_layer('admin-ssh-bare'), 1, 'it has the layer now';
    my $admin = $after->unlock_admin_key($PIN2, 'admin-ssh-bare');
    is $admin && $admin->{private}, $pem->{'admin-ssh-bare'}, 'the new PIN2 opens it to the same key';
    ok !$after->unlock_admin_key('wrong', 'admin-ssh-bare'), 'a wrong PIN2 does not';
    is stored($after, $_), $before{$_}, "$_ unchanged" for sort keys %before;
    is $after->unlock_admin_key('pin2-old', 'admin-ssh-old')->{private}, $pem->{'admin-ssh-old'},
        'the layered admin key still opens with its own PIN2';

    my $again = cli($dir, "never-read\n", '--pins-stdin');
    is $again->{rc}, 0, 'again: exit 0';
    like $again->{out}, qr/Every admin key has its PIN2 layer.*Nothing to do/s, 'again: nothing to do';
    is $again->{left}, "never-read\n", 'again: nothing asked';
};

subtest 'refusals write nothing' => sub {
    my ($dir, $keys) = project();
    my $file = $dir->child('keys.yaml')->slurp;

    my $nobody = cli($dir, '');
    is $nobody->{rc}, 1, 'no terminal, no --pins-stdin: exit 1';
    like $nobody->{err}, qr/no terminal to\s+ask on/, '... and says why';

    my $mismatch = cli($dir, "$PIN2\nother\n", '--pins-stdin');
    is $mismatch->{rc}, 1, 'PIN2 and confirmation differ: exit 1';
    like $mismatch->{err}, qr/PIN2 passwords don't match/, '... and says so';

    is $dir->child('keys.yaml')->slurp, $file, 'keys.yaml as it was';

    for my $case ([ 'admin-ssh-old', $PIN2, qr/has its PIN2 layer already/ ],
                  [ 'robo-ssh-x',    $PIN2, qr/is an automation key/ ],
                  [ 'admin-ssh-bare', '',   qr/PIN2 required/ ]) {
        my ($name, $pin, $re) = @$case;
        ok !eval { $keys->add_pin2_layer($name, $pin); 1 }, "add_pin2_layer('$name', '$pin') refused";
        like $@, $re, '... by name';
    }
    is $dir->child('keys.yaml')->slurp, $file, 'keys.yaml still as it was';
};

done_testing;
