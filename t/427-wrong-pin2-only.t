#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use Crypt::Age;

use lib 'lib';

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Keys::Secure;
use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

#
# k427: OCP::Role::Cmd::require_admin_approval (the PIN2 gate of `ocp
# inject-key` and secret_approved) and `ocp keys secure` continuing with
# staged keys wrapped the admin key's decrypt in a blanket eval and called
# whatever failed a wrong PIN2. With the right PIN2, a .ocp/age.key that does
# not open keys.yaml, or a private half the age key does not open, was
# reported as "Wrong PIN2" -- the operator retypes a PIN2 that was never the
# problem. OCP::ClusterKey and `ocp apply` had their own copy of the regex
# that tells the two apart (k391).
#
# The claims:
#   * OCP::Keys->is_wrong_pin2 is true for the failure a wrong PIN2 makes and
#     for nothing else; unlock_admin_key returns nothing for a wrong PIN2 and
#     rethrows every other failure unchanged
#   * require_admin_approval: a wrong PIN2 is refused as one; a foreign
#     .ocp/age.key or a private half that does not open, with the right
#     PIN2, dies with its own message, not "Wrong PIN2"
#   * ocp keys secure, continuing with staged keys: the same
#

umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};

my $PIN2  = 'pin2-k427';
my $WRONG = 'not-pin2-k427';

package FakeOCP {
    sub new     { bless { config => $_[1] }, $_[0] }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

package main;

# A project with an age key and an admin + robo key in $file (keys.yaml by
# default), the admin key under $PIN2.
sub project {
    my (%o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    OCP::Secrets->new(project_dir => $dir, ocp => $ocp)->generate_age_key;
    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp,
        ($o{file} ? (keys_file => $dir->child(@{ $o{file} })) : ()));
    $keys->add_key(name => 'robo-k427', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO k427\n", public => 'ssh-ed25519 AAAArobo');
    $keys->add_key(name => 'admin-k427', type => 'ssh_ed25519', purpose => 'admin',
        private => "ADMIN k427\n", public => 'ssh-ed25519 AAAAadmin', pin2 => $PIN2);
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k427',
        control_planes => { provider => 'ssh', host => 'cp.k427.invalid' },
    });
    return ($dir, $keys);
}

# Another project's age key in place of this one's: keys.yaml no longer opens.
sub foreign_age_key {
    my ($dir) = @_;
    my $other = path(tempdir(CLEANUP => 1));
    OCP::Secrets->new(project_dir => $other, ocp => $ocp)->generate_age_key;
    $other->child('.ocp', 'age.key')->copy($dir->child('.ocp', 'age.key'));
}

# The admin key's private half re-encrypted to another age recipient: the
# key file opens, the private half does not -- whatever the PIN2.
sub foreign_private_half {
    my ($keys) = @_;
    my ($pub) = Crypt::Age->generate_keypair;
    my $data = $keys->_read_keys_file_encrypted;
    $_->{private} = Crypt::Age->encrypt(plaintext => 'x', recipients => [$pub])
        for grep { $_->{purpose} eq 'admin' } @{ $data->{keys} };
    $keys->_write_keys_file_encrypted($data);
}

sub config_of { OCP::Config->new(file => $_[0]->child('ocp.yaml')->stringify, ocp => $ocp) }

sub with_pin {
    my ($pin, $code) = @_;
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { $pin };
    my $out = '';
    open my $fh, '>', \$out or die $!;
    my $err = '';
    open my $efh, '>', \$err or die $!;
    local *STDOUT = $fh;
    local *STDERR = $efh;
    my @r = eval { $code->() };
    return { died => $@, result => \@r };
}

subtest 'OCP::Keys: is_wrong_pin2 and unlock_admin_key' => sub {
    my ($dir, $keys) = project();

    ok !eval { $keys->get_admin_key($WRONG); 1 }, 'a wrong PIN2 dies in get_admin_key';
    ok $keys->is_wrong_pin2($@), 'is_wrong_pin2 knows it';
    ok !$keys->is_wrong_pin2($_), 'not: '.(defined $_ ? $_ : 'undef')
        for undef, '', "PIN2 required for admin key\n", "Could not decrypt data key\n",
            "AES-GCM authentication failed at lib/Foo.pm line 1.\n";

    is $keys->unlock_admin_key($PIN2)->{private}, "ADMIN k427\n", 'the right PIN2 unlocks';
    is_deeply [ $keys->unlock_admin_key($WRONG) ], [], 'a wrong PIN2: nothing, no death';

    foreign_age_key($dir);
    my $fresh = OCP::Keys->new(project_dir => $dir, ocp => $ocp);
    my $direct = eval { $fresh->get_admin_key($PIN2); 1 } ? '' : "$@";
    isnt $direct, '', 'a foreign age key: keys.yaml does not open';
    ok !eval { $fresh->unlock_admin_key($PIN2); 1 }, 'unlock_admin_key dies';
    is $@, $direct, 'with that error, unchanged';
};

subtest 'require_admin_approval: a wrong PIN2 is refused as one' => sub {
    my ($dir) = project();
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new('ocp.yaml') ]);
    my $r = with_pin($WRONG, sub { $apply->require_admin_approval(config_of($dir), 'Gate k427') });
    is $r->{died}, "ERROR: Wrong PIN2 or no admin key; Gate k427 refused.\n", 'refused as a wrong PIN2';

    $r = with_pin($PIN2, sub { $apply->require_admin_approval(config_of($dir), 'Gate k427') });
    is $r->{died}, '', 'the right PIN2 passes';
    is $r->{result}[0]{private}, "ADMIN k427\n", 'and hands back the admin key';
};

subtest 'require_admin_approval: a foreign age key is not a wrong PIN2' => sub {
    my ($dir) = project();
    foreign_age_key($dir);
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new('ocp.yaml') ]);
    my $r = with_pin($PIN2, sub { $apply->require_admin_approval(config_of($dir), 'Gate k427') });
    isnt $r->{died}, '', 'refused';
    unlike $r->{died}, qr/PIN2/, 'not blamed on the right PIN2';
    # The SOPS read's own words: the age key, not the PIN2.
    like $r->{died}, qr/Could not decrypt data key/,
        'but on what failed';
};

subtest 'require_admin_approval: a private half that does not open is not a wrong PIN2' => sub {
    my ($dir, $keys) = project();
    foreign_private_half($keys);
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new('ocp.yaml') ]);
    my $r = with_pin($PIN2, sub { $apply->require_admin_approval(config_of($dir), 'Gate k427') });
    isnt $r->{died}, '', 'refused';
    unlike $r->{died}, qr/PIN2/, 'not blamed on the right PIN2';
    like $r->{died}, qr/No matching identity/, 'but on what failed';
};

subtest 'ocp keys secure, staged keys: a wrong PIN2 is refused as one' => sub {
    my ($dir) = project(file => [ '.ocp', 'keys.yaml.pending' ]);
    my $cmd = bless {}, 'OCP::Cmd::Keys::Secure';
    my $staging = $dir->child('.ocp', 'keys.yaml.pending');

    my $r = with_pin($WRONG, sub { $cmd->_staged_keys(config_of($dir), $staging) });
    like $r->{died}, qr/\AERROR: Wrong PIN2 for the staged admin key admin-k427\./,
        'refused as a wrong PIN2';

    $r = with_pin('', sub { $cmd->_staged_keys(config_of($dir), $staging) });
    like $r->{died}, qr/\AERROR: No PIN2 given/, 'no PIN2: said so';
    unlike $r->{died}, qr/ line \d+/, 'without a Perl location';

    $r = with_pin($PIN2, sub { $cmd->_staged_keys(config_of($dir), $staging) });
    is $r->{died}, '', 'the right PIN2 continues';
    is $r->{result}[0]{private}, "ADMIN k427\n", 'with the staged admin key';
};

subtest 'ocp keys secure, staged keys: a private half that does not open is not a wrong PIN2' => sub {
    my ($dir, $keys) = project(file => [ '.ocp', 'keys.yaml.pending' ]);
    foreign_private_half($keys);
    my $cmd = bless {}, 'OCP::Cmd::Keys::Secure';
    my $r = with_pin($PIN2, sub {
        $cmd->_staged_keys(config_of($dir), $dir->child('.ocp', 'keys.yaml.pending')) });
    isnt $r->{died}, '', 'refused';
    unlike $r->{died}, qr/PIN2/, 'not blamed on the right PIN2';
    like $r->{died}, qr/No matching identity/, 'but on what failed';
};

done_testing;
