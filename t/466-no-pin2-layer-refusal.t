#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';

use OCP;
use OCP::ClusterKey;
use OCP::Cmd::Apply;
use OCP::Cmd::Keys::Secure;
use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

#
# k466: an admin key stored without its PIN2 layer (the pre-k390 PIN2 "0"
# bug, k450) fails every PIN2 the way a wrong one does, so the operator was
# told "Wrong PIN2" and retyped a PIN2 that does not exist. The claims:
#
#   1. OCP::Keys::unlock_admin_key, for such a key -- named, or the first
#      admin key -- dies naming the key and `ocp keys add-pin2`, instead of
#      returning nothing (which every caller words as "Wrong PIN2");
#   2. a wrong PIN2 on a key that has its layer is still nothing, no death;
#   3. the refusal reaches the operator through the PIN2 gates
#      (require_admin_approval, OCP::ClusterKey), not "Wrong PIN2";
#   4. in a keys file other than keys.yaml (the staging file of ocp keys
#      secure) it names the key and file, but not add-pin2, which repairs
#      keys.yaml alone;
#   5. after add_pin2_layer the key opens with its new PIN2.
#

umask 022;

local @ARGV = ();
my $ocp = OCP->new;

delete local $ENV{SOPS_AGE_KEY_FILE};

my $PIN2  = 'pin2-k466';
my $WRONG = 'not-pin2-k466';
my $PEM   = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAk466\n-----END OPENSSH PRIVATE KEY-----\n";

package FakeOCP {
    sub new     { bless { config => $_[1] }, $_[0] }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

package main;

# A project whose first admin key has no PIN2 layer -- add_key with no pin2
# stores it as the PIN2 "0" bug did -- a second admin key under $PIN2 and a
# robo key, in $file (keys.yaml by default).
sub project {
    my (%o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    OCP::Secrets->new(project_dir => $dir, ocp => $ocp)->generate_age_key;
    my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp,
        ($o{file} ? (keys_file => $dir->child(@{ $o{file} })) : ()));
    $keys->add_key(name => 'admin-bare', type => 'ssh_ed25519', purpose => 'admin',
        private => $PEM, public => 'ssh-ed25519 AAAAbare');
    $keys->add_key(name => 'admin-layered', type => 'ssh_ed25519', purpose => 'admin',
        private => $PEM, public => 'ssh-ed25519 AAAAlayered', pin2 => $PIN2);
    $keys->add_key(name => 'robo-k466', type => 'ssh_ed25519', purpose => 'automation',
        private => "ROBO k466\n", public => 'ssh-ed25519 AAAArobo');
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k466',
        control_planes => { provider => 'ssh', host => 'cp.k466.invalid' },
    });
    return ($dir, $keys);
}

sub config_of { OCP::Config->new(file => $_[0]->child('ocp.yaml')->stringify, ocp => $ocp) }

sub with_pin {
    my ($pin, $code) = @_;
    no warnings 'redefine';
    local *OCP::Password::prompt_password = sub { $pin };
    my ($out, $err) = ('', '');
    open my $fh,  '>', \$out or die $!;
    open my $efh, '>', \$err or die $!;
    local *STDOUT = $fh;
    local *STDERR = $efh;
    my @r = eval { $code->() };
    return { died => $@, result => \@r };
}

my $refusal = qr/\AERROR: The admin key 'admin-bare' in keys\.yaml has no PIN2 layer, so no PIN2\n/;
my $hint    = qr/Run 'ocp keys add-pin2' to set its PIN2/;

subtest 'unlock_admin_key: a key without its PIN2 layer names add-pin2' => sub {
    my (undef, $keys) = project();
    is $keys->has_pin2_layer('admin-bare'), 0, 'precondition: admin-bare has no PIN2 layer';

    for my $pin ($PIN2, $WRONG) {
        ok !eval { $keys->unlock_admin_key($pin, 'admin-bare'); 1 }, "by name, PIN2 '$pin': dies";
        like $@, $refusal, '... naming the key and the file';
        like $@, $hint,    '... and the command that repairs it';
        unlike $@, qr/Wrong PIN2| line \d+/, '... no "Wrong PIN2", no Perl location';
    }

    ok !eval { $keys->unlock_admin_key($PIN2); 1 }, 'no name, the first admin key is the bare one: dies';
    like $@, $refusal, '... the same refusal';
};

subtest 'unlock_admin_key: a wrong PIN2 on a layered key is still nothing' => sub {
    my (undef, $keys) = project();
    is_deeply [ $keys->unlock_admin_key($WRONG, 'admin-layered') ], [], 'a wrong PIN2: nothing, no death';
    is $keys->unlock_admin_key($PIN2, 'admin-layered')->{private}, $PEM, 'the right one opens it';
};

subtest 'the PIN2 gates pass the refusal on' => sub {
    my ($dir) = project();

    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new('ocp.yaml') ]);
    my $r = with_pin($PIN2, sub { $apply->require_admin_approval(config_of($dir), 'Gate k466') });
    like $r->{died}, $refusal, 'require_admin_approval: the no-layer refusal';
    like $r->{died}, $hint, '... naming add-pin2';
    unlike $r->{died}, qr/Wrong PIN2/, '... not "Wrong PIN2"';

    $r = with_pin(undef, sub {
        OCP::ClusterKey::_unlock_admin_key(config_of($dir), 'ssh', pin2 => $PIN2);
    });
    like $r->{died}, $refusal, 'OCP::ClusterKey: the no-layer refusal';
    like $r->{died}, $hint, '... naming add-pin2';
    unlike $r->{died}, qr/Wrong PIN2/, '... not "Wrong PIN2"';
};

subtest 'another keys file: named, without add-pin2' => sub {
    my ($dir) = project(file => [ '.ocp', 'keys.yaml.pending' ]);
    my $cmd     = bless {}, 'OCP::Cmd::Keys::Secure';
    my $staging = $dir->child('.ocp', 'keys.yaml.pending');

    my $r = with_pin($PIN2, sub { $cmd->_staged_keys(config_of($dir), $staging) });
    like $r->{died}, qr/\AERROR: The admin key 'admin-bare' in keys\.yaml\.pending has no PIN2 layer/,
        'names the key and the staging file';
    unlike $r->{died}, qr/add-pin2/, 'but not add-pin2, which repairs keys.yaml';
};

subtest 'after add_pin2_layer it opens' => sub {
    my (undef, $keys) = project();
    $keys->add_pin2_layer('admin-bare', $PIN2);
    is $keys->unlock_admin_key($PIN2, 'admin-bare')->{private}, $PEM, 'the new PIN2 opens it';
    is_deeply [ $keys->unlock_admin_key($WRONG, 'admin-bare') ], [], 'a wrong one is a wrong PIN2 again';
};

done_testing;
