#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );

use lib 'lib';

use OCP;
use OCP::Keys;
use OCP::Secrets;

#
# k411: OCP::Keys::update_key put a PIN2 layer on a new private half whatever
# the key was and whatever pin2 held. An admin key without a pin2 got a layer
# derived from an empty password -- the PIN2 protection gone in all but name;
# an automation key got a PIN2 layer it must never have (robocop reads it
# unattended, decrypt_key takes it age-only).
#
# The claims:
#   * a new private half for a key that is not automation needs a pin2 that
#     is defined and not empty; without one update_key croaks and keys.yaml
#     is unchanged
#   * an automation key's new private half is age-only, pin2 or not, and
#     reads back without one
#   * an admin key's new private half reads back with the new pin2 and not
#     with the old one
#   * "0" is a PIN2 (k390)
#   * an update without a private half (deprecate_key) needs no pin2
#

delete local $ENV{SOPS_AGE_KEY_FILE};

local @ARGV = ();
my $ocp = OCP->new;

my $dir = path(tempdir(CLEANUP => 1));
OCP::Secrets->new(project_dir => $dir, ocp => $ocp)->generate_age_key;
my $keys = OCP::Keys->new(project_dir => $dir, ocp => $ocp);

$keys->add_key(name => 'robo', type => 'ssh_ed25519', purpose => 'automation',
    private => "ROBO OLD\n", public => 'ssh-ed25519 AAAArobo');
$keys->add_key(name => 'admin', type => 'ssh_ed25519', purpose => 'admin',
    private => "ADMIN OLD\n", public => 'ssh-ed25519 AAAAadmin', pin2 => 'old-pin2');

subtest 'a non-automation key without pin2 is refused' => sub {
    my $before = $keys->keys_file->slurp_raw;
    for my $pin2 (undef, '') {
        my $label = defined $pin2 ? 'empty pin2' : 'no pin2';
        ok !eval { $keys->update_key('admin', private => "ADMIN NEW\n", pin2 => $pin2); 1 },
            $label.': croaks';
        like $@, qr/PIN2 required/, $label.': says PIN2 is required';
    }
    is $keys->keys_file->slurp_raw, $before, 'keys.yaml untouched';
    is $keys->decrypt_key('admin', 'old-pin2')->{private}, "ADMIN OLD\n",
        'the old private half still opens with the old PIN2';
};

subtest 'an automation key never gets a PIN2 layer' => sub {
    ok $keys->update_key('robo', private => "ROBO NEW\n", pin2 => 'some-pin2'),
        'updated with a pin2 given';
    is $keys->decrypt_key('robo')->{private}, "ROBO NEW\n", 'reads back without PIN2';
    is $keys->get_automation_key->{private}, "ROBO NEW\n", 'get_automation_key reads it';

    ok $keys->update_key('robo', private => "ROBO NEWER\n"), 'updated without a pin2';
    is $keys->decrypt_key('robo')->{private}, "ROBO NEWER\n", 'reads back without PIN2';
};

subtest 'an admin key gets the new PIN2' => sub {
    ok $keys->update_key('admin', private => "ADMIN NEW\n", pin2 => 'new-pin2'), 'updated';
    is $keys->decrypt_key('admin', 'new-pin2')->{private}, "ADMIN NEW\n", 'opens with the new PIN2';
    ok !eval { $keys->decrypt_key('admin', 'old-pin2'); 1 }, 'not with the old one';

    ok $keys->update_key('admin', private => "ADMIN ZERO\n", pin2 => '0'), '"0" is a PIN2';
    is $keys->decrypt_key('admin', '0')->{private}, "ADMIN ZERO\n", 'opens with "0"';
};

subtest 'an update without a private half needs no pin2' => sub {
    ok $keys->deprecate_key('admin'), 'deprecate_key';
    ok $keys->get_key('admin')->{deprecated}, 'deprecated';
    is $keys->decrypt_key('admin', '0')->{private}, "ADMIN ZERO\n", 'private half unchanged';
};

done_testing;
