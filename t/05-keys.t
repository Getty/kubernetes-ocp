#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Secrets;
use OCP::Keys;

# Ensure OCP singleton exists
local @ARGV = ();
my $ocp = OCP->new;

my $tmpdir = tempdir(CLEANUP => 1);
my $project_dir = path($tmpdir);

# Setup: generate age key (required for encryption)
my $secrets = OCP::Secrets->new(project_dir => $project_dir);
my $age_keys = $secrets->generate_age_key;
ok($age_keys, 'Age key generated');

#
# Test: Create Keys manager
#

my $keys = OCP::Keys->new(project_dir => $project_dir, ocp => $ocp);
isa_ok($keys, 'OCP::Keys');

#
# Test: No keys initially
#

ok(!$keys->has_keys_file, 'No keys.yaml initially');
is_deeply($keys->list_keys, [], 'list_keys returns empty');
is($keys->get_key('nonexistent'), undef, 'get_key returns undef for missing');

#
# Test: Add automation key (single encryption, no PIN2)
#

{
    my $private = "-----FAKE PRIVATE KEY-----\nautomation-secret-data\n";
    my $public  = "ssh-ed25519 AAAA_automation_key user\@host";

    my $result = $keys->add_key(
        name    => 'robo-ssh-20260101',
        type    => 'ssh_ed25519',
        purpose => 'automation',
        private => $private,
        public  => $public,
    );

    ok($result, 'add_key returns true');
    ok($keys->has_keys_file, 'keys.yaml created');

    my $list = $keys->list_keys;
    is(scalar @$list, 1, 'One key in list');
    is($list->[0]{name}, 'robo-ssh-20260101', 'Key name correct');
    is($list->[0]{purpose}, 'automation', 'Key purpose correct');
    is($list->[0]{type}, 'ssh_ed25519', 'Key type correct');
    is($list->[0]{public}, $public, 'Public key stored');
    ok($list->[0]{created}, 'Created timestamp present');
    ok(!$list->[0]{deprecated}, 'Not deprecated');

    # Private key should be encrypted (not plaintext)
    unlike($list->[0]{private}, qr/automation-secret-data/, 'Private key is encrypted');
}

#
# Test: Decrypt automation key (no PIN2 needed)
#

{
    my $decrypted = $keys->decrypt_key('robo-ssh-20260101');
    ok($decrypted, 'decrypt_key returns data');
    is($decrypted->{name}, 'robo-ssh-20260101', 'Decrypted key name');
    like($decrypted->{private}, qr/automation-secret-data/, 'Decrypted private key content');
    is($decrypted->{purpose}, 'automation', 'Decrypted purpose');
}

#
# Test: get_automation_key helper
#

{
    my $auto = $keys->get_automation_key;
    ok($auto, 'get_automation_key finds key');
    is($auto->{name}, 'robo-ssh-20260101', 'Finds correct automation key');
    like($auto->{private}, qr/automation-secret-data/, 'Decrypted content');
}

#
# Test: Add admin key (double encryption, with PIN2)
#

{
    my $private = "-----FAKE ADMIN KEY-----\nadmin-secret-data\n";
    my $public  = "ssh-ed25519 AAAA_admin_key admin\@host";
    my $pin2    = 'test-pin2-secret';

    my $result = $keys->add_key(
        name    => 'admin-ssh-20260101',
        type    => 'ssh_ed25519',
        purpose => 'admin',
        private => $private,
        public  => $public,
        pin2    => $pin2,
    );

    ok($result, 'add_key admin returns true');

    my $list = $keys->list_keys;
    is(scalar @$list, 2, 'Two keys in list');

    my ($admin) = grep { $_->{purpose} eq 'admin' } @$list;
    ok($admin, 'Admin key in list');
    is($admin->{name}, 'admin-ssh-20260101', 'Admin key name');
    unlike($admin->{private}, qr/admin-secret-data/, 'Admin private key is encrypted');
}

#
# Test: Decrypt admin key (requires PIN2)
#

{
    my $pin2 = 'test-pin2-secret';

    my $decrypted = $keys->decrypt_key('admin-ssh-20260101', $pin2);
    ok($decrypted, 'decrypt_key admin returns data');
    is($decrypted->{name}, 'admin-ssh-20260101', 'Decrypted admin name');
    like($decrypted->{private}, qr/admin-secret-data/, 'Decrypted admin private key');
    is($decrypted->{purpose}, 'admin', 'Decrypted admin purpose');
}

#
# Test: get_admin_key helper
#

{
    my $admin = $keys->get_admin_key('test-pin2-secret');
    ok($admin, 'get_admin_key finds key');
    is($admin->{name}, 'admin-ssh-20260101', 'Correct admin key');
    like($admin->{private}, qr/admin-secret-data/, 'Decrypted admin content');
}

#
# Test: Wrong PIN2 fails
#

{
    my $result = eval { $keys->decrypt_key('admin-ssh-20260101', 'wrong-pin2') };
    ok(!$result || $@, 'Wrong PIN2 fails to decrypt');
}

#
# Test: Admin key without PIN2 croaks
#

{
    eval { $keys->decrypt_key('admin-ssh-20260101') };
    like($@, qr/PIN2 required/, 'Missing PIN2 croaks');
}

#
# Test: get_key
#

{
    my $key = $keys->get_key('robo-ssh-20260101');
    ok($key, 'get_key returns key');
    is($key->{name}, 'robo-ssh-20260101', 'get_key name correct');

    my $missing = $keys->get_key('nonexistent');
    is($missing, undef, 'get_key returns undef for missing key');
}

#
# Test: Duplicate key name is rejected
#

{
    eval {
        $keys->add_key(
            name    => 'robo-ssh-20260101',
            type    => 'ssh_ed25519',
            purpose => 'automation',
            private => 'duplicate',
        );
    };
    like($@, qr/already exists/, 'Duplicate key name rejected');
}

#
# Test: Deprecate key
#

{
    ok($keys->deprecate_key('robo-ssh-20260101'), 'deprecate_key returns true');

    my $key = $keys->get_key('robo-ssh-20260101');
    ok($key->{deprecated}, 'Key is now deprecated');

    # get_automation_key should skip deprecated keys
    my $auto = $keys->get_automation_key;
    is($auto, undef, 'get_automation_key skips deprecated keys');
}

#
# Test: Delete key
#

{
    my $before = scalar @{$keys->list_keys};
    ok($keys->delete_key('robo-ssh-20260101'), 'delete_key returns true');

    my $after = scalar @{$keys->list_keys};
    is($after, $before - 1, 'Key count decreased');
    is($keys->get_key('robo-ssh-20260101'), undef, 'Deleted key is gone');

    # Deleting non-existent key
    ok(!$keys->delete_key('nonexistent'), 'delete_key returns false for missing');
}

done_testing;
