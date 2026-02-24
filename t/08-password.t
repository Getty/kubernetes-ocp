#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use OCP::Password qw(encrypt_age_key decrypt_age_key);

#
# Test: Round-trip encryption/decryption
#

{
    my $plaintext = "AGE-SECRET-KEY-1FAKE0KEY0FOR0TESTING0ONLY0ABCDEFGHIJKLMNOP\n";
    my $password = 'test-pin-1234';

    my $encrypted = encrypt_age_key($plaintext, $password);
    ok($encrypted, 'encrypt_age_key returns data');
    ok(length($encrypted) > 0, 'encrypted data is non-empty');

    # Should be base64
    like($encrypted, qr/^[A-Za-z0-9+\/=]+$/, 'encrypted output is base64');

    # Should not contain plaintext
    unlike($encrypted, qr/AGE-SECRET-KEY/, 'plaintext not visible in ciphertext');

    my $decrypted = decrypt_age_key($encrypted, $password);
    is($decrypted, $plaintext, 'round-trip: decrypted matches original');
}

#
# Test: Different passwords produce different ciphertext
#

{
    my $plaintext = "some-secret-data";
    my $enc1 = encrypt_age_key($plaintext, 'password-one');
    my $enc2 = encrypt_age_key($plaintext, 'password-two');

    isnt($enc1, $enc2, 'different passwords produce different ciphertext');
}

#
# Test: Same password produces different ciphertext (random salt/nonce)
#

{
    my $plaintext = "same-data";
    my $password = 'same-password';
    my $enc1 = encrypt_age_key($plaintext, $password);
    my $enc2 = encrypt_age_key($plaintext, $password);

    isnt($enc1, $enc2, 'same input produces different ciphertext (random salt/nonce)');

    # But both decrypt to same plaintext
    is(decrypt_age_key($enc1, $password), $plaintext, 'first decrypts correctly');
    is(decrypt_age_key($enc2, $password), $plaintext, 'second decrypts correctly');
}

#
# Test: Wrong password fails
#

{
    my $plaintext = "secret-data";
    my $encrypted = encrypt_age_key($plaintext, 'correct-password');

    eval { decrypt_age_key($encrypted, 'wrong-password') };
    ok($@, 'wrong password throws error');
    like($@, qr/Decryption failed|Wrong password/, 'error message mentions decryption failure');
}

#
# Test: Empty/missing arguments die
#

{
    eval { encrypt_age_key('', 'pass') };
    ok($@, 'encrypt dies with empty content');

    eval { encrypt_age_key('data', '') };
    ok($@, 'encrypt dies with empty password');

    eval { decrypt_age_key('', 'pass') };
    ok($@, 'decrypt dies with empty encrypted data');

    eval { decrypt_age_key('data', '') };
    ok($@, 'decrypt dies with empty password');
}

#
# Test: Multiline content preserved
#

{
    my $multiline = "line1\nline2\nline3\n";
    my $password = 'pin';
    my $encrypted = encrypt_age_key($multiline, $password);
    my $decrypted = decrypt_age_key($encrypted, $password);
    is($decrypted, $multiline, 'multiline content preserved through encryption');
}

#
# Test: Unicode-safe password
#

{
    my $plaintext = "test-data";
    my $password = "p\x{e4}ssw\x{f6}rd";  # pässwörd
    my $encrypted = encrypt_age_key($plaintext, $password);
    my $decrypted = decrypt_age_key($encrypted, $password);
    is($decrypted, $plaintext, 'unicode password works');
}

#
# Test: Binary-ish content
#

{
    my $binary = join('', map { chr($_) } 0..255);
    my $password = 'binary-test';
    my $encrypted = encrypt_age_key($binary, $password);
    my $decrypted = decrypt_age_key($encrypted, $password);
    is($decrypted, $binary, 'binary content preserved');
}

done_testing;
