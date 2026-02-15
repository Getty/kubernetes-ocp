#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use_ok('OCP::Secrets');
use_ok('Crypt::Age');
use_ok('File::SOPS');

# Create temp directory for test project
my $tmpdir = tempdir(CLEANUP => 1);
my $project_dir = path($tmpdir);

# Test: Create secrets manager
my $secrets = OCP::Secrets->new(project_dir => $project_dir);
isa_ok($secrets, 'OCP::Secrets');

# Test: No keys initially
ok(!$secrets->has_age_key, 'No age key initially');
ok(!$secrets->has_secrets_file, 'No secrets file initially');

# Test: Generate age key
my $keys = $secrets->generate_age_key;
ok($keys, 'generate_age_key returns result');
ok($keys->{public_key}, 'Has public key');
ok($keys->{secret_key}, 'Has secret key');
like($keys->{public_key}, qr/^age1/, 'Public key has age1 prefix');
like($keys->{secret_key}, qr/^AGE-SECRET-KEY-1/, 'Secret key has correct prefix');

# Verify files exist
ok($secrets->has_age_key, 'Age key file exists after generation');
ok(-f $secrets->age_key_file, 'Key file physically exists');
ok(-f $secrets->age_recipient_file, 'Recipient file physically exists');

# Test: Check file permissions
my $mode = (stat($secrets->age_key_file->stringify))[2] & 07777;
is($mode, 0600, 'Key file has secure permissions (0600)');

# Test: Read recipient
my $recipient = $secrets->age_recipient;
is($recipient, $keys->{public_key}, 'age_recipient returns correct key');

# Test: Create secrets
ok($secrets->create_secrets(
    hetzner_token => 'test-token-12345',
    db_password   => 'supersecret',
), 'create_secrets succeeds');

ok($secrets->has_secrets_file, 'Secrets file exists after creation');

# Test: Verify secrets file is encrypted (contains SOPS metadata)
my $secrets_content = $secrets->secrets_file->slurp;
like($secrets_content, qr/sops:/, 'Secrets file contains SOPS metadata');
like($secrets_content, qr/age:/, 'Secrets file contains age encryption info');
unlike($secrets_content, qr/test-token-12345/, 'Token is NOT in plaintext');
unlike($secrets_content, qr/supersecret/, 'Password is NOT in plaintext');

# Test: Read single secret
my $token = $secrets->read_secret('hetzner_token');
is($token, 'test-token-12345', 'read_secret returns correct value');

my $password = $secrets->read_secret('db_password');
is($password, 'supersecret', 'read_secret returns second value correctly');

# Test: Read non-existent secret
my $missing = $secrets->read_secret('nonexistent');
is($missing, undef, 'read_secret returns undef for missing key');

# Test: Read all secrets
my $all = $secrets->read_all_secrets;
is_deeply($all, {
    hetzner_token => 'test-token-12345',
    db_password   => 'supersecret',
}, 'read_all_secrets returns all data');

# Test: Update secret
$secrets->update_secret('hetzner_token', 'new-token-67890');
is($secrets->read_secret('hetzner_token'), 'new-token-67890', 'update_secret works');
is($secrets->read_secret('db_password'), 'supersecret', 'Other secrets unchanged');

# Test: Hetzner token helper
$secrets->set_hetzner_token('final-token');
is($secrets->hetzner_token, 'final-token', 'hetzner_token helper works');

# Test: Environment variable takes precedence
{
    local $ENV{HETZNER_API_TOKEN} = 'env-token';
    is($secrets->hetzner_token, 'env-token', 'Environment variable takes precedence');
}

# Test: Falls back to secrets file
is($secrets->hetzner_token, 'final-token', 'Falls back to secrets file');

# Test: Pure Perl - verify Crypt::Age works standalone
{
    my ($pub, $sec) = Crypt::Age->generate_keypair;
    my $plaintext = "Test message for encryption";

    my $encrypted = Crypt::Age->encrypt(
        plaintext  => $plaintext,
        recipients => [$pub],
    );

    ok(length($encrypted) > length($plaintext), 'Encrypted data is longer');
    unlike($encrypted, qr/Test message/, 'Plaintext not visible in ciphertext');

    my $decrypted = Crypt::Age->decrypt(
        ciphertext => $encrypted,
        identities => [$sec],
    );

    is($decrypted, $plaintext, 'Crypt::Age round-trip works');
}

# Test: Pure Perl - verify File::SOPS works standalone
{
    my ($pub, $sec) = Crypt::Age->generate_keypair;

    my $data = {
        api_key => 'secret-api-key',
        nested  => {
            value => 'nested-secret',
        },
    };

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$pub],
        format     => 'yaml',
    );

    like($encrypted, qr/sops:/, 'File::SOPS output has SOPS metadata');
    unlike($encrypted, qr/secret-api-key/, 'API key not in plaintext');

    my $decrypted = File::SOPS->decrypt(
        encrypted  => $encrypted,
        identities => [$sec],
        format     => 'yaml',
    );

    is_deeply($decrypted, $data, 'File::SOPS round-trip works');
}

done_testing;
