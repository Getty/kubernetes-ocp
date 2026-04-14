package OCP::Password;
# ABSTRACT: Secure password prompting and age.key encryption

use strict;
use warnings;
use Exporter 'import';
use Term::ReadKey;
use Carp qw(croak);
use Crypt::AuthEnc::GCM;
use Crypt::PBKDF2;
use Path::Tiny qw(path);
use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA qw(sha256);

our $VERSION = '0.001';
our @EXPORT_OK = qw(prompt_password encrypt_age_key decrypt_age_key);

#
# Prompt for password (hidden input)
#

sub prompt_password {
    my ($prompt) = @_;
    $prompt //= 'Password: ';

    print STDERR $prompt;
    ReadMode('noecho');
    my $password = ReadLine(0);
    ReadMode('restore');
    print STDERR "\n";

    chomp $password if defined $password;
    return $password;
}

#
# Encrypt age.key with password
#

sub encrypt_age_key {
    my ($age_key_content, $password) = @_;

    croak "age.key content required" unless $age_key_content;
    croak "password required" unless $password;

    # Use AES-256-GCM via CryptX


    # Derive key from password (PBKDF2)
    my $salt = _random_bytes(16);
    my $key = _derive_key($password, $salt);

    # Encrypt with random nonce
    my $nonce = _random_bytes(12);
    my $gcm = Crypt::AuthEnc::GCM->new('AES', $key);
    $gcm->iv_add($nonce);
    $gcm->adata_add('');
    my $ciphertext = $gcm->encrypt_add($age_key_content);
    my $tag = $gcm->encrypt_done;

    # Return base64(salt + nonce + tag + ciphertext)
    my $encrypted = $salt . $nonce . $tag . $ciphertext;
    return encode_base64($encrypted, '');
}

#
# Decrypt age.key with password
#

sub decrypt_age_key {
    my ($encrypted_b64, $password) = @_;

    croak "encrypted age.key required" unless $encrypted_b64;
    croak "password required" unless $password;

    # Decode base64
    my $encrypted = decode_base64($encrypted_b64);

    # Extract components: salt(16) + nonce(12) + tag(16) + ciphertext
    my $salt = substr($encrypted, 0, 16);
    my $nonce = substr($encrypted, 16, 12);
    my $tag = substr($encrypted, 28, 16);
    my $ciphertext = substr($encrypted, 44);

    # Derive key
    my $key = _derive_key($password, $salt);

    # Decrypt


    my $plaintext = eval {
        my $gcm = Crypt::AuthEnc::GCM->new('AES', $key);
        $gcm->iv_add($nonce);
        $gcm->adata_add('');
        my $pt = $gcm->decrypt_add($ciphertext);
        my $ok = $gcm->decrypt_done($tag);
        $ok ? $pt : undef;
    };

    if ($@ || !defined $plaintext) {
        croak "Decryption failed. Wrong password?";
    }

    return $plaintext;
}

#
# Helpers
#

sub _derive_key {
    my ($password, $salt) = @_;


    my $pbkdf2 = Crypt::PBKDF2->new(
        hash_class => 'HMACSHA2',
        hash_args  => { sha_size => 256 },
        iterations => 100_000,
        salt_len   => 16,
    );

    return $pbkdf2->PBKDF2($salt, $password);
}

sub _random_bytes {
    my ($len) = @_;
    open my $fh, '<', '/dev/urandom' or croak "Can't open /dev/urandom: $!";
    my $bytes;
    read $fh, $bytes, $len;
    close $fh;
    return $bytes;
}

1;

__END__

=head1 NAME

OCP::Password - Secure password prompting and age.key encryption

=head1 SYNOPSIS

    use OCP::Password qw(prompt_password encrypt_age_key decrypt_age_key);

    # Prompt for password (hidden input)
    my $pin1 = prompt_password("Enter PIN1: ");

    # Encrypt age.key with password
    my $age_key = read_file('.ocp/age.key');
    my $encrypted = encrypt_age_key($age_key, $pin1);
    write_file('age.key.enc', $encrypted);

    # Decrypt age.key
    my $encrypted = read_file('age.key.enc');
    my $age_key = decrypt_age_key($encrypted, $pin1);

=head1 DESCRIPTION

Provides secure password prompting (hidden input) and age.key encryption
for defense-in-depth security.

=head2 Encryption Details

- Algorithm: AES-256-GCM
- Key derivation: PBKDF2-HMAC-SHA256 (100,000 iterations)
- Random salt (16 bytes) per encryption
- Random nonce (12 bytes) per encryption

=head1 FUNCTIONS

=head2 prompt_password($prompt)

Prompts for password with hidden input. Returns password string.

=head2 encrypt_age_key($age_key_content, $password)

Encrypts age.key content with password. Returns base64 encoded ciphertext.

=head2 decrypt_age_key($encrypted_b64, $password)

Decrypts age.key from base64 encoded ciphertext. Returns plaintext or dies.

=cut
