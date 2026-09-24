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

our @EXPORT_OK = qw(prompt_password encrypt_age_key decrypt_age_key);

# --pins-stdin (k166): answer every prompt below with the next line of STDIN
# instead of the terminal. Switched on once per process by the option's
# trigger in OCP::Role::Cmd; tests `local`ise it.
#
# A package switch rather than an argument, on purpose. The prompts sit
# layers below the command (OCP::Secrets::ensure_age_key, OCP::ClusterKey,
# the PIN2 gates), and threading a flag through each of those would widen
# interfaces that have nothing to do with where a PIN comes from. Where PINs
# come from is a property of the process -- who is on the other end of
# STDIN -- and that is what a process-wide switch describes.
#
# Deliberately no argv/env variant: a PIN there shows up in ps,
# /proc/PID/environ and shell history (cf. k156). STDIN fed from a file or a
# process substitution is neither.
our $PINS_STDIN;

#
# Prompt for password (hidden input)
#

sub prompt_password {
    my ($prompt) = @_;
    $prompt //= 'Password: ';

    print STDERR $prompt;

    return _read_stdin_line($prompt) if $PINS_STDIN;
    ReadMode('noecho');
    my $password = ReadLine(0);
    ReadMode('restore');
    print STDERR "\n";

    chomp $password if defined $password;
    return $password;
}

# One line off STDIN with the trailing newline stripped and nothing else -- a
# PIN may begin or end in whitespace. Running out of lines is fatal: undef
# would reach the caller as "wrong PIN", and falling back to the terminal
# would hang a run that was promised to need nobody. Term::ReadKey is not
# touched on this path at all.
sub _read_stdin_line {
    my ($prompt) = @_;

    my $line = <STDIN>;
    print STDERR "\n";

    unless (defined $line) {
        (my $what = $prompt) =~ s/[\s:]+\z//;
        die "ERROR: --pins-stdin: STDIN has no line left for '$what'.\n"
          . "       Give one line per PIN prompt, in the order they are asked.\n";
    }

    $line =~ s/\n\z//;
    return $line;
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
    my $got = read $fh, $bytes, $len;
    close $fh;
    # A short read from the CSPRNG would silently weaken the salt/nonce it
    # feeds, so it is a hard failure, not a value to use as-is.
    croak "Short read from /dev/urandom: wanted $len bytes, got "
        . (defined $got ? $got : 'undef')
        unless defined $got && $got == $len;
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

Prompts for password with hidden input. Returns password string. The prompt
is printed on STDERR, so a command's STDOUT stays its payload.

With C<$OCP::Password::PINS_STDIN> true -- the C<--pins-stdin> option every
command has, see L<OCP::Role::Cmd> -- the answer is the next line of STDIN
instead of the terminal: one line per prompt, in prompt order, only the
trailing newline stripped. A missing line dies naming the prompt that had
none; there is no fallback to the terminal.

=head2 encrypt_age_key($age_key_content, $password)

Encrypts age.key content with password. Returns base64 encoded ciphertext.

=head2 decrypt_age_key($encrypted_b64, $password)

Decrypts age.key from base64 encoded ciphertext. Returns plaintext or dies.

=cut
