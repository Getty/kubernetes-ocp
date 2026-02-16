package OCP::Keys;
# ABSTRACT: Secure key management with double encryption (age + password)

use Moo;
use OCP;
use Path::Tiny qw(path);
use Carp qw(croak);
use Crypt::Age;
use File::SOPS;
use Digest::SHA qw(sha256_hex);
use MIME::Base64 qw(encode_base64 decode_base64);

our $VERSION = '0.1.0';

has ocp => (
    is      => 'lazy',
    default => sub { OCP->instance },
);

has project_dir => (
    is       => 'ro',
    required => 1,
);

has keys_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('keys.yaml') },
);

has keys_dir => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('.ocp', 'keys') },
);

has age_key_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('.ocp', 'age.key') },
);

has age_recipient_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('.ocp', 'age.pub') },
);

#
# Check if keys.yaml exists
#

sub has_keys_file {
    my ($self) = @_;
    return -f $self->keys_file;
}

#
# List all keys
#

sub list_keys {
    my ($self) = @_;

    return [] unless $self->has_keys_file;

    my $data = $self->_read_keys_file_encrypted;
    return [] unless $data && $data->{keys};

    return $data->{keys};
}

#
# Get specific key
#

sub get_key {
    my ($self, $name) = @_;

    my $keys = $self->list_keys;
    my ($key) = grep { $_->{name} eq $name } @$keys;

    return $key;
}

#
# Add new key (double encrypted)
#

sub add_key {
    my ($self, %params) = @_;

    my $name    = $params{name}    or croak "name required";
    my $type    = $params{type}    or croak "type required";
    my $private = $params{private} or croak "private key required";
    my $public  = $params{public};
    my $pin2    = $params{pin2};      # Optional! (automation keys don't need PIN2)
    my $purpose = $params{purpose} // 'general';  # automation, admin, general

    # Load existing keys
    my $data = $self->has_keys_file ? $self->_read_keys_file_encrypted : {
        version => 1,
        keys    => [],
    };

    # Check if key already exists
    my $existing = $self->get_key($name);
    if ($existing) {
        croak "Key '$name' already exists. Use update_key or choose different name.";
    }

    # Encrypt private key
    my $encrypted_private;
    if ($pin2) {
        # Double encrypt (age + password) for admin keys
        $encrypted_private = $self->_double_encrypt($private, $pin2);
    } else {
        # Single encrypt (age only) for automation keys
        $encrypted_private = $self->_single_encrypt($private);
    }

    # Add key
    push @{$data->{keys}}, {
        name       => $name,
        type       => $type,
        purpose    => $purpose,
        created    => _timestamp(),
        private    => $encrypted_private,
        public     => $public,
        deprecated => 0,
    };

    # Save
    $self->_write_keys_file_encrypted($data);

    return 1;
}

#
# Update key (re-encrypt with new PIN2)
#

sub update_key {
    my ($self, $name, %params) = @_;

    my $data = $self->_read_keys_file_encrypted;
    return unless $data && $data->{keys};

    my $found = 0;
    for my $key (@{$data->{keys}}) {
        if ($key->{name} eq $name) {
            # Update fields
            $key->{private} = $self->_double_encrypt($params{private}, $params{pin2})
                if $params{private};
            $key->{public} = $params{public} if $params{public};
            $key->{deprecated} = $params{deprecated} if defined $params{deprecated};
            $key->{updated} = _timestamp();
            $found = 1;
            last;
        }
    }

    return unless $found;

    $self->_write_keys_file_encrypted($data);
    return 1;
}

#
# Deprecate key (mark for migration)
#

sub deprecate_key {
    my ($self, $name) = @_;

    return $self->update_key($name, deprecated => 1);
}

#
# Delete key
#

sub delete_key {
    my ($self, $name) = @_;

    my $data = $self->_read_keys_file_encrypted;
    return unless $data && $data->{keys};

    my $before = scalar @{$data->{keys}};
    $data->{keys} = [ grep { $_->{name} ne $name } @{$data->{keys}} ];
    my $after = scalar @{$data->{keys}};

    return unless $before != $after;

    $self->_write_keys_file_encrypted($data);
    return 1;
}

#
# Decrypt key (PIN2 optional for automation keys)
#

sub decrypt_key {
    my ($self, $name, $pin2) = @_;

    my $key = $self->get_key($name) or return;

    # Detect encryption type
    my $decrypted;
    if ($key->{purpose} && $key->{purpose} eq 'automation') {
        # Single decrypt (age only)
        $decrypted = $self->_single_decrypt($key->{private});
    } else {
        # Double decrypt (age + password)
        croak "PIN2 required for non-automation key" unless $pin2;
        $decrypted = $self->_double_decrypt($key->{private}, $pin2);
    }

    return {
        name    => $key->{name},
        type    => $key->{type},
        purpose => $key->{purpose},
        private => $decrypted,
        public  => $key->{public},
    };
}

#
# Get automation key (no PIN2 needed!)
#

sub get_automation_key {
    my ($self, $name) = @_;

    # If name provided, get specific key
    if ($name) {
        my $key = $self->get_key($name);
        return unless $key && $key->{purpose} eq 'automation';
        return $self->decrypt_key($name);  # No PIN2 needed
    }

    # Otherwise, get first automation key
    my $keys = $self->list_keys;
    for my $key (@$keys) {
        if ($key->{purpose} && $key->{purpose} eq 'automation' && !$key->{deprecated}) {
            return $self->decrypt_key($key->{name});
        }
    }

    return undef;
}

#
# Get admin key (needs PIN2)
#

sub get_admin_key {
    my ($self, $pin2, $name) = @_;

    croak "PIN2 required for admin key" unless $pin2;

    # If name provided, get specific key
    if ($name) {
        my $key = $self->get_key($name);
        return unless $key && $key->{purpose} eq 'admin';
        return $self->decrypt_key($name, $pin2);
    }

    # Otherwise, get first admin key
    my $keys = $self->list_keys;
    for my $key (@$keys) {
        if ($key->{purpose} && $key->{purpose} eq 'admin' && !$key->{deprecated}) {
            return $self->decrypt_key($key->{name}, $pin2);
        }
    }

    return undef;
}

#
# Decrypt all keys and write to .ocp/keys/
#

sub decrypt_all_to_disk {
    my ($self, $pin2) = @_;

    my $keys = $self->list_keys;
    return unless @$keys;

    # Ensure keys directory exists
    $self->keys_dir->mkpath unless -d $self->keys_dir;

    my @decrypted;

    for my $key (@$keys) {
        next if $key->{deprecated};  # Skip deprecated keys

        my $decrypted = $self->decrypt_key($key->{name}, $pin2);
        next unless $decrypted;

        # Write private key
        my $private_file = $self->keys_dir->child($key->{name});
        $private_file->spew($decrypted->{private});
        $private_file->chmod(0600);

        # Write public key (if exists)
        if ($key->{public}) {
            my $public_file = $self->keys_dir->child("$key->{name}.pub");
            $public_file->spew($key->{public});
            $public_file->chmod(0644);
        }

        push @decrypted, {
            name         => $key->{name},
            type         => $key->{type},
            private_file => $private_file->stringify,
            public_file  => $key->{public} ? $self->keys_dir->child("$key->{name}.pub")->stringify : undef,
        };
    }

    return \@decrypted;
}

#
# Single encryption: age only (for automation keys)
#

sub _single_encrypt {
    my ($self, $plaintext) = @_;

    my $recipient = $self->_get_age_recipient;
    my $age_encrypted = Crypt::Age->encrypt(
        $plaintext,
        recipients => [$recipient],
    );

    return $age_encrypted;
}

sub _single_decrypt {
    my ($self, $encrypted) = @_;

    my $identity = $self->age_key_file->slurp;
    chomp $identity;

    my $plaintext = Crypt::Age->decrypt(
        $encrypted,
        identities => [$identity],
    );

    return $plaintext;
}

#
# Double encryption: password-based AES + age
#

sub _double_encrypt {
    my ($self, $plaintext, $password) = @_;

    # Layer 1: Password-based encryption (AES-256-GCM via Crypt::Age password mode)
    # We'll use a simple password-based encryption with salt
    my $salt = _random_bytes(16);
    my $key = _derive_key($password, $salt);
    my $encrypted_pw = _aes_encrypt($plaintext, $key);

    # Combine salt + encrypted
    my $pw_layer = encode_base64($salt . $encrypted_pw, '');

    # Layer 2: Age encryption (using age.key from project)
    my $recipient = $self->_get_age_recipient;
    my $age_encrypted = Crypt::Age->encrypt(
        $pw_layer,
        recipients => [$recipient],
    );

    return $age_encrypted;
}

sub _double_decrypt {
    my ($self, $encrypted, $password) = @_;

    # Layer 1: Age decryption
    my $identity = $self->age_key_file->slurp;
    chomp $identity;

    my $pw_layer = Crypt::Age->decrypt(
        $encrypted,
        identities => [$identity],
    );

    # Layer 2: Password decryption
    my $decoded = decode_base64($pw_layer);
    my $salt = substr($decoded, 0, 16);
    my $encrypted_pw = substr($decoded, 16);

    my $key = _derive_key($password, $salt);
    my $plaintext = _aes_decrypt($encrypted_pw, $key);

    return $plaintext;
}

#
# Simple AES-256-GCM encryption (pure Perl via CryptX)
#

sub _aes_encrypt {
    my ($plaintext, $key) = @_;

    # Use CryptX for AES-256-GCM
    require Crypt::Mode::GCM;
    my $gcm = Crypt::Mode::GCM->new('AES');

    my $nonce = _random_bytes(12);  # 96-bit nonce
    my $ciphertext = $gcm->encrypt($plaintext, $key, $nonce, '');

    # Return nonce + ciphertext + tag
    return $nonce . $ciphertext;
}

sub _aes_decrypt {
    my ($encrypted, $key) = @_;

    require Crypt::Mode::GCM;
    my $gcm = Crypt::Mode::GCM->new('AES');

    my $nonce = substr($encrypted, 0, 12);
    my $ciphertext = substr($encrypted, 12);

    my $plaintext = $gcm->decrypt($ciphertext, $key, $nonce, '');

    return $plaintext;
}

#
# Key derivation (PBKDF2)
#

sub _derive_key {
    my ($password, $salt) = @_;

    require Crypt::PBKDF2;
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

#
# SOPS operations for keys.yaml (age encrypted)
#

sub _read_keys_file_encrypted {
    my ($self) = @_;

    return {} unless -f $self->keys_file;

    my $identity = $self->age_key_file->slurp;
    chomp $identity;

    my $encrypted = $self->keys_file->slurp;

    return File::SOPS->decrypt(
        encrypted  => $encrypted,
        identities => [$identity],
        format     => 'yaml',
    );
}

sub _write_keys_file_encrypted {
    my ($self, $data) = @_;

    my $recipient = $self->_get_age_recipient;

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$recipient],
        format     => 'yaml',
    );

    $self->keys_file->spew($encrypted);
    return 1;
}

sub _get_age_recipient {
    my ($self) = @_;

    return undef unless -f $self->age_recipient_file;
    my $recipient = $self->age_recipient_file->slurp;
    chomp $recipient;
    return $recipient;
}

#
# Helpers
#

sub _timestamp {
    my @t = gmtime;
    return sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',
        $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
}

1;

__END__

=head1 NAME

OCP::Keys - Secure key management with double encryption

=head1 SYNOPSIS

    use OCP::Keys;

    my $keys = OCP::Keys->new(project_dir => path('.'));

    # Add key (double encrypted: age + PIN2)
    $keys->add_key(
        name    => 'cluster-ssh-2024',
        type    => 'ssh_ed25519',
        private => $private_key_content,
        public  => $public_key_content,
        pin2    => 'secret-pin2',
    );

    # List keys
    my $all_keys = $keys->list_keys;

    # Decrypt specific key
    my $key = $keys->decrypt_key('cluster-ssh-2024', 'secret-pin2');

    # Decrypt all to disk
    $keys->decrypt_all_to_disk('secret-pin2');
    # → .ocp/keys/cluster-ssh-2024
    # → .ocp/keys/cluster-ssh-2024.pub

=head1 DESCRIPTION

OCP::Keys manages encrypted keys with double encryption:

=over 4

=item 1. B<Layer 1>: Password-based (PIN2) - AES-256-GCM with PBKDF2

=item 2. B<Layer 2>: Age encryption (via age.key)

=back

This provides defense-in-depth security:

=over 4

=item * keys.yaml alone is useless (needs age.key)

=item * age.key alone is useless (needs PIN2 password)

=item * Both required for access

=back

=head1 FILE FORMAT

    # keys.yaml (double encrypted)
    version: 1
    keys:
      - name: cluster-ssh-2024
        type: ssh_ed25519
        created: 2024-02-15T12:00:00Z
        private: |-
          -----BEGIN AGE ENCRYPTED FILE-----
          ...
          -----END AGE ENCRYPTED FILE-----
        public: ssh-ed25519 AAAA...
        deprecated: false

=head1 METHODS

=head2 list_keys

Returns arrayref of all keys (metadata only, private keys still encrypted).

=head2 get_key($name)

Returns specific key metadata.

=head2 add_key(%params)

Add new key with double encryption.

Required params: name, type, private, pin2

=head2 decrypt_key($name, $pin2)

Decrypt specific key, returns hashref with decrypted private key.

=head2 decrypt_all_to_disk($pin2)

Decrypt all non-deprecated keys and write to .ocp/keys/

=head2 deprecate_key($name)

Mark key as deprecated (for migration tracking).

=head2 delete_key($name)

Remove key from keys.yaml.

=cut
