package OCP::Keys;
# ABSTRACT: Secure key management with double encryption (age + password)

use Moo;
use OCP;
use Path::Tiny qw(path);
use Carp qw(croak);
use Crypt::Age;
use Crypt::AuthEnc::GCM;
use Crypt::PBKDF2;
use File::SOPS;
use OCP::Secrets;
use Digest::SHA qw(sha256_hex);
use MIME::Base64 qw(encode_base64 decode_base64);

# What _aes_decrypt dies with when the PIN2 layer does not open: a wrong PIN2
# (is_wrong_pin2).
my $WRONG_PIN2 = "AES-GCM authentication failed\n";

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

has age_key_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('.ocp', 'age.key') },
);

has age_recipient_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('.ocp', 'age.pub') },
);

# The project key in hand (k349), unlocked into memory by
# OCP::Secrets::unlock_age_key: read in place of age_key_file. undef reads
# age_key_file, as ever.
has age_key => (
    is => 'ro',
);

# Where the age identity and the project's recipient come from (k216:
# SOPS_AGE_KEY_FILE, see OCP::Secrets::identities). One place for both, so
# the key file and the SOPS files can never be read with different keys.
has _secrets => (
    is       => 'lazy',
    init_arg => undef,
);

sub _build__secrets {
    my ($self) = @_;
    return OCP::Secrets->new(
        project_dir        => $self->project_dir,
        ocp                => $self->ocp,
        age_key_file       => $self->age_key_file,
        age_recipient_file => $self->age_recipient_file,
        age_key            => $self->age_key,
    );
}

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

=head1 METHODS

=method list_keys

Returns arrayref of all keys with the SOPS/age layer removed: names, types,
purposes and B<public> keys in plaintext, C<private> still encrypted. Needs
F<.ocp/age.key> (or L</age_key>), never PIN2.

=cut

#
# Get specific key
#

sub get_key {
    my ($self, $name) = @_;

    my $keys = $self->list_keys;
    my ($key) = grep { $_->{name} eq $name } @$keys;

    return $key;
}

=method get_key($name)

Returns specific key metadata.

=cut

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

    # Encrypt private key. A PIN2 is set when it is defined and not empty --
    # never "when it is true": "0" is a PIN2, and reading it as none stored
    # the admin key age-only (k390).
    my $encrypted_private;
    if (defined $pin2 && length $pin2) {
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

=method add_key(%params)

Adds a key. Required params: name, type, private. Optional: public,
C<purpose> (C<automation>, C<admin> or C<general>, the default) and
C<pin2>. With a C<pin2> that is defined and not empty (C<"0"> is one) the
private half is double encrypted (PIN2 + age); without one it gets the age
layer only, as an automation key does. Croaks when the name is taken.

=cut

#
# Add a key that has a public half only (k216)
#

# An operator's SSH key (`ocp keys operator add`): its private half stays on
# the operator's machine, so the entry has none -- and no PIN2 layer either.
# Every other field as add_key writes it; `age` is the operator's age
# recipient, which is how OCP::ClusterKey recognises a run under that
# operator's identity.
sub add_public_key {
    my ($self, %params) = @_;

    my $name    = $params{name}    or croak "name required";
    my $type    = $params{type}    or croak "type required";
    my $public  = $params{public}  or croak "public key required";
    my $purpose = $params{purpose} or croak "purpose required";

    my $data = $self->has_keys_file ? $self->_read_keys_file_encrypted : {
        version => 1,
        keys    => [],
    };

    croak "Key '$name' already exists. Use update_key or choose different name."
        if grep { $_->{name} eq $name } @{ $data->{keys} // [] };

    push @{$data->{keys}}, {
        name       => $name,
        type       => $type,
        purpose    => $purpose,
        created    => _timestamp(),
        public     => $public,
        (defined $params{age} ? (age => $params{age}) : ()),
        deprecated => 0,
    };

    $self->_write_keys_file_encrypted($data);

    return 1;
}

=method add_public_key(%params)

    $keys->add_public_key(name => 'leitstand', type => 'ssh_ed25519',
        purpose => 'operator', public => $line, age => 'age1...');

Adds an entry with a public half and B<no> private one -- an operator's SSH
key. Required: name, type, public, purpose; C<age> is optional. Croaks
when the name is taken.

=cut

#
# The two-tier pair a secure-mode project starts with (ADR 0006)
#

# Generates a robo key (purpose automation, age only) and an admin key
# (purpose admin, age + PIN2) and adds both to this key file, named
# robo-ssh-<stamp> and admin-ssh-<stamp>. `ocp init` writes them into
# keys.yaml; `ocp keys secure` (k96) into a staging file under .ocp/ that only
# becomes keys.yaml once every machine accepts the new admin key.
#
# ssh-keygen needs a file to write to, so each private half sits in .ocp/ in
# plaintext for as long as it takes to read it back -- removed before it is
# added here, so a failing add_key cannot leave it behind.
#
# Returns { automation => {...}, admin => {...} }, each with name, public and
# private: the caller that generated the keys has the admin private half in
# hand and need not ask for the PIN2 it just set to read it back.
sub add_cluster_keys {
    my ($self, %params) = @_;

    my $pin2 = $params{pin2};
    croak "add_cluster_keys: pin2 required" unless defined $pin2 && length $pin2;
    my $stamp = $params{datestamp} // _datestamp();

    my $secrets = OCP::Secrets->new(project_dir => $self->project_dir, ocp => $self->ocp);

    my %made;
    for my $tier ([ robo => 'automation', undef ], [ admin => 'admin', $pin2 ]) {
        my ($prefix, $purpose, $pin) = @$tier;
        my $name  = $prefix.'-ssh-'.$stamp;
        my $files = $secrets->generate_ssh_key(name => $name);

        my $private = path($files->{private_key})->slurp;
        my $public  = path($files->{public_key})->slurp;
        chomp $public;
        path($_)->remove for @$files{qw( private_key public_key )};

        $self->add_key(
            name    => $name,
            type    => 'ssh_ed25519',
            purpose => $purpose,
            private => $private,
            public  => $public,
            pin2    => $pin,
        );
        $made{$purpose} = { name => $name, purpose => $purpose, public => $public, private => $private };
    }

    return \%made;
}

=method add_cluster_keys(pin2 => $pin2, datestamp => $stamp)

Generates the pair a secure-mode project starts with -- C<robo-ssh-STAMP>
(C<purpose: automation>, age only) and C<admin-ssh-STAMP> (C<purpose: admin>,
age + PIN2) -- and adds both. C<datestamp> defaults to today (UTC,
C<YYYYMMDD>). Returns C<< { automation => {...}, admin => {...} } >>, each
with C<name>, C<public> and C<private>. C<ocp init> and C<ocp keys secure> use
it.

=cut

# Moves this key file to $target -- a staging file becoming keys.yaml (k96).
# Not a plain rename: the SOPS layer is written anew for the recipients
# $target has (OCP::Secrets::recipients_for), because a .sops.yaml rule that
# names keys.yaml does not match the staging file's name. The private halves
# inside keep their own layer and are carried over untouched. Returns the
# OCP::Keys for $target.
sub promote_to {
    my ($self, $target) = @_;

    my $data = $self->_read_keys_file_encrypted;
    croak "promote_to: ".$self->keys_file." holds no keys" unless $data && $data->{keys};

    my $dest = (ref $self)->new(
        project_dir => $self->project_dir,
        ocp         => $self->ocp,
        keys_file   => path($target),
    );
    $dest->_write_keys_file_encrypted($data);
    $self->keys_file->remove;

    return $dest;
}

=method promote_to($target)

Moves this key file to C<$target>, re-encrypting the SOPS layer for
C<$target>'s recipients, and returns the L<OCP::Keys> for it. C<ocp keys
secure> turns its staging file into F<keys.yaml> with it.

=cut

#
# Update key (new private half, public half, deprecated flag)
#

# A new private half is layered as add_key layers it, by the key's purpose
# (k411): an automation key age only, whatever pin2 holds -- robocop reads it
# unattended -- and every other key age + PIN2, with a PIN2 that is defined
# and not empty ("0" is one, k390). Without one it croaks before anything is
# written: an undefined or empty pin2 derived the layer from an empty
# password, a PIN2 layer in name only.
sub update_key {
    my ($self, $name, %params) = @_;

    my $data = $self->_read_keys_file_encrypted;
    return unless $data && $data->{keys};

    my $found = 0;
    for my $key (@{$data->{keys}}) {
        if ($key->{name} eq $name) {
            if ($params{private}) {
                my $pin2 = $params{pin2};
                if (($key->{purpose} // '') eq 'automation') {
                    $key->{private} = $self->_single_encrypt($params{private});
                } else {
                    croak "update_key: PIN2 required for the private half of non-automation key '$name'"
                        unless defined $pin2 && length $pin2;
                    $key->{private} = $self->_double_encrypt($params{private}, $pin2);
                }
            }
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

=method update_key($name, %params)

    $keys->update_key('admin-ssh-20260815', private => $pem, pin2 => $pin2);
    $keys->update_key('robo-ssh-20260815', private => $pem);
    $keys->update_key($name, deprecated => 1);

Changes the entry named C<$name>: C<private>, C<public>, C<deprecated>. A new
C<private> is layered by the key's purpose: an C<automation> key gets the age
layer only (a C<pin2> is ignored), every other key age + PIN2 and needs a
C<pin2> that is defined and not empty -- croaks without one, nothing written.
Returns 1, or nothing when there is no such key.

=cut

#
# The PIN2 layer of a key that should have one (k450)
#

# Before k390 a PIN2 of "0" was read as none, and add_key stored the admin
# key under the age layer alone, purpose still admin. Such an entry cannot be
# told from a layered one by its fields -- only by what is under its age
# layer: the private key itself, where a PIN2 layer is base64.
sub has_pin2_layer {
    my ($self, $name) = @_;

    my $key = $self->get_key($name)
        or croak "has_pin2_layer: no key '$name' in keys.yaml";
    croak "has_pin2_layer: key '$name' has no private half"
        unless defined $key->{private} && length $key->{private};

    my $inner = $self->_inner_decrypt($key->{private}, $name);
    return $self->_is_private_key_text($inner) ? 0 : 1;
}

=method has_pin2_layer($name)

    my @bare = grep { !$keys->has_pin2_layer($_->{name}) } @admin_entries;

1 when the private half of the key named C<$name> has a PIN2 layer under
its age layer, 0 when the age layer holds the private key itself -- an admin
key stored before k390 with a PIN2 of C<"0">, or an C<automation> key, which
never has one. Needs the project key (PIN1), never PIN2. Croaks for an
unknown name or an entry without a private half.

=cut

# Puts the missing PIN2 layer under the age layer of $name. The private key
# comes out of the age layer and goes back in under age + PIN2; the new half
# is opened with $pin2 before it is written, so keys.yaml never holds a layer
# that does not open to the key it replaces.
sub add_pin2_layer {
    my ($self, $name, $pin2) = @_;

    croak "add_pin2_layer: PIN2 required" unless defined $pin2 && length $pin2;

    my $data = $self->_read_keys_file_encrypted;
    my ($key) = grep { $_->{name} eq $name } @{ ($data && $data->{keys}) || [] };
    croak "add_pin2_layer: no key '$name' in keys.yaml" unless $key;
    croak "add_pin2_layer: key '$name' is an automation key, which has no PIN2 layer"
        if ($key->{purpose} // '') eq 'automation';
    croak "add_pin2_layer: key '$name' has no private half"
        unless defined $key->{private} && length $key->{private};

    my $private = $self->_inner_decrypt($key->{private}, $name);
    croak "add_pin2_layer: key '$name' has its PIN2 layer already"
        unless $self->_is_private_key_text($private);

    my $layered = $self->_double_encrypt($private, $pin2);
    croak "add_pin2_layer: the new layer of '$name' does not open to its key; nothing written"
        unless $self->_double_decrypt($layered, $pin2, $name) eq $private;

    $key->{private} = $layered;
    $key->{updated} = _timestamp();
    $self->_write_keys_file_encrypted($data);
    return 1;
}

=method add_pin2_layer($name, $pin2)

    $keys->add_pin2_layer('admin-ssh-20260815', $pin2);

Re-encrypts the private half of a key stored under the age layer alone (see
L</has_pin2_layer>) under age + PIN2, as L</add_key> stores a key with a
C<pin2>. The key itself is unchanged; the new half is checked to open with
C<$pin2> before F<keys.yaml> is written. Croaks -- nothing written -- for an
empty C<$pin2>, an unknown name, an C<automation> key, an entry without a
private half, and a key that has its PIN2 layer already (changing a PIN2 is
not this). C<ocp keys add-pin2> uses it.

=cut

# The age layer of an entry holds either a private key (no PIN2 layer) or
# base64 (the PIN2 layer). ssh-keygen and every key format OCP stores begin
# with a PEM armour line.
sub _is_private_key_text {
    my ($self, $text) = @_;
    return 0 unless defined $text;
    return $text =~ /\A\s*-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ ? 1 : 0;
}

#
# Deprecate key (mark for migration)
#

sub deprecate_key {
    my ($self, $name) = @_;

    return $self->update_key($name, deprecated => 1);
}

=method deprecate_key($name)

Mark key as deprecated (for migration tracking).

=cut

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

=method delete_key($name)

Remove key from keys.yaml.

=cut

#
# Decrypt key (PIN2 optional for automation keys)
#

sub decrypt_key {
    my ($self, $name, $pin2) = @_;

    my $key = $self->get_key($name) or return;

    # An operator key (k216) has no private half here: it never left the
    # operator's machine.
    die "ERROR: Key '$name' has no private half in keys.yaml (purpose "
      . ($key->{purpose} // '?') . "); its owner holds it.\n"
        unless defined $key->{private} && length $key->{private};

    # Detect encryption type
    my $decrypted;
    if ($key->{purpose} && $key->{purpose} eq 'automation') {
        # Single decrypt (age only)
        $decrypted = $self->_single_decrypt($key->{private}, $name);
    } else {
        # Double decrypt (age + password)
        croak "PIN2 required for non-automation key" unless defined $pin2 && length $pin2;
        $decrypted = $self->_double_decrypt($key->{private}, $pin2, $name);
    }

    return {
        name    => $key->{name},
        type    => $key->{type},
        purpose => $key->{purpose},
        private => $decrypted,
        public  => $key->{public},
    };
}

=method decrypt_key($name, $pin2)

Decrypt specific key, returns hashref with decrypted private key. C<$pin2> is
required unless the key's purpose is C<automation>. Dies, naming the key, for
an entry without a private half (an operator's).

To read only a public key, use C<list_keys>/C<get_key> and take the C<public>
field — that path needs no PIN2. C<ocp keys show> is the CLI for it.

=cut

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

    croak "PIN2 required for admin key" unless defined $pin2 && length $pin2;

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

# A wrong PIN2 does not come back as undef from get_admin_key: the PIN2
# layer's AES-GCM tag fails and _aes_decrypt dies with $WRONG_PIN2 -- crypto
# internals, not words for a user (k391). Every caller that asks for PIN2
# tells that failure from every other one here, in one place (k427): a
# .ocp/age.key that does not open keys.yaml fails with the right PIN2 too,
# and calling that a wrong PIN2 sends the operator after the wrong thing.
sub is_wrong_pin2 {
    my ($self, $error) = @_;
    return 0 unless defined $error && !ref $error;
    return $error eq $WRONG_PIN2 ? 1 : 0;
}

=method is_wrong_pin2($error)

    my $admin = eval { $keys->decrypt_key($name, $pin2) };
    warn "wrong PIN2\n" if !$admin && $keys->is_wrong_pin2($@);

True when C<$error> is the failure a wrong PIN2 makes -- the PIN2 layer's
authentication tag not matching -- and false for every other error, a
F<keys.yaml> the age key does not open included.

=cut

# get_admin_key, with a wrong PIN2 answered as "no key" instead of the
# crypto line. Every other failure is rethrown unchanged.
#
# Except an admin key without its PIN2 layer (k466): every PIN2 fails on it
# the way a wrong one does, so "Wrong PIN2" would send the operator after a
# PIN2 that does not exist. has_pin2_layer tells the two apart, and the
# refusal names the key and, in keys.yaml, the command that repairs it.
sub unlock_admin_key {
    my ($self, $pin2, $name) = @_;

    my $admin = eval { $self->get_admin_key($pin2, $name) };
    return $admin if $admin;
    my $error = $@;
    return unless length $error;
    die $error unless $self->is_wrong_pin2($error);

    # The key get_admin_key tried: the one named, or the first admin key
    # that is not deprecated.
    my ($tried) = defined $name && length $name
        ? ($name)
        : map  { $_->{name} }
          grep { ($_->{purpose} // '') eq 'admin' && !$_->{deprecated} } @{ $self->list_keys };
    die $self->_no_pin2_layer_refusal($tried)
        if defined $tried && !$self->has_pin2_layer($tried);
    return;
}

sub _no_pin2_layer_refusal {
    my ($self, $name) = @_;

    my $file = path($self->keys_file);
    my $msg  = "ERROR: The admin key '$name' in ".$file->basename." has no PIN2 layer, so no PIN2\n"
             . "       opens it: before the fix for a PIN2 of \"0\", ocp init and ocp keys\n"
             . "       secure stored it under PIN1 alone.\n";
    return $msg unless $file->absolute eq path($self->project_dir)->child('keys.yaml')->absolute;
    return $msg
         . "       Run 'ocp keys add-pin2' to set its PIN2. The key itself stays the\n"
         . "       same, so no machine needs a new one.\n";
}

=method unlock_admin_key($pin2, $name)

    my $admin = $keys->unlock_admin_key($pin2)
        or die "ERROR: Wrong PIN2 or no admin key\n";

L</get_admin_key> (the admin key named C<$name>, or the first one that is not
deprecated), returning nothing for a wrong PIN2 as for no admin key. Any
other failure -- a F<keys.yaml> the age key does not open, an empty C<$pin2>
-- dies with its own message, unchanged, so it is never reported as a wrong
PIN2. An admin key without its PIN2 layer (L</has_pin2_layer>), which no
PIN2 opens, dies naming the key, and for F<keys.yaml> names
C<ocp keys add-pin2>, which puts the layer on.

=cut

# decrypt_all_to_disk used to live here: it wrote every decrypted key to
# .ocp/keys/<name>[.pub]. It had no caller anywhere in lib/ or bin/, but its
# POD promised the layout, so the docs and a deploy plan both assumed
# .ocp/keys/ existed after `ocp init` — it never did. Worse than the missing
# feature was the shape of it: the only way to see a public key was a method
# that also spilled every private key onto the filesystem in plaintext.
#
# `ocp keys show` (OCP::Cmd::Keys::Show) answers the question that was
# actually being asked — "what do I put in authorized_keys?" — and answers it
# with the public half alone, on stdout, writing nothing.

#
# Single encryption: age only (for automation keys)
#

sub _single_encrypt {
    my ($self, $plaintext) = @_;

    my $recipient = $self->_get_age_recipient;
    my $age_encrypted = Crypt::Age->encrypt(
        plaintext  => $plaintext,
        recipients => [$recipient],
    );

    return $age_encrypted;
}

sub _single_decrypt {
    my ($self, $encrypted, $name) = @_;

    return $self->_inner_decrypt($encrypted, $name);
}

# The age layer of a private half. It is the project key's alone (k212); under
# SOPS_AGE_KEY_FILE an identity that is another recipient reads keys.yaml but
# not this, and gets told so instead of age's "no identity matched" (k216).
sub _inner_decrypt {
    my ($self, $encrypted, $name) = @_;

    my @identities = $self->_secrets->identities;

    my $plaintext = eval {
        Crypt::Age->decrypt(
            ciphertext => $encrypted,
            identities => \@identities,
        );
    };
    return $plaintext if defined $plaintext;

    my $err  = $@;
    my $file = $self->_secrets->sops_age_key_file;
    die $err unless $file;

    die "ERROR: The private half of " . (defined $name ? "'$name'" : 'this key')
      . " in keys.yaml opens for the project key alone,\n"
      . "       and this run decrypts with SOPS_AGE_KEY_FILE (".$file."),\n"
      . "       another recipient of the project: it reads keys.yaml, not the\n"
      . "       private SSH keys inside it. Run this with the project key (PIN1),\n"
      . "       or unset SOPS_AGE_KEY_FILE.\n";
}

#
# Double encryption: password-based AES + age
#

sub _double_encrypt {
    my ($self, $plaintext, $password) = @_;

    # Layer 1: the PIN2 layer, OCP's own -- Crypt::Age has no passphrase mode.
    # PBKDF2-HMAC-SHA256 (100_000 rounds) over a random 16-byte salt derives
    # the AES-256-GCM key (_derive_key, _aes_encrypt); the salt goes in front
    # of nonce . ciphertext . tag, and the whole is base64.
    my $salt = _random_bytes(16);
    my $key = _derive_key($password, $salt);
    my $encrypted_pw = _aes_encrypt($plaintext, $key);

    # Combine salt + encrypted
    my $pw_layer = encode_base64($salt . $encrypted_pw, '');

    # Layer 2: Age encryption (using age.key from project)
    my $recipient = $self->_get_age_recipient;
    my $age_encrypted = Crypt::Age->encrypt(
        plaintext  => $pw_layer,
        recipients => [$recipient],
    );

    return $age_encrypted;
}

sub _double_decrypt {
    my ($self, $encrypted, $password, $name) = @_;

    # Layer 1: Age decryption
    my $pw_layer = $self->_inner_decrypt($encrypted, $name);

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



    my $nonce = _random_bytes(12);  # 96-bit nonce
    my $ae = Crypt::AuthEnc::GCM->new('AES', $key, $nonce);
    my $ciphertext = $ae->encrypt_add($plaintext);
    my $tag = $ae->encrypt_done;

    # Return nonce + ciphertext + tag (16 bytes)
    return $nonce . $ciphertext . $tag;
}

sub _aes_decrypt {
    my ($encrypted, $key) = @_;



    my $nonce      = substr($encrypted, 0, 12);
    my $tag        = substr($encrypted, -16);
    my $ciphertext = substr($encrypted, 12, length($encrypted) - 28);

    my $ae = Crypt::AuthEnc::GCM->new('AES', $key, $nonce);
    my $plaintext = $ae->decrypt_add($ciphertext);
    my $ok = $ae->decrypt_done($tag);

    # A wrong PIN2 ends here; is_wrong_pin2 tells it from every other
    # failure by this line (k427; t/391-*.t, t/427-*.t).
    die $WRONG_PIN2 unless $ok;

    return $plaintext;
}

#
# Key derivation (PBKDF2)
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
    # A short read from the CSPRNG would silently weaken every key derived from
    # it (salt, nonce), so it is a hard failure, not a value to use as-is.
    croak "Short read from /dev/urandom: wanted $len bytes, got "
        . (defined $got ? $got : 'undef')
        unless defined $got && $got == $len;
    return $bytes;
}

#
# SOPS operations for keys.yaml (age encrypted)
#

sub _read_keys_file_encrypted {
    my ($self) = @_;

    return {} unless -f $self->keys_file;

    # A cached .ocp/age.key that is not the project's is refused as such,
    # not left to die in the SOPS read below (k428).
    $self->_secrets->check_cached_age_key;
    my @identities = $self->_secrets->identities;

    my $encrypted = $self->keys_file->slurp;

    return File::SOPS->decrypt(
        encrypted  => $encrypted,
        identities => \@identities,
        format     => 'yaml',
    );
}

sub _write_keys_file_encrypted {
    my ($self, $data) = @_;

    # The SOPS layer goes to every project recipient (k212); the private
    # halves inside keep their own layer for the project key alone.
    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => $self->_secrets->recipients_for($self->keys_file),
        format     => 'yaml',
    );

    $self->keys_file->spew($encrypted);
    return 1;
}

# The project key's recipient, for the inner layers. OCP::Secrets answers it
# the same way for the SOPS layer: .ocp/age.pub, or under SOPS_AGE_KEY_FILE
# read off the files -- never derived from that identity (k216).
sub _get_age_recipient {
    my ($self) = @_;

    return $self->_secrets->project_recipient;
}

#
# Helpers
#

sub _datestamp {
    my @t = gmtime;
    return sprintf('%04d%02d%02d', $t[5]+1900, $t[4]+1, $t[3]);
}

sub _timestamp {
    my @t = gmtime;
    return sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',
        $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
}

1;

__END__

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

    # Public halves need no PIN2 — see ENCRYPTION LAYERS below
    my ($admin) = grep { $_->{purpose} eq 'admin' } @{ $keys->list_keys };
    print $admin->{public};

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

F<keys.yaml> is a SOPS file: C<_write_keys_file_encrypted> encrypts B<every>
leaf value to the project's age recipient, so nothing in it — not the name,
not the public key — is readable without F<.ocp/age.key>.

    # keys.yaml on disk
    version: ENC[AES256_GCM,data:...]
    keys:
      - name: ENC[AES256_GCM,data:...]
        type: ENC[AES256_GCM,data:...]
        created: ENC[AES256_GCM,data:...]
        private: ENC[AES256_GCM,data:...]
        public: ENC[AES256_GCM,data:...]
        deprecated: ENC[AES256_GCM,data:...]
    sops:
      age: [...]

What the accessors here return is the file after that layer comes off:

    # after _read_keys_file_encrypted
    version: 1
    keys:
      - name: admin-ssh-20260815
        type: ssh_ed25519
        purpose: admin
        created: 2026-08-15T12:00:00Z
        private: |-                      # still encrypted, see below
          -----BEGIN AGE ENCRYPTED FILE-----
          ...
          -----END AGE ENCRYPTED FILE-----
        public: ssh-ed25519 AAAA...      # plaintext from here on
        deprecated: 0

=head1 ENCRYPTION LAYERS

The two layers do not apply uniformly, and the difference is the whole point:

=over 4

=item * B<public> is protected by the SOPS/age layer only. Once
F<.ocp/age.key> is unlocked (PIN1), C<list_keys> hands it back in plaintext.
No PIN2. This is what C<ocp keys show> prints.

=item * B<private> carries a second, PIN2-derived layer on top for
C<purpose: admin> keys (C<_double_encrypt>: PBKDF2 + AES-256-GCM, then age).
C<purpose: automation> keys get the age layer only (C<_single_encrypt>), so
robocop can use them unattended.

=back

So F<keys.yaml> alone is useless; F<keys.yaml> + F<age.key> yields the public
keys and the automation private key; the admin private key additionally needs
PIN2.

The age identity is the one L<OCP::Secrets/identities> names: the project key,
or the file C<SOPS_AGE_KEY_FILE> points at. The SOPS layer opens for
every recipient of the project; the inner layer of a private half is the
project key's alone, and another identity trying it is told so by name
instead of with age's own error.

B<operator> entries (C<purpose: operator>, written by
C<add_public_key>) have no C<private> at all, and an C<age> field: the
operator's age recipient. Their private SSH key never leaves the operator's
machine.

=head1 ATTRIBUTES

=head2 age_key

The project key in hand, as L<OCP::Secrets/unlock_age_key> leaves it in
L<OCP::Secrets/age_key>: every decrypt reads it instead of F<.ocp/age.key>.
C<undef> by default.

    $secrets->unlock_age_key;
    my $keys = OCP::Keys->new(project_dir => $dir, age_key => $secrets->age_key);
