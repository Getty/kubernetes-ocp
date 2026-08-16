package OCP::Secrets;
# ABSTRACT: Secret management for OCP using Crypt::Age and File::SOPS

use Moo;
use OCP;
use OCP::Password;
use Path::Tiny qw(path);
use Carp qw(croak);
use Crypt::Age;
use Crypt::Age::Keys;
use File::SOPS;

has ocp => (
    is      => 'lazy',
    default => sub { OCP->instance },
);

has project_dir => (
    is       => 'ro',
    required => 1,
);

has secrets_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('secrets.yaml') },
);

has age_key_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('.ocp', 'age.key') },
);

has age_recipient_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('.ocp', 'age.pub') },
);

has kubeconfig_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('kubeconfig.yaml') },
);

has age_key_enc_file => (
    is      => 'lazy',
    builder => sub { shift->project_dir->child('age.key.enc') },
);

#
# Age key management
#

sub has_age_key {
    my ($self) = @_;
    return -f $self->age_key_file;
}

# The SOPS files OCP writes. Every one of them records, in plaintext, the age
# recipient its data key is wrapped for:
#
#     sops:
#       age:
#       - enc: |
#           -----BEGIN AGE ENCRYPTED FILE-----
#         recipient: age1...
#
# That block is readable without holding any key, which makes it the honest
# answer to "which age key does this project belong to" — as opposed to
# has_age_key, which only answers "is there one on this machine".
sub _sops_files {
    my ($self) = @_;
    return map { $self->project_dir->child($_) }
        qw(keys.yaml secrets.yaml kubeconfig.yaml);
}

# Which committed files are bound to which recipient. Returns a list of
# { file => 'keys.yaml', recipient => 'age1...' } — names, not a boolean,
# because every caller is about to tell a human what stands in the way.
sub age_key_bindings {
    my ($self) = @_;

    my @bindings;
    for my $file ($self->_sops_files) {
        next unless -f $file;

        my $data = eval { $self->ocp->load($file->slurp) };
        next unless $data && ref $data eq 'HASH';

        my $age = $data->{sops} && $data->{sops}{age};
        next unless $age && ref $age eq 'ARRAY';

        for my $entry (@$age) {
            next unless ref $entry eq 'HASH';
            my $recipient = $entry->{recipient};
            next unless defined $recipient && length $recipient;
            push @bindings, {
                file      => $file->basename,
                recipient => $recipient,
            };
        }
    }

    return \@bindings;
}

sub project_age_recipients {
    my ($self) = @_;

    my %seen;
    return [ grep { !$seen{$_}++ }
             map  { $_->{recipient} } @{ $self->age_key_bindings } ];
}

# Does this PROJECT already have an age key — even one this checkout does not
# hold? .ocp/ is gitignored (ADR 0004), so a clone has age.key.enc and the
# encrypted files but never .ocp/age.key. Asking has_age_key there and
# generating on "no" is what karr #86 was: a fresh key written over
# .ocp/age.pub, and keys.yaml bound to a recipient nobody has any more.
sub project_has_age_key {
    my ($self) = @_;

    return 1 if $self->has_age_key;
    return 1 if $self->has_age_key_enc;
    return @{ $self->age_key_bindings } ? 1 : 0;
}

# Everything a new key would orphan. A lone .ocp/age.pub is deliberately not
# on this list: nothing is encrypted to it, so replacing it costs nothing.
sub _age_key_blockers {
    my ($self) = @_;

    my %seen;
    my @blockers;
    push @blockers, 'age.key.enc' if $self->has_age_key_enc;
    push @blockers, grep { !$seen{$_}++ }
                    map  { $_->{file} } @{ $self->age_key_bindings };

    return \@blockers;
}

sub generate_age_key {
    my ($self) = @_;

    my $key_file = $self->age_key_file;
    my $pub_file = $self->age_recipient_file;

    # The safety net for karr #86, placed here rather than in the caller so it
    # holds for any path to generation — present or added later. A generated
    # keypair is always new, so it can never be the recipient the committed
    # files already name; writing .ocp/age.pub from it is therefore always the
    # damaging move whenever anything is bound.
    my $blockers = $self->_age_key_blockers;
    if (@$blockers) {
        croak
            "Refusing to generate a new age key: this project already has one.\n"
          . "  Bound to it: " . join(', ', @$blockers) . "\n"
          . "A new key would replace .ocp/age.pub, and none of those files could\n"
          . "be decrypted again. Unlock the existing key with PIN1 (age.key.enc),\n"
          . "or copy .ocp/age.key from whoever set the project up — .ocp/ is\n"
          . "gitignored, so a clone never carries it.";
    }

    # Ensure .ocp directory exists
    $key_file->parent->mkpath;

    # Generate key using Crypt::Age
    my ($public_key, $secret_key) = Crypt::Age->generate_keypair;

    # Write files
    $key_file->spew($secret_key . "\n");
    $key_file->chmod(0600);

    $pub_file->spew($public_key . "\n");

    return {
        public_key => $public_key,
        secret_key => $secret_key,
    };
}

sub age_recipient {
    my ($self) = @_;
    return undef unless -f $self->age_recipient_file;
    my $recipient = $self->age_recipient_file->slurp;
    chomp $recipient;
    return $recipient;
}

# The public half of an age secret key. X25519, so it is derivable — there is
# never a reason to guess at a recipient or to mint a new key just because
# .ocp/age.pub is missing.
sub _recipient_of_key {
    my ($self, $secret_key) = @_;

    my $secret = $secret_key;
    chomp $secret;

    return Crypt::Age::Keys->public_key_from_secret($secret);
}

# Does this secret key open what the project is bound to? Called before any
# write that would act on the key's authority, so a stale or foreign
# age.key.enc fails here — with the two recipients named — instead of later,
# as an opaque "could not decrypt data key with any of the provided
# identities" from three commands down.
sub _assert_key_matches_project {
    my ($self, $secret_key) = @_;

    my $bound = $self->age_key_bindings;
    return 1 unless @$bound;

    my $public = $self->_recipient_of_key($secret_key);
    return 1 if grep { $_->{recipient} eq $public } @$bound;

    croak
        "This age key does not belong to this project.\n"
      . "  The key opens:   $public\n"
      . join('', map { sprintf "  %-16s %s\n", "$_->{file} needs:", $_->{recipient} }
                 @$bound)
      . "Nothing was done. Use the key those files name.";
}

# Does the key in this checkout open what the project is bound to? Croaks
# with both recipients named when it does not. That is the state an old
# `ocp init` left a fresh clone in — a minted key sitting next to committed
# files it cannot read — and without this the only symptom is "could not
# decrypt data key with any of the provided identities" from wherever the run
# happens to reach first.
sub check_local_age_key {
    my ($self) = @_;

    return 0 unless $self->has_age_key;
    return $self->_assert_key_matches_project($self->age_key_file->slurp);
}

# Rebuild .ocp/age.pub from .ocp/age.key when it is missing. Every encrypt
# path reads it — create_secrets, save_kubeconfig, OCP::Keys::add_key — so a
# checkout that unlocked age.key.enc but has no recipient file can decrypt
# everything and encrypt nothing.
#
# It never overwrites an existing recipient file: that file is what the
# committed material is bound to, and replacing it is the whole failure mode
# this guards against.
sub restore_age_recipient {
    my ($self) = @_;

    return 0 if -f $self->age_recipient_file;
    return 0 unless $self->has_age_key;

    my $secret = $self->age_key_file->slurp;
    $self->_assert_key_matches_project($secret);

    my $public = $self->_recipient_of_key($secret);

    $self->age_recipient_file->parent->mkpath;
    $self->age_recipient_file->spew($public . "\n");

    return $public;
}

#
# Password-encrypted age.key (Defense in Depth!)
#

sub has_age_key_enc {
    my ($self) = @_;
    return -f $self->age_key_enc_file;
}

sub encrypt_age_key_with_password {
    my ($self, $password) = @_;

    unless ($self->has_age_key) {
        croak "No age.key found. Run generate_age_key first.";
    }


    my $age_key = $self->age_key_file->slurp;
    my $encrypted = OCP::Password::encrypt_age_key($age_key, $password);

    $self->age_key_enc_file->spew($encrypted);
    return 1;
}

sub decrypt_age_key_with_password {
    my ($self, $password) = @_;

    unless ($self->has_age_key_enc) {
        croak "No age.key.enc found.";
    }


    my $encrypted = $self->age_key_enc_file->slurp;
    chomp $encrypted;

    my $age_key = OCP::Password::decrypt_age_key($encrypted, $password);

    # Before caching it: is this the key the project's files are bound to?
    # Caching a mismatched key would make has_age_key say yes from then on,
    # and every later run would fail at the SOPS layer instead of here.
    $self->_assert_key_matches_project($age_key);

    # Write to .ocp/age.key (cached)
    $self->age_key_file->spew($age_key);
    $self->age_key_file->chmod(0600);

    # ...and the recipient half, which a clone has no other source for.
    $self->restore_age_recipient;

    return $age_key;
}

sub ensure_age_key {
    my ($self, $password) = @_;

    # If .ocp/age.key exists, we're good
    if ($self->has_age_key) {
        $self->restore_age_recipient;
        return 1;
    }

    # Try to decrypt from age.key.enc
    if ($self->has_age_key_enc) {
        unless ($password) {
        
            $password = OCP::Password::prompt_password("Enter PIN1 (cluster access): ");
        }
        $self->decrypt_age_key_with_password($password);
        return 1;
    }

    # No age.key available
    croak "No age.key found. Run 'ocp init' first.";
}

#
# SOPS operations
#

sub has_secrets_file {
    my ($self) = @_;
    return -f $self->secrets_file;
}

sub create_secrets {
    my ($self, %secrets) = @_;

    my $recipient = $self->age_recipient
        or croak "No age recipient found. Run generate_age_key first.";

    # Encrypt with File::SOPS
    my $encrypted = File::SOPS->encrypt(
        data       => \%secrets,
        recipients => [$recipient],
        format     => 'yaml',
    );

    $self->secrets_file->spew($encrypted);
    return 1;
}

sub read_secret {
    my ($self, $key) = @_;

    return undef unless $self->has_secrets_file;

    my $secrets = $self->read_all_secrets;
    return $secrets->{$key};
}

sub read_all_secrets {
    my ($self) = @_;

    return {} unless $self->has_secrets_file;

    my $identity = $self->age_key_file->slurp;
    chomp $identity;
    # The same guard the write paths use: a foreign key in .ocp/age.key
    # must surface as the named-recipients error, not as File::SOPS's
    # opaque "could not decrypt data key" line (karr #118).
    $self->_assert_key_matches_project($identity);

    my $encrypted = $self->secrets_file->slurp;

    return File::SOPS->decrypt(
        encrypted  => $encrypted,
        identities => [$identity],
        format     => 'yaml',
    );
}

sub update_secret {
    my ($self, $key, $value) = @_;

    my $secrets = $self->read_all_secrets;
    $secrets->{$key} = $value;

    $self->create_secrets(%$secrets);
}

#
# SSH key management
#

sub has_ssh_key {
    my ($self) = @_;
    my $key_path = $self->project_dir->child('.ocp', 'id_ed25519');
    return -f $key_path;
}

sub generate_ssh_key {
    my ($self, %opts) = @_;

    my $name = $opts{name} // 'id_ed25519';
    my $key_path = $self->project_dir->child('.ocp', $name);
    my $pub_path = $self->project_dir->child('.ocp', "$name.pub");

    # Ensure .ocp directory exists
    $key_path->parent->mkpath;

    # Remove existing file to avoid ssh-keygen "Overwrite?" prompt
    unlink $key_path->stringify if -f $key_path;
    unlink $pub_path->stringify if -f $pub_path;

    # Generate ED25519 key
    my $cmd = "ssh-keygen -t ed25519 -N '' -f '$key_path' -C 'ocp-cluster-key'";
    system($cmd);

    if ($? != 0) {
        croak "Failed to generate SSH key";
    }

    $key_path->chmod(0600);

    return {
        private_key => $key_path->stringify,
        public_key  => $pub_path->stringify,
    };
}

#
# Hetzner token helpers
#

sub hetzner_token {
    my ($self) = @_;

    # First check environment
    return $ENV{HETZNER_API_TOKEN} if $ENV{HETZNER_API_TOKEN};

    # Then check secrets file
    return $self->read_secret('hetzner_token');
}

sub set_hetzner_token {
    my ($self, $token) = @_;

    if ($self->has_secrets_file) {
        $self->update_secret('hetzner_token', $token);
    } else {
        $self->create_secrets(hetzner_token => $token);
    }
}

#
# Kubeconfig management (encrypted file)
#

sub has_kubeconfig {
    my ($self) = @_;
    return -f $self->kubeconfig_file;
}

sub save_kubeconfig {
    my ($self, $kubeconfig_yaml) = @_;

    my $recipient = $self->age_recipient
        or croak "No age recipient found. Generate age key first.";

    # Encrypt kubeconfig with SOPS
    my $encrypted = File::SOPS->encrypt(
        data       => $self->ocp->load($kubeconfig_yaml),
        recipients => [$recipient],
        format     => 'yaml',
    );

    $self->kubeconfig_file->spew($encrypted);
    return 1;
}

sub read_kubeconfig {
    my ($self) = @_;

    return undef unless $self->has_kubeconfig;

    my $identity = $self->age_key_file->slurp;
    chomp $identity;
    # Same guard as the write paths — karr #118.
    $self->_assert_key_matches_project($identity);

    my $encrypted = $self->kubeconfig_file->slurp;

    my $decrypted = File::SOPS->decrypt(
        encrypted  => $encrypted,
        identities => [$identity],
        format     => 'yaml',
    );

    return $self->ocp->dump($decrypted);
}

sub decrypt_kubeconfig_to_file {
    my ($self, $target_file) = @_;

    my $kubeconfig = $self->read_kubeconfig
        or croak "No kubeconfig found";

    # Ensure parent directory exists
    my $target = path($target_file);
    $target->parent->mkpath;

    $target->spew($kubeconfig);
    $target->chmod(0600);

    return $target->stringify;
}

#
# Generic encrypted file helper
#

sub encrypt_file {
    my ($self, $content, $file) = @_;

    my $recipient = $self->age_recipient
        or croak "No age recipient found";

    # If content is YAML string, parse it first
    my $data = ref($content) ? $content : $self->ocp->load($content);

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$recipient],
        format     => 'yaml',
    );

    my $file_path = $self->project_dir->child($file);
    $file_path->spew($encrypted);

    return 1;
}

sub decrypt_file {
    my ($self, $file) = @_;

    my $file_path = $self->project_dir->child($file);
    return undef unless -f $file_path;

    my $identity = $self->age_key_file->slurp;
    chomp $identity;
    # Same guard as the write paths — karr #118.
    $self->_assert_key_matches_project($identity);

    my $encrypted = $file_path->slurp;

    my $decrypted = File::SOPS->decrypt(
        encrypted  => $encrypted,
        identities => [$identity],
        format     => 'yaml',
    );

    return $self->ocp->dump($decrypted);
}

1;

__END__

=head1 NAME

OCP::Secrets - Secret management for OCP using SOPS and age

=head1 SYNOPSIS

    use OCP::Secrets;

    my $secrets = OCP::Secrets->new(project_dir => path('.'));

    # Generate encryption key
    $secrets->generate_age_key;

    # Store Hetzner token
    $secrets->set_hetzner_token('xxx');

    # Read token
    my $token = $secrets->hetzner_token;

=head1 DESCRIPTION

OCP::Secrets manages encrypted secrets using File::SOPS with Crypt::Age encryption.
Secrets are stored in C<secrets.yaml> (encrypted) and the age key is
stored in C<.ocp/age.key>.

This module uses pure Perl implementations (Crypt::Age and File::SOPS)
and does not require any external CLI tools.

=head1 WHOSE KEY IS IT

F<.ocp/> is gitignored; F<keys.yaml>, F<secrets.yaml>, F<kubeconfig.yaml> and
F<age.key.enc> are committed. So "is there an age key on this machine" and
"does this project have an age key" are B<different questions>, and a checkout
that confuses them mints a new key over F<.ocp/age.pub> and orphans everything
the project ever encrypted (karr #86).

=over 4

=item C<has_age_key> — is F<.ocp/age.key> here? Machine-local.

=item C<project_has_age_key> — does the project have one at all, held or not?

=back

=head2 age_key_bindings

Returns an arrayref of C<< { file => 'keys.yaml', recipient => 'age1...' } >>
for every committed SOPS file. SOPS records its recipient in plaintext, so
this reads without any key — which is what makes it usable I<before> deciding
whether to generate.

=head2 project_age_recipients

The deduplicated recipients from L</age_key_bindings>.

=head2 project_has_age_key

True when F<.ocp/age.key> or F<age.key.enc> exists, or when any committed SOPS
file names a recipient. This is the question to ask before generating.

=head2 generate_age_key

Generates a keypair into F<.ocp/age.key> and F<.ocp/age.pub>.

B<Croaks> when anything is already bound to a recipient (F<age.key.enc> or a
SOPS file). A generated keypair is always new, so it can never be the
recipient those files name — writing F<.ocp/age.pub> from it would always be
the destructive move. The guard sits here, below every command, so it holds
for paths added later as well.

=head2 restore_age_recipient

Rebuilds F<.ocp/age.pub> from F<.ocp/age.key> when it is missing — the public
half is derivable (X25519), so a clone that unlocked F<age.key.enc> does not
need a stored copy in order to encrypt again. It never overwrites an existing
recipient file, and refuses outright when the local key does not open what the
project is bound to.

=cut
