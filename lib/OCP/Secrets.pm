package OCP::Secrets;
# ABSTRACT: Secret management for OCP using Crypt::Age and File::SOPS

use Moo;
use OCP;
use Path::Tiny qw(path);
use Carp qw(croak);
use Crypt::Age;
use File::SOPS;

our $VERSION = '0.1.0';

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

sub generate_age_key {
    my ($self) = @_;

    my $key_file = $self->age_key_file;
    my $pub_file = $self->age_recipient_file;

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

    require OCP::Password;
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

    require OCP::Password;
    my $encrypted = $self->age_key_enc_file->slurp;
    chomp $encrypted;

    my $age_key = OCP::Password::decrypt_age_key($encrypted, $password);

    # Write to .ocp/age.key (cached)
    $self->age_key_file->spew($age_key);
    $self->age_key_file->chmod(0600);

    return $age_key;
}

sub ensure_age_key {
    my ($self, $password) = @_;

    # If .ocp/age.key exists, we're good
    return 1 if $self->has_age_key;

    # Try to decrypt from age.key.enc
    if ($self->has_age_key_enc) {
        unless ($password) {
            require OCP::Password;
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

=cut
