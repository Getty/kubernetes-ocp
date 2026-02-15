package OCP::Cmd::Init;
# ABSTRACT: Initialize OCP project

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);

use OCP::Config;
use OCP::Secrets;

our $VERSION = '0.1.0';

option hetzner => (
    is    => 'ro',
    doc   => 'Initialize with Hetzner Cloud provider (interactive setup)',
);

option force => (
    is    => 'ro',
    short => 'f',
    doc   => 'Overwrite existing files',
);

option no_git => (
    is    => 'ro',
    doc   => 'Skip git initialization',
);

option name => (
    is     => 'ro',
    format => 's',
    doc    => 'Cluster name',
);

option dist => (
    is     => 'ro',
    format => 's',
    doc    => 'Kubernetes distribution: rke2 (default) or k3s',
);

option provider => (
    is     => 'ro',
    format => 's',
    doc    => 'Infrastructure provider: hetzner (default), ssh, or local',
);

option single => (
    is    => 'ro',
    doc   => 'Single-node cluster (control plane hosts workloads)',
);

option host => (
    is     => 'ro',
    format => 's',
    doc    => 'SSH host (for --provider=ssh)',
);

option service => (
    is     => 'ro',
    format => 's',
    doc    => 'Service manager: systemd or none (default: none for local, systemd for others)',
);

option ssh_key => (
    is     => 'ro',
    format => 's',
    doc    => 'Use existing SSH private key (e.g. ~/.ssh/id_ed25519)',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $project_dir = path('.');
    my $config_file = $chain->[0]->config;

    print "Initializing OCP project...\n\n";

    # Determine cluster name
    my $name = $self->name // $args->[0] // $project_dir->basename;

    # Check what already exists
    my $has_git       = -d '.git';
    my $has_config    = -f $config_file;
    my $has_gitignore = -f '.gitignore';
    my $has_ocp_dir   = -d '.ocp';

    my $secrets = OCP::Secrets->new(project_dir => $project_dir);

    #
    # Step 1: Git
    #
    if ($self->no_git) {
        print "[--] Skipping git (--no-git)\n";
    } elsif ($has_git) {
        print "[ok] Git repository exists\n";
    } else {
        print "[..] Initializing git repository\n";
        system('git', 'init', '--quiet');
        print "[ok] Git repository initialized\n";
    }

    #
    # Step 2: .gitignore
    #
    if ($self->no_git) {
        # Skip gitignore when git is disabled
    } elsif ($has_gitignore) {
        # Check if .ocp/ is already in gitignore
        my $content = path('.gitignore')->slurp;
        if ($content =~ /\.ocp\//) {
            print "[ok] .gitignore exists (has .ocp/)\n";
        } else {
            print "[..] Adding .ocp/ to .gitignore\n";
            path('.gitignore')->append("\n# OCP\n.ocp/\n");
            print "[ok] Updated .gitignore\n";
        }
    } else {
        print "[..] Creating .gitignore\n";
        path('.gitignore')->spew(_gitignore_content());
        print "[ok] Created .gitignore\n";
    }

    #
    # Step 3: .ocp directory
    #
    if ($has_ocp_dir) {
        print "[ok] .ocp/ directory exists\n";
    } else {
        print "[..] Creating .ocp/ directory\n";
        path('.ocp')->mkpath;
        print "[ok] Created .ocp/\n";
    }

    #
    # Step 4: Age key
    #
    if ($secrets->has_age_key) {
        print "[ok] Age encryption key exists\n";
    } else {
        print "[..] Generating age encryption key\n";
        my $keys = $secrets->generate_age_key;
        print "[ok] Generated age key: $keys->{public_key}\n";
    }

    #
    # Step 5: SSH key
    #
    if ($self->ssh_key) {
        # Use existing SSH key
        my $key_path = $self->ssh_key;
        $key_path =~ s/^~/$ENV{HOME}/;  # Expand ~

        unless (-f $key_path) {
            die "SSH key not found: $key_path\n";
        }

        my $pub_path = "$key_path.pub";
        unless (-f $pub_path) {
            die "SSH public key not found: $pub_path\n";
        }

        # Copy keys to .ocp/
        use File::Copy qw(copy);
        copy($key_path, '.ocp/id_ed25519') or die "Failed to copy private key: $!";
        copy($pub_path, '.ocp/id_ed25519.pub') or die "Failed to copy public key: $!";
        chmod 0600, '.ocp/id_ed25519';
        chmod 0644, '.ocp/id_ed25519.pub';

        print "[ok] Using existing SSH key: $key_path\n";
    } elsif ($secrets->has_ssh_key) {
        print "[ok] SSH key exists\n";
    } else {
        print "[..] Generating SSH key\n";
        my $keys = $secrets->generate_ssh_key;
        print "[ok] Generated SSH key: $keys->{public_key}\n";
    }

    #
    # Step 6: Hetzner token (if --hetzner)
    #
    if ($self->hetzner) {
        my $token = $secrets->hetzner_token;
        if ($token) {
            print "[ok] Hetzner token configured\n";
        } else {
            print "\n";
            print "Hetzner Cloud API Token required.\n";
            print "Get one at: https://console.hetzner.cloud/ -> Project -> Security -> API tokens\n\n";
            print "Enter Hetzner API token: ";
            my $input = <STDIN>;
            chomp $input;

            if ($input) {
                $secrets->set_hetzner_token($input);
                print "[ok] Hetzner token saved (encrypted)\n";
            } else {
                print "[!!] No token provided. Set HETZNER_API_TOKEN or run 'ocp init --hetzner' again.\n";
            }
        }
    }

    #
    # Step 7: ocp.yaml
    #
    if ($has_config && !$self->force) {
        print "[ok] $config_file exists\n";
    } else {
        print "[..] Creating $config_file\n";

        # Determine provider (default based on flags)
        my $provider = $self->provider // ($self->hetzner ? 'hetzner' : 'hetzner');
        my $dist = $self->dist // 'rke2';

        my %opts = (
            name             => $name,
            dist             => $dist,
            provider         => $provider,
            single_node      => $self->single,
            host             => $self->host,
            service          => $self->service,
            ssh_private_key  => '.ocp/id_ed25519',
            ssh_public_key   => '.ocp/id_ed25519.pub',
        );

        OCP::Config->write_spec($config_file, %opts);
        print "[ok] Created $config_file\n";
    }

    #
    # Summary
    #
    print "\n";
    print "=" x 50, "\n";
    print "OCP project initialized: $name\n";
    print "=" x 50, "\n\n";

    print "Files created:\n";
    print "  ocp.yaml        - Cluster specification (edit this)\n";
    print "  secrets.yaml    - Encrypted secrets\n" if $secrets->has_secrets_file;
    print "  .ocp/           - Status & keys (local only)\n";
    print "  .gitignore      - Git ignore rules\n" unless $self->no_git;

    # SSH provider instructions (only if new key was generated)
    my $init_provider = $self->provider // ($self->hetzner ? 'hetzner' : 'hetzner');
    if ($init_provider eq 'ssh' && !$self->ssh_key) {
        # Only show instructions if we generated a NEW key
        my $pubkey_path = path('.ocp/id_ed25519.pub');
        if (-f $pubkey_path) {
            my $pubkey = $pubkey_path->slurp;
            chomp $pubkey;
            print "\n";
            print "!" x 50, "\n";
            print "SSH PROVIDER - Manual Setup Required\n";
            print "!" x 50, "\n\n";
            print "Add this public key to your server:\n\n";
            print "  $pubkey\n\n";
            print "Commands to run on your server";
            print " (${\($self->host)})" if $self->host;
            print ":\n";
            print "  mkdir -p ~/.ssh\n";
            print "  echo '$pubkey' >> ~/.ssh/authorized_keys\n";
            print "  chmod 700 ~/.ssh\n";
            print "  chmod 600 ~/.ssh/authorized_keys\n";
        }
    } elsif ($init_provider eq 'ssh' && $self->ssh_key) {
        # Using existing key - no setup needed
        print "\n";
        print "[ok] Using existing SSH key - no manual setup needed\n";
    }

    print "\n";
    print "Next steps:\n";
    if ($init_provider eq 'ssh' && !$self->ssh_key) {
        # New key generated - need manual copy
        print "  1. Add SSH key to your server (see above)\n";
        print "  2. Review and edit ocp.yaml\n";
        print "  3. Run: ocp apply\n";
    } elsif ($init_provider eq 'ssh' && $self->ssh_key) {
        # Existing key - ready to go
        print "  1. Review and edit ocp.yaml\n";
        print "  2. Run: ocp apply\n";
    } elsif ($init_provider eq 'hetzner') {
        print "  1. Review and edit ocp.yaml\n";
        print "  2. Run: ocp apply (SSH key will be uploaded automatically)\n";
    } else {
        print "  1. Review and edit ocp.yaml\n";
        print "  2. Run: ocp apply\n";
    }
    print "\n";
}

sub _gitignore_content {
    return <<'GITIGNORE';
# OCP - Omni Control Plane
.ocp/

# Editor
*~
*.swp
.idea/
.vscode/

# OS
.DS_Store
Thumbs.db
GITIGNORE
}

1;

__END__

=head1 NAME

OCP::Cmd::Init - Initialize OCP project

=head1 SYNOPSIS

    # Basic init
    ocp init

    # With name
    ocp init --name mycluster

    # Full Hetzner setup (interactive)
    ocp init --hetzner

    # Without git initialization
    ocp init --no-git

=head1 DESCRIPTION

Initializes an OCP project with intelligent defaults. Checks what already
exists and only creates what's missing.

With --hetzner, prompts for Hetzner API token and stores it encrypted
using SOPS/age.

With --no-git, skips git repository initialization and .gitignore creation.

=cut
