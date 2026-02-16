package OCP::Cmd::Init;
# ABSTRACT: Initialize OCP project

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);
use File::Copy qw(copy move);

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

option nogit => (
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

option nopassword => (
    is    => 'ro',
    doc   => 'Disable encryption (local dev only)',
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
    if ($self->nogit) {
        print "[--] Skipping git (--nogit)\n";
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
    if ($self->nogit) {
        # Skip gitignore when git is disabled
    } elsif ($has_gitignore) {
        # Check if .ocp/ and .kube/ are already in gitignore
        my $content = path('.gitignore')->slurp;
        my $needs_update = 0;
        my $append = "\n# OCP\n";

        unless ($content =~ /\.ocp\//) {
            $append .= ".ocp/\n";
            $needs_update = 1;
        }

        unless ($content =~ /\.kube\//) {
            $append .= ".kube/\n";
            $needs_update = 1;
        }

        if ($needs_update) {
            print "[..] Updating .gitignore\n";
            path('.gitignore')->append($append);
            print "[ok] Updated .gitignore\n";
        } else {
            print "[ok] .gitignore exists (has .ocp/ and .kube/)\n";
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
    # Step 4.5: Password-protect age.key (DEFAULT unless --nopassword)
    #
    unless ($self->nopassword) {
        if ($secrets->has_age_key_enc) {
            print "[ok] age.key.enc exists (password-protected)\n";
        } else {
            print "\n";
            print "Security Setup (Defense in Depth)\n";
            print "═" x 60, "\n";
            print "PIN1: Encrypts age.key (cluster access)\n";
            print "PIN2: Encrypts admin SSH key (server access)\n";
            print "Share PINs securely with team (NOT in git!)\n";
            print "═" x 60, "\n\n";

            require OCP::Password;
            my $pin1 = OCP::Password::prompt_password("Enter PIN1 (cluster access): ");
            my $pin1_confirm = OCP::Password::prompt_password("Confirm PIN1: ");

            if ($pin1 ne $pin1_confirm) {
                die "PIN1 passwords don't match!\n";
            }

            print "[..] Encrypting age.key with PIN1\n";
            $secrets->encrypt_age_key_with_password($pin1);
            print "[ok] age.key.enc created (git this!)\n";
            print "\n";
        }
    }

    #
    # Step 5: SSH keys (Two-Tier: robocop + admin)
    #
    require OCP::Keys;
    my $keys_mgr = OCP::Keys->new(project_dir => $project_dir);

    if ($self->nopassword) {
        # Dev mode: No encryption, use existing or generate simple key
        if ($self->ssh_key) {
            my $key_path = $self->ssh_key;
            $key_path =~ s/^~/$ENV{HOME}/;

            unless (-f $key_path) {
                die "SSH key not found: $key_path\n";
            }

            use File::Copy qw(copy);
            copy($key_path, '.ocp/id_ed25519') or die "Failed to copy private key: $!\n";
            if (-f "$key_path.pub") {
                copy("$key_path.pub", '.ocp/id_ed25519.pub');
            }
            chmod 0600, '.ocp/id_ed25519';

            print "[ok] Using existing SSH key (no encryption): $key_path\n";
        } else {
            print "[..] Generating SSH key (no encryption)\n";
            my $ssh_keys = $secrets->generate_ssh_key;
            print "[ok] Generated SSH key: $ssh_keys->{public_key}\n";
        }
    } else {
        # Secure mode (default): Two-tier SSH keys in keys.yaml
        my $existing = $keys_mgr->list_keys;

        if (@$existing && grep { $_->{purpose} eq 'automation' } @$existing) {
            print "[ok] SSH keys exist in keys.yaml\n";
        } else {
            print "[..] Generating two-tier SSH keys\n";

            my $datestamp = _datestamp();

            # Generate robo-ssh key (automation, age only)
            my $robo_keys = $secrets->generate_ssh_key;
            move('.ocp/id_ed25519', ".ocp/robo-ssh-$datestamp") or die $!;
            move('.ocp/id_ed25519.pub', ".ocp/robo-ssh-$datestamp.pub") or die $!;

            my $robo_private = path(".ocp/robo-ssh-$datestamp")->slurp;
            my $robo_public = path(".ocp/robo-ssh-$datestamp.pub")->slurp;
            chomp $robo_public;

            # Generate admin-ssh key (requires PIN2)
            my $admin_keys = $secrets->generate_ssh_key;
            move('.ocp/id_ed25519', ".ocp/admin-ssh-$datestamp") or die $!;
            move('.ocp/id_ed25519.pub', ".ocp/admin-ssh-$datestamp.pub") or die $!;

            my $admin_private = path(".ocp/admin-ssh-$datestamp")->slurp;
            my $admin_public = path(".ocp/admin-ssh-$datestamp.pub")->slurp;
            chomp $admin_public;

            # Prompt for PIN2 (admin SSH access)
            require OCP::Password;
            my $pin2 = OCP::Password::prompt_password("Enter PIN2 (admin SSH access): ");
            my $pin2_confirm = OCP::Password::prompt_password("Confirm PIN2: ");

            if ($pin2 ne $pin2_confirm) {
                die "PIN2 passwords don't match!\n";
            }

            # Add robo-key (age only, no PIN2)
            $keys_mgr->add_key(
                name    => "robo-ssh-$datestamp",
                type    => 'ssh_ed25519',
                purpose => 'automation',
                private => $robo_private,
                public  => $robo_public,
                pin2    => undef,  # No PIN2 for automation!
            );

            # Add admin-key (age + PIN2)
            $keys_mgr->add_key(
                name    => "admin-ssh-$datestamp",
                type    => 'ssh_ed25519',
                purpose => 'admin',
                private => $admin_private,
                public  => $admin_public,
                pin2    => $pin2,
            );

            # Cleanup: Remove temporary key files (keys are now in keys.yaml!)
            unlink ".ocp/robo-ssh-$datestamp";
            unlink ".ocp/robo-ssh-$datestamp.pub";
            unlink ".ocp/admin-ssh-$datestamp";
            unlink ".ocp/admin-ssh-$datestamp.pub";

            print "[ok] Generated SSH keys:\n";
            print "     - robo-ssh-$datestamp (automation, age encrypted)\n";
            print "     - admin-ssh-$datestamp (admin, age+PIN2 encrypted)\n";
            print "     Stored in keys.yaml (encrypted)\n";
        }
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

        # Validate: SSH provider requires --host
        if ($provider eq 'ssh' && !$self->host) {
            die "ERROR: SSH provider requires --host parameter.\n\n" .
                "Did you mean:\n" .
                "  ocp init --provider ssh --host yourserver.com\n" .
                "  ocp init --provider local (for localhost)\n";
        }

        # Local provider is always single-node
        my $single_node = $self->single || ($provider eq 'local');

        my %opts = (
            name             => $name,
            dist             => $dist,
            provider         => $provider,
            single_node      => $single_node,
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
    print "  keys.yaml       - Encrypted SSH keys (git ✓)\n" unless $self->nopassword;
    print "  secrets.yaml    - Encrypted secrets (git ✓)\n" if $secrets->has_secrets_file;
    if ($secrets->has_age_key_enc) {
        print "  age.key.enc     - Password-protected age key (git ✓)\n";
    }
    print "  .ocp/           - Keys & cache (gitignored)\n";
    print "  .gitignore      - Git ignore rules\n" unless $self->nogit;
    print "\n";

    if ($secrets->has_age_key_enc) {
        print "🔐 Security (Defense in Depth - Two-Tier SSH Keys):\n";
        print "  PIN1: Encrypts age.key (cluster access)\n";
        print "  PIN2: Encrypts admin SSH key (control plane deployment)\n";
        print "\n";
        print "  admin-key:\n";
        print "    - Control plane deployment (ocp apply)\n";
        print "    - Manual SSH access (ocp ssh)\n";
        print "    - Protected with age+PIN2 encryption\n";
        print "\n";
        print "  robo-key:\n";
        print "    - Worker node automation ONLY (used by robocop controller)\n";
        print "    - Protected with age encryption (no PIN2)\n";
        print "    - Injected into robocop memory (never on disk!)\n";
        print "    - CANNOT access control planes!\n";
        print "\n";
        print "  Team sharing: Repo (git) + PIN1 + PIN2 (via 1Password/Signal)\n";
    } elsif (!$self->nopassword) {
        print "🔐 Security Notes:\n";
        print "  Two-tier SSH keys stored in keys.yaml (encrypted)\n";
        print "  Admin key: Control planes + manual SSH\n";
        print "  Robocop key: Workers only (automation)\n";
    } else {
        print "⚠️  Dev Mode (--nopassword):\n";
        print "  Single SSH key in .ocp/id_ed25519 (NOT encrypted)\n";
        print "  For development only! Use default mode for production.\n";
    }

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
    unless ($self->nopassword) {
        print "  1. Review and edit ocp.yaml\n";
        print "  2. Deploy control plane: ocp apply (requires PIN2)\n";
        print "  3. Deploy robocop (optional): ocp deploy robocop\n";
        print "  4. Inject robocop key: ocp inject-key (requires PIN2)\n";
        print "  5. Add workers via CRDs (robocop automates this)\n";
    } else {
        # Dev mode
        print "  1. Review and edit ocp.yaml\n";
        print "  2. Deploy cluster: ocp apply\n";
        print "  3. Test with: kubectl get nodes\n";
    }
    print "\n";
}

sub _gitignore_content {
    return <<'GITIGNORE';
# OCP - Omni Control Plane
.ocp/
.kube/

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

sub _datestamp {
    my @t = gmtime;
    return sprintf('%04d%02d%02d', $t[5]+1900, $t[4]+1, $t[3]);
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
    ocp init --nogit

=head1 DESCRIPTION

Initializes an OCP project with intelligent defaults. Checks what already
exists and only creates what's missing.

With --hetzner, prompts for Hetzner API token and stores it encrypted
using SOPS/age.

With --nogit, skips git repository initialization and .gitignore creation.

=cut
