package OCP::Cmd::Init;
# ABSTRACT: Initialize OCP project

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);
use File::Copy qw(copy move);

use OCP;
use OCP::Config;
use OCP::Hetzner;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

option hetzner => (
    is    => 'ro',
    doc   => 'Prompt for a Hetzner Cloud API token and store it encrypted',
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

# The provider that lands in ocp.yaml. Hetzner is the default because that is
# what the spec means everywhere else: OCP::Config's _default_spec, write_spec
# and validation all read an absent provider as hetzner. It is also the only
# default under which a bare `ocp init` can do its job — scaffolding a project
# it cannot know the answers for yet — instead of dying on a missing --host.
# The token is a separate, later step (--hetzner), so init stays offline.
has _provider => (
    is      => 'lazy',
    builder => sub { $_[0]->provider // 'hetzner' },
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $project_dir = path('.');
    my $config_file = $self->ocp->config;

    print "Initializing OCP project...\n\n";

    # Determine cluster name (--name flag or directory basename)
    my $name = $self->name // $project_dir->realpath->basename;

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
        # .ocp/ is the only thing OCP needs ignored — see _gitignore_content.
        my $content = path('.gitignore')->slurp;

        if ($content =~ /\.ocp\//) {
            print "[ok] .gitignore exists (has .ocp/)\n";
        } else {
            print "[..] Updating .gitignore\n";
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
    my $keys_mgr = OCP::Keys->new(project_dir => $project_dir);

    if ($self->nopassword) {
        # Dev mode: No encryption
        my $key_path = $self->ssh_key // '.ocp/id_ed25519';
        $key_path =~ s/^~/$ENV{HOME}/;

        if (-f $key_path) {
            # Key exists - copy to .ocp/ if it's an external path
            if ($key_path ne '.ocp/id_ed25519') {
                copy($key_path, '.ocp/id_ed25519') or die "Failed to copy private key: $!\n";
                copy("$key_path.pub", '.ocp/id_ed25519.pub') if -f "$key_path.pub";
                chmod 0600, '.ocp/id_ed25519';
                print "[ok] Copied SSH key from $key_path\n";
            } else {
                print "[ok] SSH key exists (.ocp/id_ed25519)\n";
            }
        } else {
            die "SSH key not found: $key_path\n" if $self->ssh_key;
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
            my $robo_name = "robo-ssh-$datestamp";
            $secrets->generate_ssh_key(name => $robo_name);

            my $robo_private = path(".ocp/$robo_name")->slurp;
            my $robo_public = path(".ocp/$robo_name.pub")->slurp;
            chomp $robo_public;

            # Generate admin-ssh key (requires PIN2)
            my $admin_name = "admin-ssh-$datestamp";
            $secrets->generate_ssh_key(name => $admin_name);

            my $admin_private = path(".ocp/$admin_name")->slurp;
            my $admin_public = path(".ocp/$admin_name.pub")->slurp;
            chomp $admin_public;

            # Prompt for PIN2 (admin SSH access)

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
    # Step 6: Hetzner token
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
                print "[!!] No token provided. Run 'ocp init --hetzner' again.\n";
            }
        }
    }

    #
    # Step 7: ocp.yaml
    #
    if ($has_config && !$self->force) {
        print "[ok] $config_file exists\n";

        # Augment: add missing sections to existing config
        my $augmented = $self->_augment_existing_config($config_file);
        if ($augmented) {
            print "     Added missing config: $augmented\n";
        }
    } else {
        print "[..] Creating $config_file\n";

        my $dist = $self->dist // 'rke2';

        my %opts = (
            name             => $name,
            dist             => $dist,
        );

        # Detect system settings (timezone, locale) from current machine
        my $system = _detect_system_settings();
        $opts{system} = $system if $system && %$system;

        $opts{ssh_private_key} = '.ocp/id_ed25519';
        $opts{ssh_public_key}  = '.ocp/id_ed25519.pub';

        my $provider = $self->_provider;

        # Validate: SSH provider requires --host
        if ($provider eq 'ssh' && !$self->host) {
            die "ERROR: SSH provider requires --host parameter.\n\n" .
                "Did you mean:\n" .
                "  ocp init --provider ssh --host yourserver.com\n" .
                "  ocp init --provider local (for localhost)\n" .
                "  ocp init (for Hetzner Cloud, the default provider)\n";
        }

        $opts{provider} = $provider;
        $opts{host}     = $self->host;
        $opts{service}  = $self->service;

        OCP::Config->write_spec($config_file, %opts);
        print "[ok] Created $config_file\n";
        if ($system && %$system) {
            my @parts;
            push @parts, "timezone: $system->{timezone}" if $system->{timezone};
            push @parts, "locale: $system->{locale}" if $system->{locale};
            print "     System: ", join(', ', @parts), " (detected from host)\n" if @parts;
        }
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
    my $init_provider = $self->_provider;
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

    # Hetzner is the default provider, so a bare `ocp init` can land here
    # without the user ever having been asked for a token. Say so now rather
    # than letting `ocp apply` be the one to find out.
    if ($init_provider eq 'hetzner' && !$secrets->hetzner_token) {
        print "\n";
        print "!" x 50, "\n";
        print "HETZNER PROVIDER - API Token Required\n";
        print "!" x 50, "\n\n";
        print "ocp.yaml uses the Hetzner provider (the default).\n";
        print "Store a token before deploying:\n\n";
        print "  ocp init --hetzner\n\n";
        print "Or switch to a machine you already have:\n";
        print "  ocp init --force --provider ssh --host yourserver.com\n";
        print "  ocp init --force --provider local\n";
    }

    print "\n";
    print "Next steps:\n";
    unless ($self->nopassword) {
        print "  1. Review and edit ocp.yaml\n";
        print "  2. Deploy control plane: ocp apply (requires PIN2)\n";
        print "  3. Inspect cluster: ocp status\n";
        print "  4. Export kubeconfig: ocp kubeconfig -e\n";
    } else {
        # Dev mode
        print "  1. Review and edit ocp.yaml\n";
        print "  2. Deploy cluster: ocp apply\n";
        print "  3. Inspect cluster: ocp status\n";
        print "  4. Export kubeconfig: ocp kubeconfig -e\n";
    }
    print "\n";

    return 0;
}

# Only .ocp/ belongs here. Everything OCP writes outside it — keys.yaml,
# secrets.yaml, age.key.enc, kubeconfig.yaml — is encrypted and MUST stay
# committable; an entry that swallows one of those only shows up when a
# colleague clones the project and finds the cluster unreachable.
sub _gitignore_content {
    return <<'GITIGNORE';
# OCP - Omni Control Plane
# Decrypted state and cache. The encrypted files (keys.yaml, secrets.yaml,
# age.key.enc, kubeconfig.yaml) belong in git — do not ignore them.
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

sub _datestamp {
    my @t = gmtime;
    return sprintf('%04d%02d%02d', $t[5]+1900, $t[4]+1, $t[3]);
}

sub _augment_existing_config {
    my ($self, $config_file) = @_;

    my $ocp = OCP->instance;
    my $spec = $ocp->load_file($config_file);
    return unless $spec && ref $spec eq 'HASH';

    my @added;

    # system section: detect and add if missing
    unless (exists $spec->{system}) {
        my $system = _detect_system_settings();
        if ($system && %$system) {
            $spec->{system} = $system;
            my @parts;
            push @parts, "timezone=$system->{timezone}" if $system->{timezone};
            push @parts, "locale=$system->{locale}" if $system->{locale};
            push @added, "system (" . join(', ', @parts) . ")" if @parts;
        }
    }

    # Future: add more missing sections here
    # e.g. unless (exists $spec->{registry}) { ... }

    if (@added) {
        $ocp->dump_file($config_file, $spec);
        return join(', ', @added);
    }

    return;
}

sub _detect_system_settings {
    my %system;

    # Detect timezone
    my $tz = _detect_timezone();
    $system{timezone} = $tz if $tz && $tz ne 'UTC';

    # Detect locale
    my $locale = _detect_locale();
    $system{locale} = $locale if $locale && $locale ne 'en_US.UTF-8';

    # NTP defaults to true, only write if different
    # (always enabled by default, no need to detect)

    return \%system;
}

sub _detect_timezone {
    # Method 0: TZ environment variable (Docker pass-through)
    my $tz = $ENV{TZ} // '';
    return $tz if $tz =~ m{/};

    # Method 1: timedatectl (systemd)
    $tz = `timedatectl show -p Timezone --value 2>/dev/null`;
    chomp $tz if defined $tz;
    return $tz if $tz && $tz =~ m{/};

    # Method 2: /etc/timezone (Debian/Ubuntu)
    if (-f '/etc/timezone') {
        $tz = path('/etc/timezone')->slurp;
        chomp $tz;
        return $tz if $tz && $tz =~ m{/};
    }

    # Method 3: readlink /etc/localtime
    if (-l '/etc/localtime') {
        my $link = readlink('/etc/localtime') // '';
        if ($link =~ m{/zoneinfo/(.+)$}) {
            return $1;
        }
    }

    return 'UTC';
}

sub _detect_locale {
    # Method 1: localectl (systemd)
    my $locale = `localectl show-locale 2>/dev/null | grep '^LANG=' | sed 's/LANG=//'`;
    chomp $locale if defined $locale;
    return $locale if $locale && $locale =~ /\./;

    # Method 2: environment variable
    $locale = $ENV{LANG} // '';
    return $locale if $locale && $locale =~ /\./;

    # Method 3: /etc/default/locale
    if (-f '/etc/default/locale') {
        my $content = path('/etc/default/locale')->slurp;
        if ($content =~ /^LANG=["']?([^"'\s]+)/m) {
            return $1;
        }
    }

    return 'en_US.UTF-8';
}


1;

__END__

=head1 NAME

OCP::Cmd::Init - Initialize OCP project

=head1 SYNOPSIS

    # Basic init (Hetzner Cloud, the default provider)
    ocp init

    # With name
    ocp init --name mycluster

    # Full Hetzner setup (interactive)
    ocp init --hetzner

    # A machine you already have
    ocp init --provider ssh --host yourserver.com
    ocp init --provider local

    # Without git initialization
    ocp init --nogit

=head1 DESCRIPTION

Initializes an OCP project with intelligent defaults. Checks what already
exists and only creates what's missing.

The provider defaults to C<hetzner>, which is what an absent provider means
everywhere else in the spec (see L<OCP::Config>). C<--provider ssh> needs
C<--host>; C<--provider local> targets the machine C<ocp> runs on.

With --hetzner, prompts for Hetzner API token and stores it encrypted
using SOPS/age. Without it, init stays offline and only warns that a token
is still missing.

With --nogit, skips git repository initialization and .gitignore creation.
The generated F<.gitignore> ignores F<.ocp/> only: the encrypted files
(F<keys.yaml>, F<secrets.yaml>, F<age.key.enc>, F<kubeconfig.yaml>) are
meant to be committed.

=cut
