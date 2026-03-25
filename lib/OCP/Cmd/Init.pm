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
use OCP::UI;

with 'OCP::Role::Cmd';

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

    # No flags given -> just use defaults (directory name, rke2, hetzner)
    # TUI wizard disabled for now

    my $project_dir = path('.');
    my $config_file = $self->ocp->config;

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
    if ($self->{_wizard_ssh_ref_path}) {
        # Reference mode: use external key path as-is, no generation/copying
        my $ref_path = $self->{_wizard_ssh_ref_path};
        $ref_path =~ s/^~/$ENV{HOME}/;
        unless (-f $ref_path) {
            die "Referenced SSH key not found: $ref_path\n";
        }
        print "[ok] Using referenced SSH key: $self->{_wizard_ssh_ref_path}\n";
    }
    else {


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

    } # end else (not reference mode)

    #
    # Step 6: Hetzner token
    #
    if ($self->{_wizard_token}) {
        # Token from wizard - save now that age key exists
        $secrets->set_hetzner_token($self->{_wizard_token});
        print "[ok] Hetzner token saved (encrypted)\n";
    } elsif ($self->hetzner) {
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

        # SSH key paths: reference mode uses external path, others use .ocp/
        if ($self->{_wizard_ssh_ref_path}) {
            my $ref = $self->{_wizard_ssh_ref_path};  # keep original (with ~ if any)
            $opts{ssh_private_key} = $ref;
            $opts{ssh_public_key}  = "$ref.pub";
        } else {
            $opts{ssh_private_key} = '.ocp/id_ed25519';
            $opts{ssh_public_key}  = '.ocp/id_ed25519.pub';
        }

        # Wizard-generated cps/workers take priority
        if ($self->{_wizard_cps}) {
            $opts{cps} = $self->{_wizard_cps};
            $opts{workers} = $self->{_wizard_workers}
                if $self->{_wizard_workers} && @{$self->{_wizard_workers}};
        } else {
            # CLI flags path
            my $provider = $self->provider // ($self->hetzner ? 'hetzner' : 'ssh');

            # Validate: SSH provider requires --host
            if ($provider eq 'ssh' && !$self->host) {
                die "ERROR: SSH provider requires --host parameter.\n\n" .
                    "Did you mean:\n" .
                    "  ocp init --provider ssh --host yourserver.com\n" .
                    "  ocp init --provider local (for localhost)\n";
            }

            $opts{provider} = $provider;
            $opts{host}     = $self->host;
            $opts{service}  = $self->service;
        }

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
    my $init_provider = $self->provider // ($self->hetzner ? 'hetzner' : 'ssh');
    if ($self->{_wizard_ssh_ref_path}) {
        # Reference mode: key already exists externally
        print "\n";
        print "[ok] SSH key referenced: $self->{_wizard_ssh_ref_path}\n";
        print "     Ensure this key is authorized on your servers.\n";
    } elsif ($init_provider eq 'ssh' && !$self->ssh_key) {
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

sub _run_init_wizard {
    my ($self) = @_;


    my $project_dir = path('.');
    my $secrets = OCP::Secrets->new(project_dir => $project_dir);

    # Page 1: Basics
    my $basics = OCP::UI->new(
        title  => 'OCP Init',
        fields => [
            { name => 'name', type => 'text', label => 'Cluster Name',
              default => path('.')->absolute->basename },
            { name => 'dist', type => 'choice', label => 'Distribution',
              options => [
                  { label => 'RKE2 (recommended)', value => 'rke2' },
                  { label => 'K3s (lightweight)',   value => 'k3s' },
              ], default => 'rke2' },
        ],
    )->run;
    return undef unless $basics;

    # CP loop: jeder CP einzeln, verschiedene Provider mischbar
    my @cps;
    my $hetzner_token;
    my $hz;  # OCP::Hetzner instance, cached

    # Build context from basics for sub-pages
    my @base_ctx = (
        { label => 'Cluster Name', value => $basics->{name} },
        { label => 'Distribution', value => $basics->{dist} },
    );

    while (1) {
        my $cp = eval {
            $self->_wizard_add_cp($secrets, \$hetzner_token, \$hz, scalar @cps, \@base_ctx)
        };
        if ($@) {
            print "\nError: $@\n";
            return undef;
        }
        last unless $cp;  # Cancel
        # _wizard_add_cp returns HashRef (single) or ArrayRef (batch)
        if (ref $cp eq 'ARRAY') {
            push @cps, @$cp;
        } else {
            push @cps, $cp;
        }

        # Noch einen?
        my $more = OCP::UI->new(
            title   => sprintf('OCP Init - %d CP(s) configured', scalar @cps),
            context => \@base_ctx,
            fields  => [
                { name => 'add_more', type => 'choice', label => 'Add another CP?',
                  options => [
                      { label => 'No, done',  value => 'no' },
                      { label => 'Yes, add',  value => 'yes' },
                  ], default => 'no' },
            ],
        )->run;
        last unless $more && $more->{add_more} eq 'yes';
    }

    return undef unless @cps;

    # Summary: show configured CPs
    my @cp_summary;
    for my $i (0 .. $#cps) {
        my $cp = $cps[$i];
        my $desc = $cp->{provider};
        $desc .= " ($cp->{host})" if $cp->{host};
        $desc .= " ($cp->{serverType} @ $cp->{location})" if $cp->{serverType};
        push @cp_summary, { label => sprintf('CP %d', $i + 1), value => $desc };
    }

    # Worker providers?
    my @workers;
    my $worker_ask = OCP::UI->new(
        title   => 'OCP Init - Summary',
        context => [@base_ctx, @cp_summary],
        fields  => [
            { name => 'add_workers', type => 'choice', label => 'Add worker node providers?',
              options => [
                  { label => 'No (single-node / robocop later)', value => 'no' },
                  { label => 'Yes, configure workers',           value => 'yes' },
              ], default => 'no' },
        ],
    )->run;
    return undef unless $worker_ask;

    if ($worker_ask->{add_workers} eq 'yes') {
        my @w_ctx = (@base_ctx, @cp_summary);
        while (1) {
            my $w = eval {
                $self->_wizard_add_worker($secrets, \$hetzner_token, \$hz,
                    scalar @workers, \@w_ctx)
            };
            if ($@) {
                print "\nError: $@\n";
                return undef;
            }
            last unless $w;
            push @workers, $w;

            my $more = OCP::UI->new(
                title   => sprintf('OCP Init - %d worker pool(s)', scalar @workers),
                context => \@w_ctx,
                fields  => [
                    { name => 'add_more', type => 'choice', label => 'Add another worker pool?',
                      options => [
                          { label => 'No, done',  value => 'no' },
                          { label => 'Yes, add',  value => 'yes' },
                      ], default => 'no' },
                ],
            )->run;
            last unless $more && $more->{add_more} eq 'yes';
        }
    }

    # Determine cluster endpoint
    my $first_cp = $cps[0];
    my $endpoint;
    if ($first_cp->{host}) {
        $endpoint = $first_cp->{host};
    } elsif ($first_cp->{provider} eq 'hetzner') {
        $endpoint = '(assigned after deploy)';
    } elsif ($first_cp->{provider} eq 'local') {
        $endpoint = 'localhost';
    } else {
        $endpoint = '(unknown)';
    }

    # Build full summary context
    my @worker_summary;
    for my $i (0 .. $#workers) {
        my $w = $workers[$i];
        my $desc = "$w->{provider}";
        $desc .= " ($w->{host})" if $w->{host};
        $desc .= " ($w->{serverType} @ $w->{location})" if $w->{serverType};
        $desc .= " x$w->{nodes}" if ($w->{nodes} // 1) > 1;
        push @worker_summary, { label => "Worker ${\($i+1)}", value => $desc };
    }

    my @full_ctx = (
        @base_ctx, @cp_summary,
        @worker_summary,
        { label => 'API Endpoint', value => $endpoint },
    );

    # Security mode?
    my $sec = OCP::UI->new(
        title   => 'OCP Init - Security',
        context => \@full_ctx,
        fields  => [
            { name => 'security', type => 'choice', label => 'Security Mode',
              options => [
                  { label => 'Secure (PIN1 + PIN2)', value => 'secure' },
                  { label => 'No password (dev)',    value => 'nopassword' },
              ], default => 'secure' },
        ],
    )->run;
    return undef unless $sec;

    my $nopassword = $sec->{security} eq 'nopassword';
    push @full_ctx, { label => 'Security', value => $nopassword ? 'no password' : 'PIN1 + PIN2' };

    # SSH key handling (only for remote providers)
    my $has_remote = grep { $_->{provider} ne 'local' } @cps;
    my $ssh_key_mode = 'generate';
    my $ssh_key_path;

    if ($has_remote) {
        my $ssh_q = OCP::UI->new(
            title   => 'OCP Init - SSH Key',
            context => \@full_ctx,
            fields  => [
                { name => 'ssh_mode', type => 'choice', label => 'SSH Key',
                  options => [
                      { label => 'Generate new',     value => 'generate' },
                      { label => 'Copy existing',    value => 'copy' },
                      { label => 'Reference by path', value => 'reference' },
                  ], default => 'generate' },
            ],
        )->run;
        return undef unless $ssh_q;

        $ssh_key_mode = $ssh_q->{ssh_mode};

        if ($ssh_key_mode eq 'copy' || $ssh_key_mode eq 'reference') {
            my $path_q = OCP::UI->new(
                title   => 'OCP Init - SSH Key Path',
                context => [@full_ctx, { label => 'SSH Key', value => $ssh_key_mode }],
                fields  => [
                    { name => 'path', type => 'text', label => 'Private key path',
                      default => '~/.ssh/id_ed25519' },
                ],
            )->run;
            return undef unless $path_q;
            $ssh_key_path = $path_q->{path};
        }

        my $key_desc = $ssh_key_mode;
        $key_desc .= " ($ssh_key_path)" if $ssh_key_path;
        push @full_ctx, { label => 'SSH Key', value => $key_desc };
    }

    # Final confirmation
    my $confirm = OCP::UI->new(
        title   => 'OCP Init - Confirm',
        context => \@full_ctx,
        fields  => [
            { name => 'confirm', type => 'choice', label => 'Start initialization?',
              options => [
                  { label => 'Yes, create project', value => 'yes' },
                  { label => 'Cancel',              value => 'no' },
              ], default => 'yes' },
        ],
    )->run;
    return undef unless $confirm && $confirm->{confirm} eq 'yes';

    return {
        name           => $basics->{name},
        dist           => $basics->{dist},
        cps            => \@cps,
        workers        => \@workers,
        hetzner_token  => $hetzner_token,
        nopassword     => $nopassword,
        ssh_key_mode   => $ssh_key_mode,
        ssh_key_path   => $ssh_key_path,
    };
}

sub _wizard_add_cp {
    my ($self, $secrets, $token_ref, $hz_ref, $cp_num, $base_ctx) = @_;


    my @ctx = @{$base_ctx // []};

    # Provider Auswahl
    my $prov = OCP::UI->new(
        title   => sprintf('OCP Init - Control Plane %d', $cp_num + 1),
        context => \@ctx,
        fields  => [
            { name => 'provider', type => 'choice', label => 'CP Provider',
              options => [
                  { label => 'Hetzner Cloud', value => 'hetzner' },
                  { label => 'SSH (existing)', value => 'ssh' },
                  { label => 'Local',          value => 'local' },
              ], default => 'hetzner' },
        ],
    )->run;
    return undef unless $prov;

    my $provider = $prov->{provider};
    my @cp_ctx = (@ctx, { label => 'CP Provider', value => $provider });

    if ($provider eq 'hetzner') {
        # Token holen/testen (einmalig)
        $$token_ref //= $secrets->hetzner_token;
        unless ($$token_ref) {
            my $tok = OCP::UI->new(
                title   => 'OCP Init - Hetzner Token',
                context => \@cp_ctx,
                fields  => [
                    { name => 'token', type => 'text', label => 'API Token' },
                ],
            )->run;
            return undef unless $tok;
            $$token_ref = $tok->{token};
            die "No Hetzner API token provided.\n" unless $$token_ref;
        }

        unless ($$hz_ref) {
            print "Testing Hetzner API connection... ";

            $$hz_ref = OCP::Hetzner->new(token => $$token_ref);
            $$hz_ref->location_options;  # Test: dies if token invalid
            print "OK\n\n";
        }

        my $details = OCP::UI->new(
            title   => sprintf('OCP Init - Hetzner CP %d+', $cp_num + 1),
            context => \@cp_ctx,
            fields  => [
                { name => 'count', type => 'choice', label => 'How many?',
                  options => [
                      { label => '1 (single)',  value => '1' },
                      { label => '3 (HA)',      value => '3' },
                  ], default => '1' },
                { name => 'location', type => 'choice', label => 'Location',
                  options => $$hz_ref->location_options,
                  default => 'fsn1' },
                { name => 'server_type', type => 'choice', label => 'Server Type',
                  options => $$hz_ref->server_type_options,
                  default => 'cpx21' },
            ],
        )->run;
        return undef unless $details;

        my $cp = {
            provider   => 'hetzner',
            serverType => $details->{server_type},
            location   => $details->{location},
            image      => 'debian-13',
        };
        my $count = $details->{count} // 1;
        # Return ArrayRef for batch (compacted later by write_spec)
        return [($cp) x $count];
    }
    elsif ($provider eq 'ssh') {
        my $ssh = OCP::UI->new(
            title   => sprintf('OCP Init - SSH CP %d', $cp_num + 1),
            context => \@cp_ctx,
            fields  => [
                { name => 'host', type => 'text', label => 'SSH Host' },
            ],
        )->run;
        return undef unless $ssh;

        return { provider => 'ssh', host => $ssh->{host} };
    }
    elsif ($provider eq 'local') {
        return { provider => 'local' };
    }

    return undef;
}

sub _wizard_add_worker {
    my ($self, $secrets, $token_ref, $hz_ref, $pool_num, $base_ctx) = @_;


    my @ctx = @{$base_ctx // []};

    my $prov = OCP::UI->new(
        title   => sprintf('OCP Init - Worker Pool %d', $pool_num + 1),
        context => \@ctx,
        fields  => [
            { name => 'name', type => 'text', label => 'Pool Name',
              default => sprintf('pool%d', $pool_num + 1) },
            { name => 'provider', type => 'choice', label => 'Provider',
              options => [
                  { label => 'Hetzner Cloud', value => 'hetzner' },
                  { label => 'SSH (existing)', value => 'ssh' },
              ], default => 'hetzner' },
        ],
    )->run;
    return undef unless $prov;

    my $provider = $prov->{provider};
    my @w_ctx = (@ctx, { label => 'Worker Provider', value => $provider });

    if ($provider eq 'hetzner') {
        $$token_ref //= $secrets->hetzner_token;
        unless ($$token_ref) {
            my $tok = OCP::UI->new(
                title   => 'OCP Init - Hetzner Token',
                context => \@w_ctx,
                fields  => [
                    { name => 'token', type => 'text', label => 'API Token' },
                ],
            )->run;
            return undef unless $tok;
            $$token_ref = $tok->{token};
            die "No Hetzner API token provided.\n" unless $$token_ref;
        }

        unless ($$hz_ref) {
            print "Testing Hetzner API connection... ";

            $$hz_ref = OCP::Hetzner->new(token => $$token_ref);
            $$hz_ref->location_options;
            print "OK\n\n";
        }

        my $details = OCP::UI->new(
            title   => sprintf('OCP Init - Hetzner Workers %d', $pool_num + 1),
            context => \@w_ctx,
            fields  => [
                { name => 'nodes', type => 'choice', label => 'Nodes',
                  options => [
                      { label => '1', value => '1' },
                      { label => '2', value => '2' },
                      { label => '3', value => '3' },
                  ], default => '1' },
                { name => 'location', type => 'choice', label => 'Location',
                  options => $$hz_ref->location_options,
                  default => 'fsn1' },
                { name => 'server_type', type => 'choice', label => 'Server Type',
                  options => $$hz_ref->server_type_options,
                  default => 'cpx21' },
            ],
        )->run;
        return undef unless $details;

        return {
            name       => $prov->{name},
            provider   => 'hetzner',
            serverType => $details->{server_type},
            location   => $details->{location},
            image      => 'debian-13',
            nodes      => $details->{nodes},
        };
    }
    elsif ($provider eq 'ssh') {
        my $ssh = OCP::UI->new(
            title   => sprintf('OCP Init - SSH Worker %d', $pool_num + 1),
            context => \@w_ctx,
            fields  => [
                { name => 'host', type => 'text', label => 'SSH Host' },
            ],
        )->run;
        return undef unless $ssh;

        return {
            name     => $prov->{name},
            provider => 'ssh',
            host     => $ssh->{host},
        };
    }

    return undef;
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
