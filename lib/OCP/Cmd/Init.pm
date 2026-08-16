package OCP::Cmd::Init;
# ABSTRACT: Initialize OCP project

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);
use File::Copy qw(copy move);

use OCP;
use OCP::Choices;
use OCP::Config;
use OCP::Hetzner::Picker;
use OCP::Keys;
use OCP::Password;
use OCP::Provider;
use OCP::Secrets;

with 'OCP::Role::Cmd';

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

# Whether it is safe to ask the user anything. A pipe, a CI job or the test
# suite has no one to answer, so every prompt below has to fall back to its
# default rather than block. Kept as an attribute so tests can set it.
has _interactive => (
    is      => 'lazy',
    builder => sub { -t STDIN ? 1 : 0 },
);

# Catalogue wrapper for the location/server-type pickers. Built from the
# stored token when it is needed; injectable so tests stay network-free.
has _picker => (is => 'rw');

# What the pickers settled on. Undef means "never asked" — write_spec then
# applies OCP::Config's defaults exactly as before.
has _location    => (is => 'rw');
has _server_type => (is => 'rw');

sub execute {
    my ($self, $args, $chain) = @_;

    # Validate enum-shaped options before any side effect. The doc strings on
    # these options already advertise the valid set; refusing a typo at the
    # option boundary is the same discipline karr #67, #89 and #103 applied
    # elsewhere -- the rejection names what would have worked. A typo here
    # used to sail through CLI parsing and die far downstream (karr #124):
    # `ocp init --dist rke3` reached write_spec, `ocp init --provider
    # hetzner-cloud` wrote a spec with no control_planes block, and
    # `ocp init --ssh-key ~/.ssh/id_ed25519.pub` copied the public half into
    # the private slot.
    if (defined $self->dist && !grep { $_ eq $self->dist } qw(rke2 k3s)) {
        die OCP::Choices::unknown('dist', $self->dist, [ qw(rke2 k3s) ]);
    }

    if (defined $self->provider && !OCP::Provider->known_type($self->provider)) {
        die OCP::Choices::unknown('provider', $self->provider,
            [ OCP::Provider->types ]);
    }

    if (defined $self->service && !grep { $_ eq $self->service } qw(systemd none)) {
        die OCP::Choices::unknown('service', $self->service, [ qw(systemd none) ]);
    }

    # --ssh-key takes the PRIVATE half: the .pub convention is universal
    # enough that "ends in .pub" catches the mistake the field exists for
    # (copying the public key into the private slot). No Available: line
    # here -- there is no second valid value, only a shape.
    if (defined $self->ssh_key && $self->ssh_key =~ /\.pub\z/) {
        die OCP::Choices::unknown('SSH key', $self->ssh_key, [],
            hint => "--ssh-key takes the PRIVATE key (no .pub extension);"
                  . " the public half is ssh_key + '.pub'.\n",
        );
    }

    # --host is only meaningful with --provider ssh. The converse -- ssh
    # without --host -- is the existing check further down; this one is the
    # silent counterpart karr #124 flagged: --host with any non-ssh provider
    # is dropped on the floor by write_spec (only the ssh branch reads it).
    if (defined $self->host && $self->_provider ne 'ssh') {
        die OCP::Choices::unknown('--host target', $self->host, [],
            hint => "--host is only used with --provider ssh; this init"
                  . " writes provider: " . $self->_provider
                  . " and --host would be ignored.\n",
        );
    }

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
    $self->_ensure_age_key($secrets);

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
    # Step 5a: Bootstrap SSH key (.ocp/id_ed25519)
    #
    $self->_ensure_bootstrap_key($secrets);

    #
    # Step 5b: Two-Tier SSH keys (robocop + admin) — secure mode only
    #
    my $keys_mgr = OCP::Keys->new(project_dir => $project_dir);

    unless ($self->nopassword) {
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
    # Step 6.5: Hetzner location and server type
    #
    # The catalogue is only readable once the token is in hand, so the pickers
    # sit directly behind the token step — and only on the path that asked for
    # a token in the first place. Whatever is not answered stays at the
    # defaults OCP::Config writes anyway, so a run without a terminal, without
    # a token or with the API unreachable produces the same ocp.yaml as before.
    if ($self->hetzner && $self->_provider eq 'hetzner' && (!$has_config || $self->force)) {
        $self->_prompt_hetzner_control_plane($secrets);
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

        # Only set when a picker actually ran; write_spec falls back to
        # OCP::Config's defaults for anything left undef.
        $opts{location}    = $self->_location    if $self->_location;
        $opts{server_type} = $self->_server_type if $self->_server_type;

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
        # A bootstrap key in a secure-mode project is a leftover from before
        # the two-tier decision. It is kept — machines may still have it in
        # authorized_keys — but nothing in OCP reaches for it here any more,
        # and saying so is the difference between a smooth migration and an
        # operator wondering why their key stopped working.
        if (-f '.ocp/id_ed25519') {
            print "  bootstrap-key (.ocp/id_ed25519) — LEGACY:\n";
            print "    - Secure mode no longer uses it: every machine, on every\n";
            print "      provider, is reached with the admin key\n";
            print "    - Kept, not deleted: machines set up earlier still have\n";
            print "      its public half in authorized_keys\n";
            print "    - Migrate by adding the admin key there as well:\n";
            print "      ocp keys show --purpose admin\n";
            print "\n";
        }
        print "  Team sharing: Repo (git) + PIN1 + PIN2 (via 1Password/Signal)\n";
    } elsif (!$self->nopassword) {
        print "🔐 Security Notes:\n";
        print "  Two-tier SSH keys stored in keys.yaml (encrypted)\n";
        print "  Admin key: every machine, every provider (PIN2)\n";
        print "  Robocop key: workers only (automation, no PIN2)\n";
        print "  .ocp/id_ed25519 is a LEGACY bootstrap key — unused in secure\n"
            . "  mode; add the admin key to authorized_keys to migrate\n"
            if -f '.ocp/id_ed25519';
    } else {
        print "⚠️  Dev Mode (--nopassword):\n";
        print "  Single SSH key in .ocp/id_ed25519 (NOT encrypted)\n";
        print "  For development only! Use default mode for production.\n";
    }

    # SSH provider instructions: which public key does a human have to put on
    # the machine? Exactly one, and which one it is follows the mode.
    #
    #   secure  -> the ADMIN key. `ocp apply`, `ocp ssh`, `ocp update`,
    #              `ocp node add` and `ocp destroy` all reach the machine with
    #              it. It is the same key the Hetzner provider uploads through
    #              the API; the only difference here is that a human carries it.
    #   dev     -> the bootstrap key, the only key material a --nopassword
    #              project has.
    #
    # Naming two keys (as this block did while the bootstrap key still existed
    # in secure mode) is how an operator ends up authorising the wrong one.
    # _effective_provider, not _provider: a bare `ocp init` re-run inside an
    # existing ssh project passes no --provider, and that re-run is exactly
    # how an operator asks "what do I have to do now?" during the migration.
    my $init_provider = $self->_effective_provider($has_config);
    if ($init_provider eq 'ssh') {
        my $pubkey_path = path('.ocp/id_ed25519.pub');

        # Print the key itself where we can — it is what gets pasted, and the
        # public half needs no PIN2 (OCP::Keys, ENCRYPTION LAYERS). Falling
        # back to naming `ocp keys show` keeps init from ever failing here.
        my ($pubkey, $label);
        if ($self->nopassword) {
            if (-f $pubkey_path) {
                $pubkey = $pubkey_path->slurp;
                $label  = 'bootstrap';
            }
        }
        else {
            $pubkey = eval {
                my ($admin) = grep { ($_->{purpose} // '') eq 'admin' && !$_->{deprecated} }
                              @{ $keys_mgr->list_keys };
                $admin && $admin->{public};
            };
            $label = 'admin';
        }
        chomp $pubkey if defined $pubkey;

        if (!$self->nopassword || defined $pubkey) {
            print "\n";
            print "!" x 50, "\n";
            print "SSH PROVIDER - Manual Setup Required\n";
            print "!" x 50, "\n\n";

            print "You supplied this key with --ssh-key; skip if it is already\n"
                . "deployed.\n\n" if $self->ssh_key && $self->nopassword;

            print "Add the $label public key to your server:\n\n";
            if (defined $pubkey && length $pubkey) {
                print "  $pubkey\n\n";
            }
            else {
                print "  ocp keys show --purpose admin\n\n";
            }

            print "Commands to run as root on your server";
            print " (${\($self->host)})" if $self->host;
            print ":\n";
            print "  mkdir -p ~/.ssh\n";
            print "  echo '"
                . (defined $pubkey && length $pubkey ? $pubkey : '<the key above>')
                . "' >> ~/.ssh/authorized_keys\n";
            print "  chmod 700 ~/.ssh\n";
            print "  chmod 600 ~/.ssh/authorized_keys\n";

            unless ($self->nopassword) {
                print "\n";
                print "That one key is all of it: 'ocp apply', 'ocp ssh',\n";
                print "'ocp update', 'ocp node add' and 'ocp destroy' all use it.\n";
                print "Print it again any time with:\n";
                print "  ocp keys show --purpose admin\n";
                print "\n";
                print "Nothing checks this in advance. The first command that\n";
                print "opens an SSH connection is what finds out whether the key\n";
                print "arrived.\n";

                # The migration case, stated where the operator is already
                # looking at authorized_keys.
                if (-f $pubkey_path) {
                    print "\n";
                    print "NOTE: .ocp/id_ed25519 exists in this project. If your\n";
                    print "      machines were set up with it, ADD the admin key\n";
                    print "      above — do not replace anything yet. Secure mode\n";
                    print "      does not use the bootstrap key any more.\n";
                }
            }
        }
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

# Which provider this project actually deploys with. Deliberately not the same
# question as _provider, which answers "what should a NEW ocp.yaml say" and
# defaults to hetzner. A bare `ocp init` re-run inside an existing ssh project
# passes no --provider, so _provider would report hetzner and Step 5a would
# skip the bootstrap key — which is exactly the case of someone switching
# ocp.yaml over to provider: ssh and re-running init to pick the key up.
sub _effective_provider {
    my ($self, $has_config) = @_;

    # Step 7 is about to (over)write ocp.yaml, so the flags are the answer.
    return $self->_provider if !$has_config || $self->force;

    # Otherwise the file that will survive this run is the authority.
    my $cps = eval { OCP::Config->new(file => $self->ocp->config)->control_planes };
    return $self->_provider unless $cps && @$cps;
    return $cps->[0]{provider} // 'hetzner';
}

# Step 4, the age key — and the one place in init where asking the wrong
# question destroys the project.
#
# `has_age_key` answers "is there a key on this machine". That is not the
# question here. .ocp/ is gitignored (ADR 0004), while keys.yaml, secrets.yaml
# and age.key.enc are committed on purpose, so the second person to clone the
# repo has all the encrypted material and none of the key. Init used to ask
# has_age_key, hear "no", and generate a fresh keypair over .ocp/age.pub — and
# from that point keys.yaml was bound to a recipient whose private half no
# longer existed anywhere. `ocp init`, the documented first command, was how
# you lost the project (karr #86).
#
# The question is whether this PROJECT already has a key. age.key.enc and the
# plaintext `sops: age: - recipient:` block of the committed files answer it
# without holding any key at all, which is what project_has_age_key reads.
#
# OCP::Cmd::Apply's dev-mode branch runs the same has_age_key check and is
# right to: it states that it deliberately does not touch age.key.enc, so in
# that mode there is no committed key material a fresh key could devalue. This
# is the same reasoning with the answer secure mode needs — the boundary that
# was drawn there and not here.
sub _ensure_age_key {
    my ($self, $secrets) = @_;

    if ($secrets->has_age_key) {
        # Having a key is not the same as having THE key. A clone that ran an
        # older `ocp init` is left holding a minted one, and its only symptom
        # is a SOPS error from wherever the next run reaches first. Say it
        # here, with the way out.
        unless (eval { $secrets->check_local_age_key; 1 }) {
            my $why = $@ || "unknown error\n";
            $why =~ s/ at \S+ line \d+\.?\s*\z//;
            chomp $why;
            die "ERROR: The age key in .ocp/ does not open this project.\n\n"
              . join('', map { "  $_\n" } split /\n/, $why) . "\n"
              . "Nothing committed was changed. Remove .ocp/age.key and\n"
              . ".ocp/age.pub and run 'ocp init' again — it will unlock the\n"
              . "project's own key from age.key.enc with PIN1.\n";
        }

        print "[ok] Age encryption key exists\n";
        # A checkout can hold the private key without the public one; the
        # recipient file is what every encrypt path reads.
        $secrets->restore_age_recipient;
        return;
    }

    unless ($secrets->project_has_age_key) {
        # Genuinely new project: nothing committed, nothing to devalue.
        print "[..] Generating age encryption key\n";
        my $keys = $secrets->generate_age_key;
        print "[ok] Generated age key: $keys->{public_key}\n";
        return;
    }

    # From here on the project has a key and this checkout does not. Generating
    # is off the table; the only question is whether we can unlock it.
    my $bindings = $secrets->age_key_bindings;
    my $bound    = join ', ', map { $_->{file} } @$bindings;

    # No age.key.enc: reaching here at all means a SOPS file named a recipient,
    # so there is always something to name back.
    unless ($secrets->has_age_key_enc) {
        die "ERROR: This project is encrypted, and its age key is not in this\n"
          . "       checkout.\n\n"
          . "  Encrypted here: $bound\n"
          . "  Missing:        .ocp/age.key — and there is no age.key.enc to\n"
          . "                  unlock it with.\n\n"
          . ".ocp/ is gitignored, so a clone never carries the key. Copy\n"
          . ".ocp/age.key from whoever created the project.\n\n"
          . "Not generating a new one: it would replace .ocp/age.pub and leave\n"
          . "$bound unreadable for good.\n";
    }

    if ($self->nopassword) {
        die "ERROR: --nopassword cannot be applied to a project that is already\n"
          . "       set up in secure mode.\n\n"
          . "  Found: age.key.enc" . ($bound ? " (and $bound)" : '') . "\n\n"
          . "Unlocking that key needs PIN1, and --nopassword promises never to\n"
          . "ask for a PIN. Re-run 'ocp init' without --nopassword.\n";
    }

    print "[..] This project already has an age key — unlocking it\n";
    print "     .ocp/ is gitignored, so this checkout has no copy of it.\n";
    print "     Bound to it: $bound\n" if $bound;

    my $pin1 = OCP::Password::prompt_password("Enter PIN1 (cluster access): ");

    unless (eval { $secrets->decrypt_age_key_with_password($pin1); 1 }) {
        my $why = $@ || "unknown error\n";
        $why =~ s/ at \S+ line \d+\.?\s*\z//;
        chomp $why;
        die "ERROR: Could not unlock this project's age key from age.key.enc.\n\n"
          . join('', map { "  $_\n" } split /\n/, $why) . "\n"
          . "Wrong PIN1, or age.key.enc does not belong to this project.\n"
          . "Nothing was written — "
          . ($bound ? "$bound is untouched and still opens for\nwhoever holds the key.\n"
                    : "the project is untouched.\n");
    }

    printf "[ok] Age key unlocked: %s\n", $secrets->age_recipient // '(unknown)';

    return;
}

# The bootstrap key: .ocp/id_ed25519, dev mode's single credential.
#
# It is created under exactly the condition that makes something read it, and
# since the two-tier decision that condition is `--nopassword` and nothing
# else. OCP::ClusterKey reaches for this file in dev mode only; secure mode
# opens every machine on every provider with the admin key from keys.yaml.
#
# Why not for `provider: ssh` in secure mode any more: the difference between
# the ssh provider and Hetzner was never which key the machine trusts, only
# who puts it there — the Hetzner API before the server exists, or a human
# with `ocp keys show --purpose admin`. Keeping a third, PIN-less key alive
# for one provider bought nothing and cost the model its shape. A secure-mode
# ssh project is told to distribute the ADMIN public key instead (see the
# report block in execute).
#
# The idempotency guard below sits in FRONT of this gate and stays there: a
# project that already has a bootstrap key has machines authorised with it,
# and `ocp init` must never be the command that removes it. Migrating is
# adding the admin key to authorized_keys, not deleting anything locally.
#
# It is deliberately NOT behind PIN2: dev mode promises never to prompt.
sub _ensure_bootstrap_key {
    my ($self, $secrets) = @_;

    my $target = '.ocp/id_ed25519';

    # --ssh-key was previously read only on the dev-mode branch, so in secure
    # mode it was accepted and then silently dropped. It is evaluated in both
    # modes now, and wherever it cannot be honoured it says so out loud.
    my $source = $self->ssh_key;
    if (defined $source) {
        $source =~ s/\A~/$ENV{HOME}/;
        undef $source if $source eq $target;
    }

    # Maintaining a key that already exists is provider-agnostic on purpose.
    # A project that has one has it for a reason, whatever its provider says
    # today, and this branch is the whole guard between a key already in
    # service and OCP::Secrets::generate_ssh_key, which unlinks before it
    # generates. Regenerating it would lock the operator out of machines whose
    # authorized_keys already carry its public half.
    if (-f $target) {
        unless ($source && $self->force) {
            print "[ok] SSH bootstrap key exists ($target)\n";
            if ($source) {
                print "     Keeping it — --ssh-key $source was NOT used.\n";
                print "     Your machines already trust the existing key;\n";
                print "     replacing it would lock you out. Use --force to\n";
                print "     replace it anyway.\n";
            }
            return;
        }
        # --force with an explicit --ssh-key: an operator asking for the
        # replacement by name. Fall through to the copy below.
    }
    elsif (!$self->nopassword) {
        # Nothing reads a bootstrap key in secure mode, on any provider.
        if (defined $self->ssh_key) {
            print "[!!] --ssh-key is not used in secure mode.\n";
            print "     Only a --nopassword project authenticates with the\n";
            print "     bootstrap key .ocp/id_ed25519. Here every machine is\n";
            print "     reached with the admin key from keys.yaml, whatever the\n";
            print "     provider. No key was created from --ssh-key.\n";
            print "     Distribute this instead: ocp keys show --purpose admin\n";
        }
        return;
    }

    if ($source) {
        die "SSH key not found: $source\n" unless -f $source;
        copy($source, $target) or die "Failed to copy private key: $!\n";
        copy("$source.pub", "$target.pub") if -f "$source.pub";
        chmod 0600, $target;
        print "[ok] Copied SSH bootstrap key from $source\n";
        return;
    }

    # --ssh-key pointed at $target itself and $target does not exist: that is
    # a typo worth reporting, not a reason to generate something else.
    die "SSH key not found: " . $self->ssh_key . "\n" if defined $self->ssh_key;

    print "[..] Generating SSH bootstrap key ($target)\n";
    my $ssh_keys = $secrets->generate_ssh_key;
    print "[ok] Generated SSH bootstrap key: $ssh_keys->{public_key}\n";

    return;
}

# Ask which location and which server type the control plane should use.
# Every exit before the prompts leaves _location/_server_type undef, which is
# how "keep the defaults" is expressed — this must never be the step that
# makes `ocp init` hang or fail.
sub _prompt_hetzner_control_plane {
    my ($self, $secrets) = @_;

    return unless $self->_interactive;

    my $picker = $self->_picker;
    unless ($picker) {
        my $token = $secrets && $secrets->hetzner_token
            or return;
        $picker = OCP::Hetzner::Picker->new(token => $token);
    }

    my $locations = eval { $picker->location_options };
    my $types     = eval { $picker->server_type_options };

    unless (($locations && @$locations) && ($types && @$types)) {
        print "[!!] Could not read the Hetzner catalogue — keeping the defaults\n";
        return;
    }

    print "\n";
    print "Control plane placement (Enter keeps the default)\n";

    $self->_location(
        _pick('Location:', $locations, $OCP::Config::HETZNER_DEFAULTS{location}));
    $self->_server_type(
        _pick('Server type:', $types, $OCP::Config::HETZNER_DEFAULTS{server_type}));

    printf "[ok] Control plane: %s in %s\n",
        $self->_server_type, $self->_location;

    return;
}

# Print a { label, value } list and read one choice from STDIN. Accepts the
# number from the list or the value itself; anything else, including a bare
# Enter or a closed STDIN, keeps $default.
sub _pick {
    my ($prompt, $options, $default) = @_;

    print "\n$prompt\n";
    my $n = 0;
    for my $opt (@$options) {
        $n++;
        printf "  %2d) %s%s\n", $n, $opt->{label},
            ($opt->{value} eq $default ? '  [default]' : '');
    }
    print "Choice [$default]: ";

    my $input = <STDIN>;
    return $default unless defined $input;
    chomp $input;
    $input =~ s/\A\s+//;
    $input =~ s/\s+\z//;
    return $default unless length $input;

    return $options->[$input - 1]{value}
        if $input =~ /\A[0-9]+\z/ && $input >= 1 && $input <= @$options;

    for my $opt (@$options) {
        return $opt->{value} if $opt->{value} eq $input;
    }

    print "  '$input' is not on the list — keeping $default\n";
    return $default;
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

Once the token is stored, C<--hetzner> also offers the live Hetzner
catalogue (L<OCP::Hetzner::Picker>) as a numbered list and asks where the
control plane should run and on which server type. Both lists preselect the
values C<OCP::Config> would have written anyway, so pressing Enter twice
produces the same F<ocp.yaml> as a non-interactive run. The step is skipped
altogether when STDIN is not a terminal, when no token is available, or when
the catalogue cannot be read — it never blocks a batch run and never fails
an init.

=head2 The project age key

F<.ocp/> is gitignored; F<keys.yaml>, F<secrets.yaml> and F<age.key.enc> are
committed. A clone therefore has everything the project encrypted and none of
the key, and C<ocp init> is the command that clone is documented to run.

So init does not ask whether there is an age key on this machine — it asks
whether this B<project> has one, which F<age.key.enc> and the plaintext
C<recipient> of the committed SOPS files answer without holding any key.

=over 4

=item * Nothing committed: a keypair is generated, as before.

=item * F<age.key.enc> present: it is unlocked with PIN1, and F<.ocp/age.pub>
is rebuilt from the private half so the checkout can encrypt again.

=item * Encrypted material but no F<age.key.enc>, a wrong PIN1, or
C<--nopassword> against a project already in secure mode: init aborts, names
what is missing and where it comes from, and writes nothing.

=back

A new key is never generated over an existing recipient. The refusal lives in
L<OCP::Secrets/generate_age_key> rather than here, so it covers any other
route to generation too.

=head2 SSH keys

Secure mode — the default — writes B<two> keys into F<keys.yaml> and no
others: a robo key (C<purpose: automation>, age-encrypted, for robocop's
unattended work) and an admin key (C<purpose: admin>, age + PIN2, for
everything a human triggers: C<ocp apply>, C<ocp update>, C<ocp node add>,
C<ocp destroy>, C<ocp ssh>). Print the admin public key with C<ocp keys show
--purpose admin>.

The admin key is what every machine of the cluster trusts, on every provider.
On Hetzner OCP uploads it through the API before the server exists; with
C<provider: ssh> the operator pastes it into F<authorized_keys>, and the
report at the end of C<ocp init> prints it for exactly that. The provider
decides who distributes the key, not which key gets distributed.

The B<bootstrap key> F<.ocp/id_ed25519> therefore exists only under
C<--nopassword>, where there is no F<keys.yaml> and it is the single piece of
key material the project has. It carries no PIN, because dev mode promises
never to prompt. C<--ssh-key> supplies it instead of generating it; in secure
mode the flag is reported as not applicable rather than silently dropped.

An existing F<.ocp/id_ed25519> is never regenerated, never silently replaced,
and never deleted — its public half may still be in F<authorized_keys> on a
running cluster's machines. That guard runs before the mode is even
consulted. C<--ssh-key> against an existing key is reported and ignored
unless C<--force> is given.

B<Migrating an ssh-provider cluster built before this:> its machines carry
the bootstrap public key and have never seen the admin one. Add the admin key
to F</root/.ssh/authorized_keys> on every machine (C<ocp keys show --purpose
admin>) B<before> running any other C<ocp> command against it. Init says so
when it finds a bootstrap key in a secure-mode project.

With --nogit, skips git repository initialization and .gitignore creation.
The generated F<.gitignore> ignores F<.ocp/> only: the encrypted files
(F<keys.yaml>, F<secrets.yaml>, F<age.key.enc>, F<kubeconfig.yaml>) are
meant to be committed.

=cut
