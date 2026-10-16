package OCP::Cmd::Keys::Secure;
# ABSTRACT: Move a dev-mode project into secure mode without locking its machines out

use Moo;
use MooX::Cmd;
use MooX::Options;

use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use Path::Tiny qw( path );

use OCP::ClusterKey;
use OCP::Cmd::Apply::Bootstrap ();
use OCP::Cmd::Apply::CR ();
use OCP::Cmd::Apply::Deploy ();
use OCP::Config;
use OCP::K8s;
use OCP::Keys;
use OCP::Password;
use OCP::Provider;
use OCP::Secrets;
use OCP::Share;
use OCP::SSH;
use OCP::TempKeyPair;

with 'OCP::Role::Cmd';
# robocop's credentials Secret, rewritten with the robo key this command
# creates -- the same code `ocp apply` and `ocp deploy-robocop` write it with.
with 'OCP::Role::Cmd::RobocopCredentials';

option drop_bootstrap => (
    is  => 'ro',
    doc => 'Also remove the bootstrap key .ocp/id_ed25519 from every machine',
);

# The cluster API. Injectable for tests, the way OCP::Cmd::Destroy has it;
# otherwise built from kubeconfig.yaml on first use.
has k8s => (is => 'rw');

#
# k96: `ocp init --nopassword` used to be a one-way door. A dev-mode project's
# machines trust .ocp/id_ed25519 and nothing else, and secure mode never
# offers that key (ADR 0027 forbids the fallback), so writing keys.yaml was
# how you locked yourself out of your own cluster.
#
# The way across is the order: add the new access while the old one still
# works, prove the new one, THEN switch.
#
#   1. new keys go into a staging file, .ocp/keys.yaml.pending -- keys.yaml is
#      what makes a project secure everywhere in OCP (OCP::ClusterKey, apply,
#      ssh), so it may only appear once the machines are ready for it
#   2. both public halves are appended to every machine's authorized_keys,
#      over the bootstrap key
#   3. the admin key is tried on every machine, alone -- no fallback, the very
#      rule secure mode lives by
#   4. only if every machine passed: PIN1 lands in age.key.enc, the staging
#      file becomes keys.yaml
#
# A host that fails stops nothing but the switch: the others keep the keys
# they got, the staging file stays, and running the command again picks up the
# same keys (an authorized_keys entry that is already there is not added
# twice). Removing the bootstrap key from the machines is a separate,
# explicit step (--drop-bootstrap), because it is the one step that cannot be
# taken back from here.
#
# The staging file lives under .ocp/ on purpose: gitignored, so a half-done
# migration never reaches the repository as a second keys.yaml.

my $STAGING = 'keys.yaml.pending';

sub execute {
    my ( $self, $args, $chain ) = @_;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config  = OCP::Config->new(file => $file);
    my $dir     = $config->project_dir;
    my $secrets = OCP::Secrets->new(project_dir => $dir);

    if (-f $dir->child('keys.yaml')) {
        return $self->_drop_in_secure_mode($config, $secrets) if $self->drop_bootstrap;
        print "[ok] already in secure mode (keys.yaml exists)\n";
        return 0;
    }

    return $self->_migrate($config, $secrets);
}

#
# The migration
#

sub _migrate {
    my ( $self, $config, $secrets ) = @_;

    my $dir     = $config->project_dir;
    my $staging = $dir->child('.ocp', $STAGING);

    # Every path below prompts -- PIN2 always, PIN1 unless age.key.enc exists.
    # Without anybody to answer, say so before anything happens, the way
    # OCP::ClusterKey refuses instead of blocking on an invisible prompt.
    die "ERROR: Moving to secure mode sets and asks for PINs, and there is no\n"
      . "       terminal to ask on. Run 'ocp keys secure' from an interactive\n"
      . "       shell, or feed the PINs with --pins-stdin.\n"
        unless $self->_can_prompt;

    print "Moving this project from dev mode to secure mode\n\n";

    # Dev mode keeps a plain age.key; nothing to unlock. Needed for the
    # kubeconfig below and for every key this run encrypts.
    $secrets->ensure_age_key;

    # Which machines exist, before a single PIN is typed: a cluster that
    # cannot be asked must not cost the operator two PINs to find out.
    my $api = $self->_cluster_api($config, $secrets);
    my ($machines, $pending) = $self->_machines($config, $api);

    # The key that still opens them -- dies naming .ocp/id_ed25519 when it is
    # gone, which with machines to reach is the end of the road anyway.
    my $bootstrap = @$machines ? OCP::ClusterKey->for_config($config) : undef;

    # PIN1: secure mode means age.key.enc too. Set now, written only at the
    # switch, so a run that stops halfway leaves a project that is dev mode in
    # every file.
    my $pin1;
    if ($secrets->has_age_key_enc) {
        print "[ok] age.key.enc exists (PIN1 already set)\n";
    } else {
        print "PIN1 encrypts age.key (cluster access), PIN2 the admin SSH key.\n";
        $pin1 = OCP::Password::prompt_new_pin('PIN1', 'cluster access');
    }

    my ($admin, $robo) = $self->_staged_keys($config, $staging);

    my $failed = [];
    if (@$machines) {
        $failed = $self->_distribute_and_test($machines, $bootstrap, $admin, $robo);
    } else {
        print "[ok] No machine has been deployed yet: the switch is local\n";
    }

    if (@$failed) {
        print STDERR "[!!] $_->{label}: $_->{why}\n" for @$failed;
        print STDERR "\n"
          . "Not switched: this project is still in dev mode, and every machine\n"
          . "still accepts the bootstrap key. The new keys stay staged in\n"
          . ".ocp/$STAGING; the machines that passed keep them.\n"
          . "Fix the machines above and run 'ocp keys secure' again: it continues\n"
          . "with the same keys and adds nothing twice.\n";
        return 1;
    }

    # The switch itself. age.key.enc first: if the keys.yaml write failed
    # after it, a re-run finds PIN1 set and the staging file still there.
    if (defined $pin1) {
        $secrets->encrypt_age_key_with_password($pin1);
        print "[ok] age.key.enc written (PIN1)\n";
    }
    OCP::Keys->new(project_dir => $dir, keys_file => $staging)
        ->promote_to($dir->child('keys.yaml'));
    print "[ok] secure mode: keys.yaml written\n";
    print "     Commit keys.yaml" . (defined $pin1 ? ' and age.key.enc' : '') . ".\n";

    $self->_print_pending_hosts($pending);

    my $rc = 0;
    $rc = 1 unless $self->_upload_to_hetzner($config, $secrets, $api, $admin, $robo);
    $rc = 1 unless $self->_reroll_robocop($config, $secrets, $api, $admin);

    if ($self->drop_bootstrap) {
        $rc = 1 unless $self->_drop_bootstrap($config, $machines, $self->_admin_pair($admin));
    } elsif (@$machines) {
        print "\n";
        print "The bootstrap key .ocp/id_ed25519 is still in authorized_keys on these\n";
        print "machines, and still opens them. Remove it there with:\n";
        print "  ocp keys secure --drop-bootstrap\n";
    }

    return $rc;
}

# The admin and robo key this run moves to: the staged ones from an earlier,
# unfinished run, or a new pair. Returned as hashes with name, public and --
# for the admin key -- private.
sub _staged_keys {
    my ( $self, $config, $staging ) = @_;

    my $keys = OCP::Keys->new(project_dir => $config->project_dir, keys_file => $staging);

    unless (-f $staging) {
        my $pin2 = OCP::Password::prompt_new_pin('PIN2', 'admin SSH access');
        print "[..] Generating the admin and robo SSH keys\n";
        my $made = $keys->add_cluster_keys(pin2 => $pin2);
        print "[ok] Staged in .ocp/$STAGING: $made->{admin}{name} (admin, PIN2),"
            . " $made->{automation}{name} (robo)\n";
        return ($made->{admin}, $made->{automation});
    }

    # A run that stopped before the switch. Same keys again: the machines
    # that already took them must not need a second set.
    print "[..] Continuing with the keys staged in .ocp/$STAGING by an earlier run\n";

    my @all = @{ $keys->list_keys };
    my ($robo)  = grep { ($_->{purpose} // '') eq 'automation' } @all;
    my ($entry) = grep { ($_->{purpose} // '') eq 'admin' } @all;
    die "ERROR: .ocp/$STAGING does not hold an admin and a robo key.\n"
      . "       Remove it and run 'ocp keys secure' again for a new pair.\n"
        unless $robo && $entry;

    my $pin2 = OCP::Password::prompt_password("Enter PIN2 (admin SSH access): ");
    my $admin = eval { $keys->decrypt_key($entry->{name}, $pin2) };
    die "ERROR: Wrong PIN2 for the staged admin key $entry->{name}.\n"
      . "       It is the PIN2 you set in the earlier run. Lost it? Remove\n"
      . "       .ocp/$STAGING and run 'ocp keys secure' again for a new pair.\n"
        unless $admin && defined $admin->{private};

    print "[ok] $admin->{name} (admin) and $robo->{name} (robo)\n";
    return ($admin, $robo);
}

# Steps 2 and 3 for every machine. Returns the machines that did not make it,
# each with a reason; never dies on one host.
sub _distribute_and_test {
    my ( $self, $machines, $bootstrap, $admin, $robo ) = @_;

    my $pair = $self->_admin_pair($admin);
    my @failed;

    print "\n";
    for my $m (@$machines) {
        my $label = _label($m);

        print "[..] $label: adding the admin and robo keys (over the bootstrap key)\n";
        my $added = eval {
            $self->_append_keys($m, [ $bootstrap->path, $bootstrap->label ],
                $admin->{public}, $robo->{public});
        };
        unless ($added) {
            push @failed, { %$m, label => $label, why => 'could not add the keys: '._oneline($@) };
            next;
        }
        print "     $added\n";

        # The admin key alone. OCP::SSH offers exactly the one key file it is
        # given (-F /dev/null, IdentitiesOnly: no ~/.ssh keys, none of an
        # agent's): a pass here is the admin key's, not the bootstrap key's.
        my $why = $self->_admin_refused($m, $pair);
        if (defined $why) {
            push @failed, { %$m, label => $label, why => 'the admin key is refused: '.$why };
            next;
        }
        print "[ok] $label: the admin key opens it\n";
    }

    return \@failed;
}

#
# --drop-bootstrap
#

# Already secure: only the last step, typically after a run without the flag.
sub _drop_in_secure_mode {
    my ( $self, $config, $secrets ) = @_;

    $secrets->ensure_age_key;
    my $api = $self->_cluster_api($config, $secrets);
    my ($machines) = $self->_machines($config, $api);

    unless (@$machines) {
        print "[ok] No machine has been deployed: there is no bootstrap key to remove\n";
        return 0;
    }

    my $key = $self->cluster_ssh_key($config, reason => 'ocp keys secure --drop-bootstrap');
    return $self->_drop_bootstrap($config, $machines, [ $key->path, $key->label ]) ? 0 : 1;
}

# Removes every authorized_keys line carrying the bootstrap key's blob, on
# every machine, logged in with the admin key -- and only on a machine where
# that login has just worked, so this can never be the step that leaves a
# machine with no key OCP holds. True when every machine is done.
#
# The local .ocp/id_ed25519 is left alone: deleting it is irreversible, and a
# machine this run could not reach still trusts it.
sub _drop_bootstrap {
    my ( $self, $config, $machines, $admin_key ) = @_;

    my $blob = $self->_bootstrap_blob($config);
    unless (defined $blob) {
        print "[ok] This project has no bootstrap key (.ocp/id_ed25519): nothing to remove\n";
        return 1;
    }

    print "\n";
    my @failed;
    for my $m (@$machines) {
        my $label = _label($m);

        if (defined(my $why = $self->_admin_refused($m, $admin_key))) {
            push @failed, $label;
            print STDERR "[!!] $label: the admin key is refused ($why); "
                . "the bootstrap key stays there\n";
            next;
        }

        my $removed = eval { $self->_remove_blob($m, $admin_key, $blob) };
        unless (defined $removed) {
            push @failed, $label;
            print STDERR "[!!] $label: could not remove the bootstrap key: "._oneline($@)."\n";
            next;
        }
        print $removed
            ? "[ok] $label: bootstrap key removed ($removed line"
              . ($removed == 1 ? '' : 's') . ")\n"
            : "[ok] $label: the bootstrap key was not there\n";
    }

    my $path = $config->ssh_private_key_path;
    if (@failed) {
        print STDERR "\n"
          . "$path still opens " . join(', ', @failed) . ".\n"
          . "Keep it until those are fixed; 'ocp keys secure --drop-bootstrap' again\n"
          . "finishes the job.\n";
        return 0;
    }

    print "\n";
    print "$path no longer opens any machine of this cluster.\n";
    print "OCP does not delete it; remove it and its .pub when you are ready.\n";
    return 1;
}

#
# After the switch
#

# Hetzner keeps public keys in the project, by name; servers created later get
# the ones their creator names. In dev mode admin_ssh_key_name carried the
# bootstrap key (OCP::Cmd::Apply::Bootstrap uploads "the admin key" of the
# mode). OCP::Provider::Hetzner::upload_ssh_key is WWW::Hetzner's ensure,
# which deletes and recreates a key whose content differs -- so the name now
# points at the admin key, and so does every server created later through an
# OCPNodeProvider (spec.hetzner.sshKeyName names it). Servers that exist
# already are not touched by any of this: their authorized_keys were handled
# above.
#
# True unless an upload failed.
sub _upload_to_hetzner {
    my ( $self, $config, $secrets, $api, $admin, $robo ) = @_;

    return 1 unless $self->_uses_hetzner($config, $api);

    my $token = $secrets->hetzner_token;

    # Nothing deployed: the first `ocp apply` uploads both keys under these
    # names before it creates a server (OCP::Cmd::Apply::Bootstrap).
    if (!$token && !$api) {
        print "[--] Hetzner: no token yet; the first 'ocp apply' stores the keys there\n";
        return 1;
    }

    unless ($token) {
        print STDERR "[!!] Hetzner is in use, but secrets.yaml holds no Hetzner token:\n"
          . "     the keys could not be stored in the Hetzner project. Store a token\n"
          . "     ('ocp init --hetzner'), then add them there under these names:\n"
          . "       " . $config->admin_ssh_key_name . "  (ocp keys authorized-keys --purpose admin)\n"
          . "       " . $config->robo_ssh_key_name  . "  (ocp keys authorized-keys --purpose automation)\n";
        return 0;
    }

    my $ok = eval {
        my $prov = $self->_hetzner_provider($config, $token);
        $prov->upload_ssh_key($config->admin_ssh_key_name, $admin->{public});
        $prov->upload_ssh_key($config->robo_ssh_key_name, $robo->{public});
        1;
    };
    unless ($ok) {
        print STDERR "[!!] Could not store the keys in the Hetzner project: "._oneline($@)."\n"
          . "     Servers created from now on would get the old key. Add them in the\n"
          . "     Hetzner console under " . $config->admin_ssh_key_name . " and "
          . $config->robo_ssh_key_name . ".\n";
        return 0;
    }

    print "[ok] Hetzner: " . $config->admin_ssh_key_name . " is the admin key now, "
        . $config->robo_ssh_key_name . " the robo key\n";
    return 1;
}

# robocop reads its credentials from a Secret, as environment variables: in
# dev mode there was no robo key to put in it. Written now the way `ocp apply`
# writes it (OCP::Cmd::Apply::Deploy::robocop_step), with the admin key this
# run already unlocked for the token read -- seeded into cluster_ssh_key, so
# no second PIN2. A Deployment that was running restarts so its pod reads the
# new Secret.
#
# The switch has happened by now and is not undone by anything here. True
# unless robocop should run and could not be rolled out.
sub _reroll_robocop {
    my ( $self, $config, $secrets, $api, $admin ) = @_;

    unless ($config->robocop_enabled) {
        print "[--] robocop is not enabled in ocp.yaml: no credentials to roll out\n";
        return 1;
    }
    unless ($api) {
        print "[--] No cluster to reach (no kubeconfig.yaml): robocop gets its\n"
            . "     credentials with the first 'ocp apply'\n";
        return 1;
    }

    # keys.yaml exists now, so this is the admin key -- and the one in hand.
    $self->cluster_ssh_key($config, admin_key => $admin);

    my $had = eval { $api->get('Deployment', 'robocop', namespace => 'ocp-system') } ? 1 : 0;

    print "\n";
    my $step = OCP::Cmd::Apply::Deploy::robocop_step($self, $api, $config, {
        secrets => $secrets,
    });

    if ($step->{state} eq 'failed') {
        print STDERR "[!!] The switch to secure mode stands; only robocop is behind.\n"
          . "     Roll it out with 'ocp deploy-robocop' (or 'ocp apply').\n";
        return 0;
    }

    if ($had && $step->{changed}) {
        my $ok = eval { $self->_restart_robocop($api); 1 };
        unless ($ok) {
            print STDERR "[!!] robocop could not be restarted: "._oneline($@)."\n"
              . "     Its pod still runs with the old credentials. Delete it\n"
              . "     (label app=robocop in ocp-system) or run 'ocp deploy-robocop'.\n";
            return 0;
        }
        print "  [ok] robocop restarted to read the new credentials\n";
        print "  [..] security_level inject: run 'ocp inject-key' once the new pod runs\n"
            if $config->robocop_security_level eq 'inject';
    }

    return 1;
}

# The Deployment's pods are deleted; the ReplicaSet starts a new one, which
# reads the Secret afresh. The pod template stays as `ocp apply` writes it, so
# the next apply does not see a change and roll it once more.
sub _restart_robocop {
    my ( $self, $api ) = @_;

    my $list = $api->list('Pod', namespace => 'ocp-system', labelSelector => 'app=robocop');
    for my $pod (@{ $list->items // [] }) {
        my $h = ref $pod eq 'HASH' ? $pod : $api->k8s->object_to_struct($pod);
        $api->delete('Pod', name => $h->{metadata}{name}, namespace => 'ocp-system');
    }
    return;
}

#
# Machines
#

# Every machine of this cluster that exists, as { name, address, role }: the
# OCPNodes when the cluster can be asked (every role -- status.publicIP, else
# spec.host, the address OCP installed them over), the control planes of
# ocp.yaml with a known address, the recorded one. The OCPNodes go first, so
# their addresses win.
#
# One machine shows up under several sources, and not always under the same
# address: an ssh control plane is a hostname in ocp.yaml and may be an IP in
# its OCPNode. So, as in OCP::Cmd::Destroy, a name (its first label) or an
# address already seen is the same machine.
#
# Second return: ocp.yaml pool hosts with no OCPNode. Not machines yet --
# nothing has joined them -- but they will need both keys when they do.
sub _machines {
    my ( $self, $config, $api ) = @_;

    my ( @machines, %seen );
    my $add = sub {
        my ( $name, $address, $role ) = @_;
        return unless defined $address && length $address && $address ne '-';
        my @ids = ( 'addr:'.lc $address );
        push @ids, 'name:'.lc( (split /\./, $name, 2)[0] ) if defined $name && length $name;
        # A second source for a known machine still teaches its other ids.
        my $known = grep { $seen{$_} } @ids;
        $seen{$_} = 1 for @ids;
        return if $known;
        push @machines, { name => $name // $address, address => $address, role => $role };
    };

    my @nodes = $api ? $self->_ocpnodes($api) : ();
    $add->($_->{metadata}{name}, $_->{status}{publicIP} || $_->{spec}{host},
           $_->{spec}{role} // 'worker') for @nodes;

    my $hetzner = 0;
    for my $cp (@{ $config->control_planes }) {
        my $provider = $cp->{provider} // 'hetzner';
        my $name = $cp->{name}
            // ( $provider eq 'ssh' && $cp->{host}
                 ? (OCP::Cmd::Apply::Bootstrap::host_name_parts($cp->{host}))[0]
                 : $provider eq 'hetzner' ? 'police'.++$hetzner : undef );
        $add->($name, $cp->{host} // $cp->{public_ip}, 'control-plane');
    }
    for my $node (grep { ($_->{role} // 'control-plane') !~ /worker/ } @{ $config->nodes_status }) {
        $add->($node->{name}, $node->{public_ip}, 'control-plane');
    }
    # Its name is made up ("cp-1") when nothing recorded one: the address alone.
    my $status = $config->cluster_status;
    $add->(undef, $status->{public_ip} // $status->{host}, 'control-plane');

    my %named = map { $_->{metadata}{name} => 1 } @nodes;
    my @pending =
        grep { !$named{ $_->{name} } && !$seen{ 'addr:'.lc $_->{host} } }
        map  { { name => $_->{metadata}{name}, host => $_->{spec}{host} } }
        grep { defined $_->{spec}{host} && length $_->{spec}{host} }
        OCP::Cmd::Apply::CR::worker_ocpnodes($config);

    return ( \@machines, \@pending );
}

# Every OCPNode, as plain hashes. A cluster that has a kubeconfig but does not
# answer is not "no workers": the switch would leave every worker trusting the
# bootstrap key alone, which robocop does not hold. So it stops here, before
# anything was asked or changed.
sub _ocpnodes {
    my ( $self, $api ) = @_;

    my $list = eval { $api->list('OCPNode', namespace => 'ocp-system') };
    unless ($list) {
        my $why = _oneline($@ || 'no answer');
        die "ERROR: Could not read the OCPNodes from the cluster API: $why\n"
          . "       Without them the workers are unknown, and a switch now would\n"
          . "       leave them trusting the bootstrap key alone. Nothing was changed;\n"
          . "       run 'ocp keys secure' again once the cluster answers.\n";
    }

    return map { ref $_ eq 'HASH' ? $_ : $api->k8s->object_to_struct($_) }
           @{ $list->items // [] };
}

sub _print_pending_hosts {
    my ( $self, $pending ) = @_;
    return unless @$pending;

    print "\n";
    print "In ocp.yaml, not joined yet (no OCPNode): "
        . join(', ', map { "$_->{name} ($_->{host})" } @$pending) . "\n";
    print "They need both keys before they join:\n";
    print "  ocp keys authorized-keys | ssh root\@HOST 'cat >> ~/.ssh/authorized_keys'\n";
    return;
}

# The cluster API, or undef when the project has no kubeconfig.yaml (never
# deployed, or deployed and destroyed).
sub _cluster_api {
    my ( $self, $config, $secrets ) = @_;

    return $self->k8s if $self->k8s;
    return undef unless $secrets->has_kubeconfig;

    my $kc = $secrets->read_kubeconfig
        or die "ERROR: kubeconfig.yaml exists but could not be decrypted.\n";

    my $fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print {$fh} $kc;
    close $fh;
    # Anchored on the instance: File::Temp unlinks it on destruction.
    $self->{_kc_temp} = $fh;

    my $api = Kubernetes::REST::Kubeconfig->new(kubeconfig_path => $fh->filename)->api;
    OCP::K8s->register($api);
    return $self->k8s($api);
}

# Hetzner is in this project when a control plane, a worker pool or an
# OCPNodeProvider says so.
sub _uses_hetzner {
    my ( $self, $config, $api ) = @_;

    return 1 if grep { ($_->{provider} // 'hetzner') eq 'hetzner' } @{ $config->control_planes };
    return 1 if grep { ($_->{provider} // '') eq 'hetzner' } @{ $config->workers };
    return 0 unless $api;
    return 1 if grep { ($_->{spec}{type} // '') eq 'hetzner' } $self->provider_crs($api);
    return 0;
}

sub _hetzner_provider {
    my ( $self, $config, $token ) = @_;
    return OCP::Provider->for_spec({ provider => 'hetzner' },
        token        => $token,
        cluster_name => $config->name,
    );
}

#
# One machine
#

# Appends the two public keys to root's authorized_keys unless a line already
# carries the key's blob -- the blob, not the line: the same key under another
# comment or behind options is the same key. Returns what it did, in words.
sub _append_keys {
    my ( $self, $m, $key, @public ) = @_;

    my @adds;
    for my $i (0 .. $#public) {
        my $line = $public[$i];
        chomp $line;
        my $blob = _blob($line);
        push @adds, 'add '._sq($line).' '._sq($blob).' '.($i ? 'robo' : 'admin');
    }

    my $script = join "\n",
        'set -e',
        'umask 077',
        'd=/root/.ssh',
        'f=$d/authorized_keys',
        'mkdir -p "$d"',
        'chmod 700 "$d"',
        'touch "$f"',
        'chmod 600 "$f"',
        # A last line without its newline would swallow the first key added.
        'if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then echo >> "$f"; fi',
        'has() { awk -v b="$1" \'{ for (i = 1; i <= NF; i++) if ($i == b) { f = 1; exit } } END { exit !f }\' "$f"; }',
        'add() { if has "$2"; then echo "$3 key already there"; else printf \'%s\n\' "$1" >> "$f"; echo "$3 key added"; fi; }',
        @adds,
        '';

    my $res = $self->_ssh($m, $key)->run_script($script);
    die _ssh_failure($res) if $res->{exit};

    my @did = grep { /\S/ } split /\n/, ($res->{stdout} // '');
    return @did ? join(', ', @did) : 'keys in place';
}

# Removes every authorized_keys line carrying $blob. Returns how many.
sub _remove_blob {
    my ( $self, $m, $key, $blob ) = @_;

    my $script = join "\n",
        'set -e',
        'umask 077',
        'f=/root/.ssh/authorized_keys',
        'if [ ! -f "$f" ]; then echo 0; exit 0; fi',
        't="$f.ocp-secure"',
        ': > "$t"',
        'n=$(awk -v b='._sq($blob).' -v out="$t" \'{ m = 0; for (i = 1; i <= NF; i++) if ($i == b) m = 1 } m { c++; next } { print > out } END { print c + 0 }\' "$f")',
        # cat into the file rather than mv over it: owner, mode and any
        # SELinux label stay the ones it had.
        'cat "$t" > "$f"',
        'rm -f "$t"',
        'echo "$n"',
        '';

    my $res = $self->_ssh($m, $key, 'admin')->run_script($script);
    die _ssh_failure($res) if $res->{exit};

    my ($n) = ($res->{stdout} // '') =~ /(\d+)\s*\z/;
    die "unexpected answer: "._oneline($res->{stdout} // '')."\n" unless defined $n;
    return $n;
}

# Undef when the admin key opens $m, the reason otherwise.
sub _admin_refused {
    my ( $self, $m, $key ) = @_;

    my $res = eval { $self->_ssh($m, $key, 'admin')->run('true') };
    return _oneline($@) unless $res;
    return undef unless $res->{exit};
    return _ssh_failure($res);
}

# $key is [ path, label ]; $purpose names the admin key to OCP::SSH, so a
# refusal says which key is missing (k209). The bootstrap key has none.
sub _ssh {
    my ( $self, $m, $key, $purpose ) = @_;
    my ( $path, $label ) = @$key;
    return OCP::SSH->new(
        host      => $m->{address},
        user      => 'root',
        key_file  => $path,
        key_label => $label,
        ($purpose ? (key_purpose => $purpose) : ()),
    );
}

# The staged admin key as a file pair for OCP::SSH: [ path, label ]. The
# OCP::TempKeyPair is kept on the instance, so its files live as long as the
# command and go with it.
sub _admin_pair {
    my ( $self, $admin ) = @_;

    $self->{_admin_pair} //= OCP::TempKeyPair->for_private_key($admin->{private},
        public => $admin->{public});
    return [ $self->{_admin_pair}->path, "the admin key '$admin->{name}'" ];
}

# The bootstrap public key's blob, from its .pub, else from the private key
# itself; undef when the project has neither.
sub _bootstrap_blob {
    my ( $self, $config ) = @_;

    my $pub = $config->ssh_public_key_path;
    my $line = -f $pub ? path($pub)->slurp : undef;
    unless (defined $line && $line =~ /\S/) {
        my $priv = $config->ssh_private_key_path;
        $line = -f $priv ? OCP::TempKeyPair::public_from_private(path($priv)->slurp) : undef;
    }
    return undef unless defined $line && $line =~ /\S/;
    return _blob($line);
}

sub _can_prompt {
    my ($self) = @_;
    return $OCP::ClusterKey::INTERACTIVE if defined $OCP::ClusterKey::INTERACTIVE;
    return $OCP::Password::PINS_STDIN || -t STDIN;
}

sub _find_share_dir { OCP::Share->dir }

# What OCP::Cmd::Apply::Deploy::robocop_step calls on its first argument.
sub _ensure_robocop {
    my ( $self, $api, $config ) = @_;
    return OCP::Cmd::Apply::CR::ensure_robocop($self, $api, $config);
}

sub _wait_robocop_ready {
    my ( $self, $api, $timeout ) = @_;
    return OCP::Cmd::Apply::CR::wait_robocop_ready($self, $api, $timeout);
}

#
# Helpers
#

sub _label {
    my ($m) = @_;
    return $m->{name} eq $m->{address} ? $m->{name} : $m->{name}.' ('.$m->{address}.')';
}

# The base64 body of an authorized_keys line: what identifies the key, with
# the type in front and the comment after it left out.
sub _blob {
    my ($line) = @_;
    my ($blob) = $line =~ m{\A\s*\S+\s+([A-Za-z0-9+/]+=*)(?:\s|\z)};
    die "Not an SSH public key: "._oneline($line)."\n" unless defined $blob;
    return $blob;
}

sub _sq {
    my ($s) = @_;
    $s =~ s/'/'\\''/g;
    return "'".$s."'";
}

sub _ssh_failure {
    my ($res) = @_;
    my $why = $res->{stderr} // '';
    $why = $res->{stdout} // '' unless $why =~ /\S/;
    $why = 'ssh exited with '.($res->{exit} // '?') unless $why =~ /\S/;
    return _oneline($why);
}

sub _oneline {
    my ($s) = @_;
    $s = '' unless defined $s;
    $s =~ s/ at \S+ line \d+\.?\s*\z//;
    $s =~ s/\s+/ /g;
    $s =~ s/\A\s+|\s+\z//g;
    return $s;
}

1;

__END__

=head1 NAME

OCP::Cmd::Keys::Secure - Move a dev-mode project into secure mode without locking its machines out

=head1 SYNOPSIS

    ocp keys secure                     # switch; the bootstrap key stays on the machines
    ocp keys secure --drop-bootstrap    # switch, then remove it there
    ocp keys secure --drop-bootstrap    # already secure: remove it now
    ocp keys secure --pins-stdin < pins # PIN1, PIN1, PIN2, PIN2

=head1 DESCRIPTION

A project created with C<ocp init --nopassword> has no F<keys.yaml>, and its
machines trust the bootstrap key F<.ocp/id_ed25519> alone. Secure mode never
offers that key (ADR 0027), so creating F<keys.yaml> by hand would lock OCP
out of every machine. This command makes the switch in the order that cannot
do that:

=over 4

=item 1.

PIN1 is set (unless F<age.key.enc> exists already), PIN2 is set, and a robo
key (C<purpose: automation>) and an admin key (C<purpose: admin>, PIN2) are
generated into F<.ocp/keys.yaml.pending> -- not F<keys.yaml>, which is what
makes a project secure for every other command.

=item 2.

Every machine of the cluster gets both public keys appended to
F</root/.ssh/authorized_keys>, over the bootstrap key that still opens it. A
key whose blob is already in the file is not added twice.

=item 3.

The admin key is tried on every machine, alone -- no other key is offered.

=item 4.

Only when every machine passed both steps: F<age.key.enc> is written and the
staging file becomes F<keys.yaml>. Commit both.

=back

The machines are every OCPNode in C<ocp-system> when the cluster can be
asked (at C<status.publicIP>, else C<spec.host>), plus the control planes of
F<ocp.yaml> with a known address, deduplicated by address. Without a
F<kubeconfig.yaml> only those control planes count; with none at all the
switch is local. A kubeconfig whose cluster does not answer stops the command
before anything is asked: the workers would be unknown. Pool hosts in
F<ocp.yaml> without an OCPNode are named -- they need both keys before they
join (C<ocp keys authorized-keys>).

A machine that fails step 2 or 3 is named on STDERR with the reason, and the
project stays in dev mode with the staging file in place; the exit code is 1.
Running the command again continues with the staged keys (PIN2 once, to
unlock the staged admin key).

After the switch, as C<ocp apply> would do it:

=over 4

=item *

With Hetzner in the project (a control plane, a worker pool or an
OCPNodeProvider), the public keys are stored in the Hetzner project as
C<ocp-NAME-admin> and C<ocp-NAME-robo>, replacing the bootstrap key that dev
mode stored under the admin name. Servers created afterwards get them;
existing servers were handled in step 2. A project with no token and nothing
deployed leaves this to its first C<ocp apply>, which uploads both anyway.

=item *

With robocop enabled and a cluster to reach, the C<robocop-credentials>
Secret is written with the new robo key (the token read reuses this run's
admin key, no second PIN2) and the Deployment is ensured; a robocop that was
running is restarted to read it.

=back

A failure there does not undo the switch; it is reported, and the exit code
is 1 (C<ocp deploy-robocop> or C<ocp apply> catch up).

=head2 --drop-bootstrap

Removes every F<authorized_keys> line carrying the bootstrap key from every
machine, logged in with the admin key -- and only on a machine where the
admin key has just been accepted. F<.ocp/id_ed25519> itself is not deleted;
the command says when nothing it reaches still trusts it. On a project that
is already secure this is the only thing the command does (PIN2 for the
admin key); without the flag an already-secure project is left alone.

=head2 Prompts

PIN1 twice (when F<age.key.enc> does not exist yet), then PIN2 twice -- or
once, when continuing with staged keys. C<--pins-stdin> reads them as lines
in that order. Without a terminal and without C<--pins-stdin> the command
refuses before doing anything.

=head1 SEE ALSO

L<OCP::Cmd::Keys>, L<OCP::Cmd::Keys::AuthorizedKeys>, L<OCP::ClusterKey>,
L<OCP::Keys>, F<docs/security.md>, F<docs/adr/0027-one-admin-key-reaches-every-machine.md>

=cut
