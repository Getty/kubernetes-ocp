package OCP::Role::Cmd::RobocopCredentials;
# ABSTRACT: Write robocop's credentials Secret per robocop.security_level

use Moo::Role;

use MIME::Base64 ();

use OCP::Keys;
use OCP::Node ();      # for the join-token file paths ($RKE2_TOKEN_PATH etc.)
use OCP::Secrets;
use OCP::SSH;

requires qw( cluster_ssh_key cluster_ssh_key_if_known require_admin_approval );

# The K8s Secret the robocop Deployment mounts (share/robocop/deployment.yaml,
# k129). `ocp deploy-robocop` and `ocp apply` both write it through this role,
# so the two can never disagree about what robocop finds in it (k169).
my $CREDENTIALS_SECRET = 'robocop-credentials';
my $ROBOCOP_NAMESPACE  = 'ocp-system';

# The `ocp apply` entry: leave a Secret alone that already says what this
# write would say, write it otherwise.
#
# "Already says" is checked on what can be had without leaving the process:
# the exact key set of the level, the robo key (age layer only -- the PIN1 of
# this apply unlocked it already), the join URL, and a non-empty rke2-token.
# The token itself is NOT compared: knowing it means an SSH read of the control
# plane, which in secure mode costs the admin key, i.e. a PIN2 prompt -- the
# one cost this check exists to avoid on every reconcile. The node-token file
# does not change over a cluster's life (the Rexfile reuses it, k84), so a
# token that is there is taken as the right one; `ocp deploy-robocop` rewrites
# it unconditionally when it has to be refreshed.
#
# Returns 'current' or 'written'. Dies, writing nothing, when the Secret has to
# be written and cannot be (no host, no key, refused PIN2, empty token).
sub _ensure_robocop_credentials {
    my ($self, $api, $config, $secrets, $level, %opt) = @_;

    $secrets //= OCP::Secrets->new(project_dir => $config->project_dir);

    if ($self->_robocop_credentials_current($api, $config, $secrets, $level, %opt)) {
        print "  [ok] Secret/$CREDENTIALS_SECRET is current ($level)\n";
        return 'current';
    }

    $self->_apply_credentials_secret($api, $config, $secrets, $level, %opt);
    return 'written';
}

# Write the robocop-credentials Secret according to security_level.
#
# Three keys go in, and only three (k129, Weg A):
#   robo-ssh-key   the decrypted PRIVATE robo (automation) key
#                  (inject: robo-ssh-public-key, its public half, instead)
#   server-url     the RKE2 join URL
#   rke2-token     the node-join token, read off the control-plane disk over SSH
#
# The token lives ONLY as a file on the control plane (no K8s Secret holds it --
# verified for k129), so it has to be read over SSH. Reaching the control
# plane needs the key its machines trust: the admin key (PIN2) in secure mode,
# the bootstrap key in --nopassword dev mode. secret_approved's PIN2 approval
# unlocks that admin key and reuses it for the SSH read, so a single PIN2
# covers everything.
#
# %opt: host -- the control plane to read the token from and to name in the
# join URL. `ocp apply` has it in hand; without it, the cluster status is asked.
sub _apply_credentials_secret {
    my ($self, $api, $config, $secrets, $level, %opt) = @_;

    # PIN1: bring the age key online. Every decrypt below (robo key, and the
    # admin key that reaches the control plane) reads .ocp/age.key; this is what
    # unlocks it from age.key.enc when it is not already on disk.
    $secrets->ensure_age_key;

    # secret_approved: a human approves the write with PIN2 BEFORE anything is
    # applied, and the very admin key that unlock yields is what reaches the
    # control plane below -- one prompt, reused, no second PIN2.
    my $admin = $level eq 'secret_approved'
        ? $self->_robocop_admin_approval($config)
        : undef;

    my ($host, $key) = $self->_cp_ssh_access($config, $admin, $opt{host});
    my $token = $self->_read_join_token($config, $host, $key->path);

    my $creds = $self->_robocop_credentials($config, $host, $token, $level);

    # The namespace has to exist before the Secret can land in it. Idempotent;
    # the robocop manifests re-apply it a moment later.
    $api->ensure({
        apiVersion => 'v1',
        kind       => 'Namespace',
        metadata   => { name => $ROBOCOP_NAMESPACE },
    });

    $api->ensure({
        apiVersion => 'v1',
        kind       => 'Secret',
        metadata   => {
            name      => $CREDENTIALS_SECRET,
            namespace => $ROBOCOP_NAMESPACE,
        },
        type       => 'Opaque',
        stringData => $creds,
    });

    print "  [ok] ensured Secret/$CREDENTIALS_SECRET ($level)\n";
    return;
}

# The PIN2 approval secret_approved asks for, given at most once per run.
#
# A command that already holds the ADMIN key has had PIN2 typed into it in this
# very run: `ocp apply` on a fresh cluster unlocks it in its "Admin
# authentication" step before anything is built, and a reconcile that repaired
# drift over SSH unlocked it for that. The approval secret_approved wants is
# exactly that proof -- a human holding PIN2 is at the keyboard for this run --
# so asking for the same PIN2 again a few steps later would add a prompt, not
# safety. The held key is then what cluster_ssh_key hands back below, so undef
# (nothing to pass along) is the right answer here.
#
# Only an admin-origin key counts. The bootstrap key of dev mode cost no PIN2,
# and an on-disk key proves nobody is present; both go to the prompt, which in
# dev mode (no admin key at all) refuses.
sub _robocop_admin_approval {
    my ($self, $config) = @_;

    my $held = $self->cluster_ssh_key_if_known($config);
    if ($held && ($held->origin // '') eq 'admin') {
        print "  [ok] secret_approved: approved by the PIN2 given earlier in this run\n";
        return undef;
    }

    return $self->require_admin_approval($config,
        "robocop.security_level 'secret_approved': writing the "
      . "$CREDENTIALS_SECRET Secret");
}

# Does the Secret in the cluster already carry what a write would put there?
# See _ensure_robocop_credentials for what is compared and why the token is not.
# Any failure to tell -- no Secret, a read error, no host -- is a "no": the
# write that follows then fails loud with the real reason, instead of a skip
# hiding it.
sub _robocop_credentials_current {
    my ($self, $api, $config, $secrets, $level, %opt) = @_;

    my $data = eval {
        my $obj = $api->get('Secret', $CREDENTIALS_SECRET,
            namespace => $ROBOCOP_NAMESPACE);
        my $s = ref $obj eq 'HASH' ? $obj : $api->k8s->object_to_struct($obj);
        _secret_values($s);
    } or return 0;

    my $host = eval { $self->_cp_host($config, $opt{host}) } or return 0;

    $secrets->ensure_age_key;
    my %key = eval { $self->_robo_key_entry($config, $level) } or return 0;

    my %want = (
        %key,
        'server-url' => $config->join_url($host),
    );

    my @have = sort grep { $_ ne 'rke2-token' } keys %$data;
    return 0 unless join("\0", @have) eq join("\0", sort keys %want);
    return 0 unless length($data->{'rke2-token'} // '');
    for my $k (keys %want) {
        return 0 unless ($data->{$k} // '') eq $want{$k};
    }
    return 1;
}

# A Secret's values as plain strings. The API server hands back `data`,
# base64-encoded; `stringData` is write-only there but what a hash handed in
# directly carries.
sub _secret_values {
    my ($s) = @_;
    my %v;
    my $data = $s->{data} // {};
    $v{$_} = MIME::Base64::decode_base64($data->{$_}) for keys %$data;
    my $plain = $s->{stringData} // {};
    $v{$_} = $plain->{$_} for keys %$plain;
    return \%v;
}

# The control-plane address: the one the caller has in hand, else the
# cluster status. This is the deploy-path STOP asked for in k129: without an
# address the token cannot be read at all and there is nothing to fall back to.
sub _cp_host {
    my ($self, $config, $host) = @_;

    unless (defined $host && length $host) {
        my $status = $config->cluster_status;
        $host = $status->{public_ip} // $status->{host};
    }
    die "ERROR: No control-plane address is known for this cluster.\n"
        . "       Run 'ocp apply' first so the RKE2 server can be reached to\n"
        . "       read its join token.\n"
        unless defined $host && length $host;

    return $host;
}

# Host + private key for reaching the control plane.
#
# The admin key a secret_approved approval unlocked is handed to
# cluster_ssh_key so it does not prompt for PIN2 a second time. Without one,
# cluster_ssh_key returns the key this command already holds, or selects the
# admin key (secure mode -- prompts PIN2) or the bootstrap key (dev mode -- no
# prompt). Same key OCP::Cmd::Apply::CR uses.
sub _cp_ssh_access {
    my ($self, $config, $admin, $host) = @_;

    $host = $self->_cp_host($config, $host);

    my $key = $self->cluster_ssh_key($config,
        reason => 'robocop credentials',
        ($admin ? (admin_key => $admin) : ()),
    );

    return ($host, $key);
}

# Read the RKE2/K3s node-join token off the control plane over SSH, mirroring
# OCP::Cmd::Apply::CR. The token is a file on disk whose path differs by
# distribution; robocop later hands it to the agents it joins.
sub _read_join_token {
    my ($self, $config, $host, $key_path) = @_;

    my $token_path = ($config->distribution || 'rke2') eq 'k3s'
        ? $OCP::Node::K3S_TOKEN_PATH
        : $OCP::Node::RKE2_TOKEN_PATH;

    my $token = '';
    eval {
        my $ssh = OCP::SSH->new(host => $host, key_file => $key_path, user => 'root');
        my $res = $ssh->run("cat $token_path");
        $token = $res->{stdout} // '';
        chomp $token;
        1;
    };
    my $ssh_err = $@;

    return $token if length $token;

    # The control plane refused the key or the file was empty. A refused admin
    # key on a cluster set up before ADR 0027 is the likely cause, so append the
    # migration hint when we hold a key that can explain it.
    my $known = $self->cluster_ssh_key_if_known($config);
    my $hint  = $known ? $known->migration_hint : '';
    die "ERROR: Could not read the RKE2 join token from the control plane "
      . "($host).\n"
      . ($ssh_err ? "       $ssh_err" : "       The token file was empty.\n")
      . $hint;
}

# The three values for the Secret. Only ever the robo key -- never the admin
# key that reached the control plane, only the token it fetched. The Secret is
# replaced as a whole (ensure is a PUT), so a robo-ssh-key left from an earlier
# secret-level deploy goes away when the level becomes inject.
sub _robocop_credentials {
    my ($self, $config, $host, $token, $level) = @_;

    return {
        $self->_robo_key_entry($config, $level),
        'server-url' => $config->join_url($host),
        'rke2-token' => $token,
    };
}

# The robo key's entry in the Secret: its PRIVATE half under robo-ssh-key for
# the secret levels; for inject (k2) its PUBLIC half under robo-ssh-public-key,
# which robocop checks an injected key against -- the private key reaches the
# pod only through `ocp inject-key`.
sub _robo_key_entry {
    my ($self, $config, $level) = @_;

    my $keys = OCP::Keys->new(project_dir => $config->project_dir);

    # purpose 'automation', non-deprecated, age-layer only (no PIN2).
    my $robo = $keys->get_automation_key
        or die "ERROR: No automation (robo) key found in keys.yaml.\n"
             . "       'ocp init' creates it in secure mode; robocop needs it "
             . "to reach the workers it joins.\n";

    if (($level // '') eq 'inject') {
        my $public = $robo->{public};
        die "ERROR: The robo key carries no public half in keys.yaml; "
          . "robocop could not check an injected key against it.\n"
            unless defined $public && length $public;
        return ('robo-ssh-public-key' => $public);
    }

    my $private = $robo->{private};
    die "ERROR: The robo key carries no private material.\n"
        unless defined $private && length $private;

    return ('robo-ssh-key' => $private);
}

1;

__END__

=synopsis

    package OCP::Cmd::Something;
    use Moo;
    with 'OCP::Role::Cmd', 'OCP::Role::Cmd::RobocopCredentials';

    # ocp deploy-robocop: always write
    $self->_apply_credentials_secret($api, $config, $secrets, $level);

    # ocp apply: write unless the Secret is already current
    $self->_ensure_robocop_credentials($api, $config, $secrets, $level,
        host => $cp_ip);

=description

The one implementation of the C<robocop-credentials> Secret in C<ocp-system>
that the robocop Deployment mounts (k129), shared by C<ocp deploy-robocop> and
every path of C<ocp apply> that rolls robocop out (k169). It must be in place
B<before> the Deployment, or the pod sits in C<CreateContainerConfigError>.

Per C<robocop.security_level> it writes C<server-url> (the RKE2 join URL),
C<rke2-token> (the node-join token, read off the control plane over SSH) and
the robo key: C<robo-ssh-key>, the private half, for C<secret> and
C<secret_approved>; C<robo-ssh-public-key>, the public half, for C<inject>,
where the private key only ever reaches the pod through C<ocp inject-key>.

C<secret_approved> requires a PIN2 approval before anything is written. A
command that already unlocked the admin key in this run -- C<ocp apply>'s
admin authentication step, or a reconcile that used it for a remedy -- has had
PIN2 given and is not asked again; otherwise C<require_admin_approval> of
L<OCP::Role::Cmd> prompts, and the admin key it yields is reused for the SSH
read of the token.

C<_ensure_robocop_credentials> skips the write when the Secret already carries
the level's key set, the current robo key and join URL, and a non-empty token.
The token's value is not compared: that would need the SSH read, and with it
the admin key and a PIN2 prompt on every reconcile. C<ocp deploy-robocop>
always writes.

Consumers must also consume L<OCP::Role::Cmd>.

=seealso

L<OCP::Cmd::DeployRobocop>, L<OCP::Cmd::Apply::Deploy>,
L<OCP::Robocop::Manifest>, L<OCP::Role::Cmd>

=cut
