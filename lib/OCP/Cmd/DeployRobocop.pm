package OCP::Cmd::DeployRobocop;
# ABSTRACT: Deploy robocop controller to the cluster

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);
use YAML::XS ();
use File::Temp ();
use Kubernetes::REST::Kubeconfig;

use OCP;
use OCP::Config;
use OCP::Keys;
use OCP::Node ();      # for the join-token file paths ($RKE2_TOKEN_PATH etc.)
use OCP::Password;
use OCP::Secrets;
use OCP::Share;
use OCP::SSH;

with 'OCP::Role::Cmd';

# The K8s Secret DeployRobocop populates so the controller can reach the
# cluster. Worker R's deployment.yaml only references it (karr #129).
my $CREDENTIALS_SECRET = 'robocop-credentials';
my $ROBOCOP_NAMESPACE  = 'ocp-system';

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config  = OCP::Config->new(file => $file);

    # Decide the key-delivery model before touching the cluster. inject is
    # config-accepted but not yet built (karr #2), so it dies here, clean,
    # before any credential is decrypted or any resource applied.
    my $level = $config->robocop_security_level;
    die "robocop.security_level 'inject' is not yet available (k2)\n"
        if $level eq 'inject';

    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    my $kc_content = $secrets->read_kubeconfig;
    die "ERROR: Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n"
        unless $kc_content;

    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print {$kc_fh} $kc_content;
    close $kc_fh;

    my $api = Kubernetes::REST::Kubeconfig->new(
        kubeconfig_path => $kc_fh->filename,
    )->api;

    # Populate the credentials Secret the controller mounts. Done before the
    # manifests so the namespace and Secret exist by the time the Deployment's
    # pods start; a pod that races ahead restarts and self-heals.
    $self->_apply_credentials_secret($api, $config, $secrets, $level);

    my $share_dir = $self->_find_share_dir;
    my $robocop_dir = $share_dir->child('robocop');
    die "Robocop manifests not found under $robocop_dir\n" unless -d $robocop_dir;

    my @crd_files   = sort $robocop_dir->child('crds')->children(qr/\.ya?ml$/);
    my @other_files = grep { $_->basename ne 'kustomization.yaml' }
                           $robocop_dir->children(qr/\.ya?ml$/);

    for my $file_path (@crd_files, @other_files) {
        my @docs = YAML::XS::LoadFile($file_path->stringify);
        for my $doc (@docs) {
            next unless ref $doc eq 'HASH' && $doc->{kind} && $doc->{metadata}{name};
            my $kind = $doc->{kind};
            my $name = $doc->{metadata}{name};
            $api->ensure($doc);
            print "  [ok] ensured $kind/$name\n";
        }
    }

    print "Robocop deployed.\n";
    return 0;
}

# Write the robocop-credentials Secret according to security_level.
#
# Three keys go in, and only three (karr #129, Weg A):
#   robo-ssh-key   the decrypted PRIVATE robo (automation) key
#   server-url     the RKE2 join URL
#   rke2-token     the node-join token, read off the control-plane disk over SSH
#
# The token lives ONLY as a file on the control plane (no K8s Secret holds it —
# verified for karr #129), so it has to be read over SSH. Reaching the control
# plane needs the key its machines trust: the admin key (PIN2) in secure mode,
# the bootstrap key in --nopassword dev mode. secret_approved unlocks that admin
# key as its explicit approval and reuses it for the SSH read, so a single PIN2
# gate covers all three keys.
sub _apply_credentials_secret {
    my ($self, $api, $config, $secrets, $level) = @_;

    # PIN1: bring the age key online. Every decrypt below (robo key, and the
    # admin key that reaches the control plane) reads .ocp/age.key; this is what
    # unlocks it from age.key.enc when it is not already on disk.
    $secrets->ensure_age_key;

    # secret_approved: a human approves the write with PIN2 BEFORE anything is
    # applied, and the very admin key that unlock yields is what reaches the
    # control plane below — one prompt, reused, no second PIN2.
    my $admin = $level eq 'secret_approved'
        ? $self->_require_pin2_approval($config)
        : undef;

    my ($host, $key) = $self->_cp_ssh_access($config, $admin);
    my $token = $self->_read_join_token($config, $host, $key->path);

    my $creds = $self->_robocop_credentials($config, $host, $token);

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

# Host + private key for reaching the control plane. This is the deploy-path
# STOP the coordinator asked for (karr #129): when there is no address, or no
# key can be had, the token cannot be read at all and there is nothing to fall
# back to, so it dies with a message naming what was missing.
#
# The admin key that secret_approved already unlocked is handed to
# cluster_ssh_key so it does not prompt for PIN2 a second time. Without one,
# cluster_ssh_key selects the admin key (secure mode — prompts PIN2) or the
# bootstrap key (dev mode — no prompt). Same key OCP::Cmd::Apply::CR uses.
sub _cp_ssh_access {
    my ($self, $config, $admin) = @_;

    my $status = $config->cluster_status;
    my $host = $status->{public_ip} // $status->{host};
    die "ERROR: No control-plane address is known for this cluster.\n"
        . "       Run 'ocp apply' first so the RKE2 server can be reached to\n"
        . "       read its join token.\n"
        unless defined $host && length $host;

    my $key = $self->cluster_ssh_key($config, $admin ? (admin_key => $admin) : ());

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

# The three values for the Secret. Only ever the PRIVATE robo key — never the
# admin key that reached the control plane, only the token it fetched.
sub _robocop_credentials {
    my ($self, $config, $host, $token) = @_;

    my $keys = OCP::Keys->new(project_dir => $config->project_dir);

    # purpose 'automation', non-deprecated, age-layer only (no PIN2).
    my $robo = $keys->get_automation_key
        or die "ERROR: No automation (robo) key found in keys.yaml.\n"
             . "       'ocp init' creates it in secure mode; robocop needs it "
             . "to reach the workers it joins.\n";

    my $private = $robo->{private};
    die "ERROR: The robo key carries no private material.\n"
        unless defined $private && length $private;

    return {
        'robo-ssh-key' => $private,
        'server-url'   => $config->join_url($host),
        'rke2-token'   => $token,
    };
}

# The PIN2 approval gate for secret_approved. Unlocking the admin key is both
# the proof that a human holding PIN2 approved the write AND the key that
# reaches the control plane for the token read — so it is RETURNED for reuse,
# not thrown away. A wrong or absent PIN2 dies before anything is written.
sub _require_pin2_approval {
    my ($self, $config) = @_;

    print STDERR
        "  robocop.security_level 'secret_approved': writing the "
      . "$CREDENTIALS_SECRET\n"
      . "  Secret is admin-gated and needs PIN2 approval.\n";

    my $pin2 = OCP::Password::prompt_password("Enter PIN2 (admin approval): ");
    die "ERROR: No PIN2 given; refusing to write $CREDENTIALS_SECRET.\n"
        unless defined $pin2 && length $pin2;

    # A wrong PIN2 makes the double-decrypt die ("AES-GCM authentication
    # failed"); catch it so the refusal reads as a PIN2 problem rather than a
    # crypto-internals leak, and so nothing downstream mistakes it for success.
    my $keys  = OCP::Keys->new(project_dir => $config->project_dir);
    my $admin = eval { $keys->get_admin_key($pin2) };
    die "ERROR: Wrong PIN2 or no admin key; refusing to write "
      . "$CREDENTIALS_SECRET.\n"
        unless $admin;

    return $admin;
}

sub _find_share_dir {
    my ($self) = @_;
    return OCP::Share->dir;
}

1;

__END__

=head1 NAME

OCP::Cmd::DeployRobocop - Deploy robocop controller to the cluster

=head1 SYNOPSIS

    ocp deploy-robocop

Before the manifests, populates the C<robocop-credentials> Secret in
C<ocp-system> that the controller mounts (karr #129). Per
C<robocop.security_level> it writes three keys: C<robo-ssh-key> (the decrypted
private robo key), C<server-url> (the RKE2 join URL) and C<rke2-token> (the
node-join token, read off the control-plane disk over SSH). C<secret> gates the
write behind PIN1 for the age key and whatever key reaches the control plane;
C<secret_approved> additionally requires an explicit PIN2 admin approval, reused
for the SSH read; C<inject> is deferred (karr #2) and refused cleanly.

Then reads manifests from the OCP share directory (C<share/robocop/>), applies
CRDs first and then remaining resources (skipping C<kustomization.yaml>) via
L<Kubernetes::REST/ensure> against the encrypted kubeconfig for the current
project.

=cut
