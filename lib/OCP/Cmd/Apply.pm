package OCP::Cmd::Apply;
# ABSTRACT: Deploy the control plane, or reconcile an existing cluster to match config

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);
use JSON::MaybeXS qw( decode_json );
use JSON::PP ();

use YAML::XS ();

use Digest::MD5;
use HTTP::Tiny;

use OCP::Config;
use OCP::Drift;
use OCP::K8s;
use OCP::Keys;
use OCP::Node;
use OCP::Password;
use OCP::Provider;
use OCP::Secrets;
use OCP::Share;
use OCP::SSH;
use OCP::Rex;
use OCP::Versions;
use MIME::Base64 ();


use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::DeployedHash;
use OCP::Cmd::Apply::Deploy;
use OCP::Cmd::Apply::Drift;
use OCP::Cmd::Apply::Health;
use OCP::Cmd::Apply::K8s;
use OCP::Cmd::Apply::Network;
use OCP::Cmd::Apply::Registry;
use OCP::Cmd::Apply::SopsRepair;
use OCP::Cmd::Apply::Validate;
use OCP::Cmd::Apply::Workloads;

with 'OCP::Role::Cmd';
# robocop's credentials Secret, written before its Deployment wherever apply
# rolls robocop out -- the same code as `ocp deploy-robocop` (k169).
with 'OCP::Role::Cmd::RobocopCredentials';

has _ssh_key_path => (is => 'rw');

# Control-plane identity, as both apply paths have to agree on it: an SSH
# cluster is named after the first label of its host, a Hetzner one uses
# RoboCop naming. The reconcile path needs the same answer as the deploy path
# to address the OCPNode CR of a cluster it did not bootstrap itself.
# See OCP::Cmd::Apply::Bootstrap.

sub _cp_identity {
    my ($self, $config) = @_;
    return OCP::Cmd::Apply::Bootstrap::cp_identity($config);
}

sub _dist_label {
    my ($dist) = @_;
    return OCP::Cmd::Apply::Bootstrap::dist_label($dist);
}

option dry_run => (
    is    => 'ro',
    short => 'n',
    doc   => 'Show what would be done without doing it',
);

option only => (
    is     => 'ro',
    format => 's',
    doc    => 'Only apply: control-planes, workers, or node name',
);

# The install task's clean_cilium_residue (k406), for every install this run
# does itself: the first control plane (OCP::Rex install_server), police2+
# and the workers it drives from the CLI (OCP::Node). Workers robocop drives
# do not get it -- nothing on the OCPNode carries it.
option clean_cilium_residue => (
    is  => 'ro',
    doc => 'Clear Cilium state an earlier cluster left on a machine, without a reboot',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;
    my $verbose = $self->ocp->verbose;

    unless (-f $file) {
        die "Config file '$file' not found. Run 'ocp init' first.\n";
    }

    my $config = OCP::Config->new(file => $file);
    # k255: every ocp.yaml error at once, before a PIN, a file, a host or the cluster.
    OCP::Cmd::Apply::Validate::refuse_invalid_config($config);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    print "╔═══════════════════════════════════════════════════════════════╗\n";
    print "║  CONTROL PLANE DEPLOYMENT (requires admin authentication)    ║\n";
    print "╚═══════════════════════════════════════════════════════════════╝\n\n";

    print "Cluster: ", $config->name, "\n\n";

    # k197: the robocop image is amd64 only; say so before any work starts.
    if (my $arch = $config->robocop_arch_warning) {
        print "$arch\n\n";
        push @{ $self->{_apply_warnings} }, 'robocop arch';
    }

    # k325: an even control-plane count, on STDERR (k368; robocop's: k415).
    if (my $even = $config->even_control_planes_warning) {
        print STDERR "$even\n";
        push @{ $self->{_apply_warnings} }, 'even control planes';
    }

    # k259: re-quote a bare sops lastmodified before either path decrypts; -n names them (k266).
    OCP::Cmd::Apply::SopsRepair::repair_sops_files($self, $secrets);

    # Check if cluster already exists
    if ($config->cluster_exists) {
        print "[ok] Cluster already exists (kubeconfig.yaml found)\n";
        print "     Checking components...\n\n";
        my $reconciled = $self->_reconcile_components($config);

        # Falsy means nothing was reconciled, so there is nothing to pass a
        # verdict on: either no kubeconfig.yaml (said on STDERR), or --dry-run,
        # which stops before the first write. Return without a verdict and
        # without stamping a version — claiming this OCP manages a cluster it
        # could not reach, or deployed one it deliberately did not touch, is
        # the same class of lie as the success banner over a dead CoreDNS.
        # _reconcile_components has already said which of the two it was.
        return 0 unless $reconciled;
        return $self->_finish_apply(
            config  => $config,
            api     => $self->_k8s_api,
            cp_name => $reconciled->{cp_name},
            cp_ip   => $reconciled->{cp_ip},
        );
    }

    # Check if we're in no-password mode (no keys.yaml)
    my $keys_file = $config->project_dir->child('keys.yaml');
    my $no_password_mode = !-f $keys_file;

    my $admin_key;
    my $ssh_public_key;

    if ($no_password_mode) {
        # Dev mode: Use simple SSH key from .ocp/id_ed25519
        print "Step 1: Dev mode (--no_password)\n";
        print "        Using SSH key from .ocp/id_ed25519 (no encryption)\n";

        # The age key the kubeconfig is encrypted to, never behind a PIN in
        # dev mode -- and not made by a dry run (k297). See Bootstrap.
        OCP::Cmd::Apply::Bootstrap::ensure_dev_age_key($self, $secrets);
        print "\n";

        my $ssh_private_key = $config->ssh_private_key_path;
        my $ssh_public_key_path = $config->ssh_public_key_path;

        unless (-f $ssh_private_key) {
            die "ERROR: SSH private key not found: $ssh_private_key\n";
        }

        # Read keys
        my $private_key_content = path($ssh_private_key)->slurp;
        my $public_key_content = -f $ssh_public_key_path ? path($ssh_public_key_path)->slurp : '';
        chomp $public_key_content;

        # Fake admin_key structure for compatibility
        $admin_key = {
            name    => 'dev-ssh-key',
            type    => 'ssh_ed25519',
            purpose => 'dev',
            private => $private_key_content,
            public  => $public_key_content,
        };

        $ssh_public_key = $public_key_content;
        print "[ok] SSH key loaded (dev mode)\n\n";

    } else {
        # k216: not an operator's to make -- see Bootstrap.
        OCP::Cmd::Apply::Bootstrap::assert_first_deploy_identity($config);

        # Secure mode: Use admin-key from keys.yaml (requires PIN2)
        print "Step 1: Unlock encrypted secrets (PIN1 required)\n";
        # A dry run opens the project key into memory and leaves .ocp/ as it
        # is: no age.key cached, no age.pub restored (k349). The admin key
        # below is read with it.
        if ($self->dry_run) { $secrets->unlock_age_key }
        else                { $secrets->ensure_age_key }
        print "[ok] Secrets unlocked\n\n";

        print "Step 2: Admin authentication (PIN2 required)\n";
        print "        Control plane deployment requires admin-key.\n\n";

        my $keys = OCP::Keys->new(project_dir => $config->project_dir,
                                  age_key     => $secrets->age_key);
        my $pin2 = OCP::Password::prompt_password("Enter PIN2 (admin-key): ");
        die "ERROR: No PIN2 given, cannot decrypt the admin key.\n"
            unless defined $pin2 && length $pin2;

        # A wrong PIN2 dies in the PIN2 layer's decrypt, "AES-GCM authentication
        # failed" (k391): refused as a PIN2 problem, as OCP::ClusterKey does.
        # Any other failure (keys.yaml itself) keeps its own words.
        $admin_key = eval { $keys->get_admin_key($pin2) };
        die $@ if !$admin_key && $@ && $@ !~ /\AAES-GCM authentication failed/;
        die "ERROR: Wrong PIN2 or no admin-key found!\n" unless $admin_key;

        print "[ok] admin-key decrypted: $admin_key->{name}\n";
        print "[ok] Admin authenticated\n\n";

        $ssh_public_key = $admin_key->{public};
    }

    # Get provider configuration for the step banner — actual provisioning
    # lives in OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane.
    my $cps = $config->control_planes;
    my $first_cp = $cps->[0] // {};
    my $provider = $first_cp->{provider} // 'hetzner';

    my $deploy_step = $no_password_mode ? 2 : 3;
    $self->_announce_control_planes($config, $deploy_step);

    if ($self->dry_run) {
        print "[Dry run - no changes made]\n";
        return;
    }

    # Deploy first control plane — see OCP::Cmd::Apply::Bootstrap. The full
    # provision/install/wait-Ready sequence lives there; this dispatcher
    # hands it the admin key + ssh public key it just obtained, and gets
    # back a working Kubernetes API handle plus the identity the CR layer
    # below needs to write the control-plane OCPNode.
    my $b = OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
        $self, $config, $secrets,
        admin_key        => $admin_key,
        ssh_public_key   => $ssh_public_key,
        verbose          => $verbose,
    );

    # Now that the cluster is up, put the stack on it — registry, NFD, GPU
    # operator, cert-manager, Cilium Gateway, LB-IPAM, CR layer, workers.
    # Returns the final step counter so the health gate prints the right
    # "Step N: Verify cluster health" line. See OCP::Cmd::Apply::Deploy.
    my $step = OCP::Cmd::Apply::Deploy::deploy($self, {
        config       => $config,
        secrets      => $secrets,
        api          => $b->{api},
        cp_name      => $b->{cp_name},
        cp_ip        => $b->{cp_ip},
        provider     => $provider,
        ssh_key_path => $b->{ssh_key_path},
        deploy_step  => $deploy_step,
    });

    return $self->_finish_apply(
        config  => $config,
        api     => $b->{api},
        step    => $step,
        cp_name => $b->{cp_name},
        cp_ip   => $b->{cp_ip},
    );
}

# Announce the control-plane deploy step, honestly.
#
# OCP::Config normalises `control_planes` (array form, or a single entry with
# `nodes: N`) into an N-element arrayref. For RKE2, `ocp apply` now bootstraps
# police1 and joins police2+ to its embedded-etcd cluster (k8), so all N are
# deployed and the banner says so. For k3s, multi-CP HA is out of scope by
# decision: only police1 is built, and more than one configured control plane
# is a loud STDERR warning (diagnosis is a STDERR concern, never the STDOUT
# progress channel) rather than a silent "Count: N" that deploys one. The
# single-CP path is unchanged for both.
sub _announce_control_planes {
    my ($self, $config, $deploy_step) = @_;

    my $cps      = $config->control_planes;
    my $num      = scalar @$cps;
    my $provider = ($cps->[0] // {})->{provider} // 'hetzner';
    my $dist     = $config->distribution || 'rke2';
    my $ha_ok    = $dist eq 'rke2';

    if ($num > 1 && !$ha_ok) {
        warn "WARNING: $num control planes configured, but only the first "
           . "(police1) is deployed — multi-control-plane HA is RKE2-only, "
           . "not supported for $dist (k8).\n";
    }

    print "Step $deploy_step: Deploy control plane(s)\n";
    print "        Provider: $provider\n";
    print $num > 1 && !$ha_ok
        ? "        Control planes: $num configured, deploying 1 (police1)\n\n"
        : "        Count: $num\n\n";

    return $num;
}

#
#
# The single exit of `ocp apply` lives in OCP::Cmd::Apply::Health::finish.
# This forwarder keeps the existing call sites and the test surface (t/37)
# working without changes.
#

sub _finish_apply {
    return OCP::Cmd::Apply::Health::finish(@_);
}
#
# Cluster ingress (cert-manager + Cilium Gateway + LB-IPAM + CoreDNS) —
# see OCP::Cmd::Apply::Network. Forwarders below keep the test surface
# and the callers in this file stable.
#

sub _apply_cert_manager {
    return OCP::Cmd::Apply::Network::apply_cert_manager(@_);
}

sub _wait_cert_manager_and_create_issuers {
    return OCP::Cmd::Apply::Network::wait_cert_manager_and_create_issuers(@_);
}

sub _create_cert_issuers {
    return OCP::Cmd::Apply::Network::create_cert_issuers(@_);
}

sub _setup_cilium_gateway {
    return OCP::Cmd::Apply::Network::setup_cilium_gateway(@_);
}

sub _setup_lb_ipam {
    return OCP::Cmd::Apply::Network::setup_lb_ipam(@_);
}

sub _configure_registry_dns {
    return OCP::Cmd::Apply::Network::configure_registry_dns(@_);
}

sub _corefile_with_host {
    return OCP::Cmd::Apply::Network::corefile_with_host(@_);
}

# t/39 reads the writer's list of CoreDNS ConfigMap names from the apply
# package — make sure the array at OCP::Cmd::Apply::COREDNS_CONFIGMAPS is
# the same object (alias, not copy) that lives in the Network module.
our @COREDNS_CONFIGMAPS = @OCP::Cmd::Apply::Network::COREDNS_CONFIGMAPS;

#
# Registry (Pull-Through Cache + Local) — see OCP::Cmd::Apply::Registry.
# Forwarders below keep the test surface and the callers in this file stable.
#

sub _setup_registry {
    my ($self, $config) = @_;
    return OCP::Cmd::Apply::Registry::setup($self, $config);
}

sub _stamp_ocp_version {
    my ($self, $config) = @_;
    return OCP::Cmd::Apply::Registry::stamp_ocp_version($self, $config);
}

sub _registry_deployment {
    return OCP::Cmd::Apply::Registry::deployment(@_);
}

#
# Opt-in cluster workloads (NFD + GPU operator) — see OCP::Cmd::Apply::Workloads.
# Forwarders below keep the test surface and the callers in this file stable.
#

sub _setup_nfd {
    return OCP::Cmd::Apply::Workloads::setup_nfd(@_);
}

sub _setup_gpu_operator_after_join {
    return OCP::Cmd::Apply::Workloads::setup_gpu_operator_after_join(@_);
}

sub _setup_gpu_operator {
    return OCP::Cmd::Apply::Workloads::setup_gpu_operator(@_);
}

sub _generate_gpu_operator_manifest {
    return OCP::Cmd::Apply::Workloads::generate_gpu_operator_manifest(@_);
}

#
# Share directory (static CRDs, etc.)
#

sub _find_share_dir {
    my ($self) = @_;
    return OCP::Share->dir;
}

#
# Deploy hash tracking (.ocp/deployed.yaml) — see OCP::Cmd::Apply::DeployedHash.
# Forwarders exist so the test surface and the callers inside this file keep
# the same names.
#

sub _load_deployed_hashes {
    my ($self, $config) = @_;
    return OCP::Cmd::Apply::DeployedHash::load($self, $config);
}

sub _save_deployed_hash {
    my ($self, $config, $component, $hash) = @_;
    return OCP::Cmd::Apply::DeployedHash::save($self, $config, $component, $hash);
}

sub _report_component {
    my ($self, $label, $outcome, $changed) = @_;
    return OCP::Cmd::Apply::DeployedHash::report_component($self, $label, $outcome, $changed);
}

sub _k8s_api {
    my ($self, $kubeconfig) = @_;
    return OCP::Cmd::Apply::K8s::api($self, $kubeconfig);
}

#
# Kubernetes API helpers — see OCP::Cmd::Apply::K8s.
# Forwarders exist so the test surface (local *OCP::Cmd::Apply::_server_side_apply
# = sub { ... }) keeps working.
#

sub _server_side_apply {
    my ($self, $api, $resource) = @_;
    return OCP::Cmd::Apply::K8s::server_side_apply($self, $api, $resource);
}

sub _server_side_apply_all {
    my ($self, $api, @resources) = @_;
    return OCP::Cmd::Apply::K8s::server_side_apply_all($self, $api, @resources);
}

sub _apply_yaml_string {
    my ($self, $api, $yaml_string) = @_;
    return OCP::Cmd::Apply::K8s::apply_yaml_string($self, $api, $yaml_string);
}

sub _apply_yaml_file {
    my ($self, $api, $file_path) = @_;
    return OCP::Cmd::Apply::K8s::apply_yaml_file($self, $api, $file_path);
}

sub _poll_deployment_ready {
    my ($self, $api, $name, $namespace, $timeout) = @_;
    return OCP::Cmd::Apply::K8s::poll_deployment_ready($self, $api, $name, $namespace, $timeout);
}

sub _resource_exists {
    my ($self, $api, $kind, $name, %opts) = @_;
    return OCP::Cmd::Apply::K8s::resource_exists($self, $api, $kind, $name, %opts);
}

sub _crd_get {
    my ($self, $api, $resource_path) = @_;
    return OCP::Cmd::Apply::K8s::crd_get($self, $api, $resource_path);
}

sub _setup_ssh_key {
    return OCP::Cmd::Apply::Bootstrap::setup_ssh_key(@_);
}

#
# Worker deployment is CR-driven. All the OCPNode/OCPNodeProvider helpers
# (_ensure_crds, _ensure_providers, _ensure_cp_ocpnode, _migrate_legacy_nodes,
# _ensure_worker_ocpnodes, _ensure_robocop, _wait_robocop_ready,
# _drive_workers, _print_worker_status) live in OCP::Cmd::Apply::CR and are
# re-exported below as thin forwarders. Actual provisioning runs through
# OCP::Node->reconcile_until_ready (CLI path) or via Robocop once the
# controller is live.
#

sub _ensure_crds {
    my ($self, $api) = @_;
    return OCP::Cmd::Apply::CR::ensure_crds($self, $api);
}

sub _ensure_providers {
    my ($self, $api, $config, $secrets) = @_;
    return OCP::Cmd::Apply::CR::ensure_providers($self, $api, $config, $secrets);
}

sub _ensure_cp_ocpnode {
    my ($self, $api, $cp_info) = @_;
    return OCP::Cmd::Apply::CR::ensure_cp_ocpnode($self, $api, $cp_info);
}

sub _ensure_control_plane_ocpnodes {
    my ($self, $api, $config) = @_;
    return OCP::Cmd::Apply::CR::ensure_control_plane_ocpnodes($self, $api, $config);
}

sub _migrate_legacy_nodes {
    my ($self, $api) = @_;
    return OCP::Cmd::Apply::CR::migrate_legacy_nodes($self, $api);
}

sub _ensure_worker_ocpnodes {
    my ($self, $api, $config, $names) = @_;
    return OCP::Cmd::Apply::CR::ensure_worker_ocpnodes($self, $api, $config, $names);
}

sub _ensure_robocop {
    my ($self, $api, $config) = @_;
    return OCP::Cmd::Apply::CR::ensure_robocop($self, $api, $config);
}

sub _wait_robocop_ready {
    my ($self, $api, $timeout) = @_;
    return OCP::Cmd::Apply::CR::wait_robocop_ready($self, $api, $timeout);
}

sub _drive_workers {
    my ($self, $api, $config, $deps) = @_;
    return OCP::Cmd::Apply::CR::drive_workers($self, $api, $config, $deps);
}

sub _poll_nodes_until_terminal {
    my ($self, $api, $names, $timeout) = @_;
    return OCP::Cmd::Apply::CR::poll_nodes_until_terminal($self, $api, $names, $timeout);
}

sub _cli_reconcile_workers {
    my ($self, $api, $config, $names, $deps) = @_;
    return OCP::Cmd::Apply::CR::cli_reconcile_workers($self, $api, $config, $names, $deps);
}

sub _print_worker_status {
    my ($self, $results, $label) = @_;
    return OCP::Cmd::Apply::CR::print_worker_status($self, $results, $label);
}

#
# Post-deploy cluster health gate — see OCP::Cmd::Apply::Health.
# Forwarders exist so the test surface and the callers inside this file keep
# the same names.
#

sub _check_cluster_health {
    my ($self, $api, %opts) = @_;
    return OCP::Cmd::Apply::Health::check($self, $api, %opts);
}

sub _print_health {
    my ($self, $health) = @_;
    return OCP::Cmd::Apply::Health::print($self, $health);
}

sub _health_is_fatal {
    my ($self, $health) = @_;
    return OCP::Cmd::Apply::Health::is_fatal($self, $health);
}

sub _health_banner_text {
    my ($self, $health) = @_;
    return OCP::Cmd::Apply::Health::banner_text($self, $health);
}

sub _banner {
    my ($self, $text) = @_;
    return OCP::Cmd::Apply::Health::banner($self, $text);
}

#
# Reconciliation for existing clusters — see OCP::Cmd::Apply::Drift.
# Forwarders exist so the test surface (t/38) and the callers inside this
# file keep the same names.
#

sub _reconcile_components {
    return OCP::Cmd::Apply::Drift::reconcile_components(@_);
}

sub _run_remedy {
    return OCP::Cmd::Apply::Drift::run_remedy(@_);
}

1;

__END__

=head1 SYNOPSIS

    # Deploy control plane (requires PIN2)
    ocp apply

=head1 DESCRIPTION

Deploys the control plane using the admin-ssh key (requires PIN2).

B<Security:> Control planes are SACRED\! Only admin-key can deploy them.
Workers are managed by robocop controller using robo-key.

=opt clean_cilium_residue

    ocp apply --clean_cilium_residue

A machine that was a node of an earlier cluster and was uninstalled without a
reboot can still carry Cilium's datapath (pinned eBPF programs and maps,
cgroup programs, F</run/cilium>), which would hang every image pull of the new
install. Without this switch the install refuses such a machine, when it has
no RKE2 or K3s, before anything on it is changed, naming a reboot and this
switch. With it the install clears that state without a reboot
(L<Rex::Rancher::Uninstall/check_cilium_residue> with C<clean>) and checks
again: anything left fails the install, asking for a reboot. A machine with
nothing on it, or one running RKE2 or K3s, is not touched.

It reaches every install this run does itself: the first control plane, the
additional ones, and the workers the CLI brings up. Workers Robocop brings up
do not get it -- Robocop takes no such switch, and its refusal asks for a
reboot.

=method execute

Bootstraps the first control plane imperatively, then switches to a CR-first
flow: ensures the C<OCPNode>/C<OCPNodeProvider> CRDs, writes one
C<OCPNodeProvider> (and backing Secret for Hetzner) per unique provider
referenced in C<ocp.yaml>, writes an observational C<OCPNode> for the CP with
C<phase: Ready>, and writes a C<Pending> C<OCPNode> per worker-pool entry.

If C<robocop> is enabled (see L<OCP::Config/robocop_enabled>) the robocop
Deployment is applied and given 60s to become ready; on success the CLI simply
polls worker C<OCPNode> phases until terminal (Ready/Failed/timeout). If
robocop is disabled or fails to come up, the CLI drives each worker directly
through L<OCP::Node/reconcile_until_ready>.

=cut
