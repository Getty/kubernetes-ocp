package OCP::Cmd::Apply;
# ABSTRACT: Reconcile cluster to match config

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);
use JSON::MaybeXS qw( decode_json );
use JSON::PP ();

use YAML::XS ();

use Digest::MD5;
use File::Temp;
use HTTP::Tiny;
use Kubernetes::REST::Kubeconfig;
use Socket;

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
use OCP::Cmd::Apply::Workloads;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

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

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;
    my $verbose = $self->ocp->verbose;

    unless (-f $file) {
        die "Config file '$file' not found. Run 'ocp init' first.\n";
    }

    my $config = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    print "╔═══════════════════════════════════════════════════════════════╗\n";
    print "║  CONTROL PLANE DEPLOYMENT (requires admin authentication)    ║\n";
    print "╚═══════════════════════════════════════════════════════════════╝\n\n";

    print "Cluster: ", $config->name, "\n\n";

    # Check if cluster already exists
    if ($config->cluster_exists) {
        print "[ok] Cluster already exists (kubeconfig.yaml found)\n";
        print "     Checking components...\n\n";
        my $reconciled = $self->_reconcile_components($config);

        # No kubeconfig we can decrypt means nothing was reconciled and nothing
        # was looked at. Return without a verdict and without stamping a
        # version — claiming this OCP manages a cluster it could not reach is
        # the same class of lie as the success banner over a dead CoreDNS.
        # _reconcile_components has already said why.
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

        # We need an age key for encrypting the kubeconfig later. In dev mode
        # we never prompt for a PIN: if a plain age.key already exists, use
        # it; otherwise generate a fresh one. We deliberately do NOT touch
        # age.key.enc here — that would imply secure mode and a PIN prompt.
        if (!$secrets->has_age_key) {
            print "[..] Generating age key for kubeconfig encryption (dev mode)\n";
            my $keys = $secrets->generate_age_key;
            print "[ok] Generated age key: $keys->{public_key}\n";
        }
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
        # Secure mode: Use admin-key from keys.yaml (requires PIN2)
        print "Step 1: Unlock encrypted secrets (PIN1 required)\n";
        $secrets->ensure_age_key();
        print "[ok] Secrets unlocked\n\n";

        print "Step 2: Admin authentication (PIN2 required)\n";
        print "        Control plane deployment requires admin-key.\n\n";




        my $keys = OCP::Keys->new(project_dir => $config->project_dir);
        my $pin2 = OCP::Password::prompt_password("Enter PIN2 (admin-key): ");

        $admin_key = $keys->get_admin_key($pin2);
        unless ($admin_key) {
            die "\nERROR: Wrong PIN2 or no admin-key found!\n";
        }

        print "[ok] admin-key decrypted: $admin_key->{name}\n";
        print "[ok] Admin authenticated\n\n";

        $ssh_public_key = $admin_key->{public};
    }

    # Get provider configuration for the step banner — actual provisioning
    # lives in OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane.
    my $cps = $config->control_planes;
    my $first_cp = $cps->[0] // {};
    my $provider = $first_cp->{provider} // 'hetzner';
    my $num_control_planes = scalar @$cps;

    my $deploy_step = $no_password_mode ? 2 : 3;
    print "Step $deploy_step: Deploy control plane(s)\n";
    print "        Provider: $provider\n";
    print "        Count: $num_control_planes\n\n";

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
        no_password_mode => $no_password_mode,
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

sub _selfsigned_issuer {
    return OCP::Cmd::Apply::Network::selfsigned_issuer(@_);
}

sub _acme_issuer {
    return OCP::Cmd::Apply::Network::acme_issuer(@_);
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

sub _corefile_drop_added_hosts {
    return OCP::Cmd::Apply::Network::corefile_drop_added_hosts(@_);
}

sub _corefile_root_block {
    return OCP::Cmd::Apply::Network::corefile_root_block(@_);
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

sub _registry_running {
    my ($self, $config) = @_;
    return OCP::Cmd::Apply::Registry::running($self, $config);
}

sub _generate_registry_manifest {
    my ($self, $config) = @_;
    return OCP::Cmd::Apply::Registry::generate_manifest($self, $config);
}

sub _stamp_ocp_version {
    my ($self, $config) = @_;
    return OCP::Cmd::Apply::Registry::stamp_ocp_version($self, $config);
}

sub _registry_deployment {
    return OCP::Cmd::Apply::Registry::deployment(@_);
}

sub _nodeport_service {
    return OCP::Cmd::Apply::Registry::nodeport_service(@_);
}

#
# Opt-in cluster workloads (NFD + GPU operator) — see OCP::Cmd::Apply::Workloads.
# Forwarders below keep the test surface and the callers in this file stable.
#

sub _setup_nfd {
    return OCP::Cmd::Apply::Workloads::setup_nfd(@_);
}

sub _ensure_nfd_image {
    return OCP::Cmd::Apply::Workloads::ensure_nfd_image(@_);
}

sub _generate_nfd_manifest {
    return OCP::Cmd::Apply::Workloads::generate_nfd_manifest(@_);
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

sub _deployed_hashes_path {
    my ($self, $config) = @_;
    return OCP::Cmd::Apply::DeployedHash::hashes_path($self, $config);
}

sub _load_deployed_hashes {
    my ($self, $config) = @_;
    return OCP::Cmd::Apply::DeployedHash::load($self, $config);
}

sub _save_deployed_hash {
    my ($self, $config, $component, $hash) = @_;
    return OCP::Cmd::Apply::DeployedHash::save($self, $config, $component, $hash);
}

sub _report_component {
    my ($self, $label, $outcome) = @_;
    return OCP::Cmd::Apply::DeployedHash::report_component($self, $label, $outcome);
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

sub _pluralize_kind {
    my ($self, $kind) = @_;
    return OCP::Cmd::Apply::K8s::pluralize_kind($self, $kind);
}

sub _build_resource_path {
    my ($self, $resource) = @_;
    return OCP::Cmd::Apply::K8s::build_resource_path($self, $resource);
}

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

sub _ensure_provider_cr {
    my ($self, $api, $type, $ns, $config, $secrets) = @_;
    return OCP::Cmd::Apply::CR::ensure_provider_cr($self, $api, $type, $ns, $config, $secrets);
}

sub _k8s_node_ip {
    my ($self, $api, $name) = @_;
    return OCP::Cmd::Apply::CR::k8s_node_ip($self, $api, $name);
}

sub _ensure_cp_ocpnode {
    my ($self, $api, $cp_info) = @_;
    return OCP::Cmd::Apply::CR::ensure_cp_ocpnode($self, $api, $cp_info);
}

sub _migrate_legacy_nodes {
    my ($self, $api) = @_;
    return OCP::Cmd::Apply::CR::migrate_legacy_nodes($self, $api);
}

sub _ensure_worker_ocpnodes {
    my ($self, $api, $config) = @_;
    return OCP::Cmd::Apply::CR::ensure_worker_ocpnodes($self, $api, $config);
}

sub _ensure_robocop {
    my ($self, $api) = @_;
    return OCP::Cmd::Apply::CR::ensure_robocop($self, $api);
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
    my ($self, $results) = @_;
    return OCP::Cmd::Apply::CR::print_worker_status($self, $results);
}

#
# Post-deploy cluster health gate — see OCP::Cmd::Apply::Health.
# Forwarders exist so the test surface and the callers inside this file keep
# the same names.
#

sub _classify_pod {
    my ($self, $pod) = @_;
    return OCP::Cmd::Apply::Health::classify_pod($self, $pod);
}

sub _scan_pods {
    my ($self, $api) = @_;
    return OCP::Cmd::Apply::Health::scan_pods($self, $api);
}

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

=head1 NAME

OCP::Cmd::Apply - Deploy control plane (admin-key required)

=head1 SYNOPSIS

    # Deploy control plane (requires PIN2)
    ocp apply

=head1 DESCRIPTION

Deploys the control plane using the admin-ssh key (requires PIN2).

B<Security:> Control planes are SACRED\! Only admin-key can deploy them.
Workers are managed by robocop controller using robo-key.

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
