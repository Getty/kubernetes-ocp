package OCP::Cmd::Apply;
# ABSTRACT: Reconcile cluster to match config

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);

use OCP::Config;
use OCP::Secrets;
use OCP::SSH;
use OCP::Rex;
use OCP::Versions;
use WWW::Hetzner::Cloud;

our $VERSION = '0.1.0';

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

    my $file = $chain->[0]->config;
    my $verbose = $chain->[0]->verbose;

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
        print "     Control planes are already deployed.\n\n";
        print "To manage workers, use:\n";
        print "  kubectl apply -f workers.yaml\n";
        print "  (or deploy robocop for automated management)\n";
        return;
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

        # Still need age.key for secrets.yaml (but no PIN1 prompt in dev mode)
        if ($secrets->has_age_key || $secrets->has_age_key_enc) {
            eval { $secrets->ensure_age_key() };
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

        require OCP::Keys;
        require OCP::Password;

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

    # Get provider configuration
    my $hetzner_token = $secrets->hetzner_token;

    # Get control plane spec
    my $cp_spec = $config->control_planes;
    my $provider = $cp_spec->{provider};
    my $num_control_planes = $cp_spec->{nodes} || 1;

    # Initialize cloud provider if needed
    my $cloud;
    if ($provider eq 'hetzner') {
        unless ($hetzner_token) {
            die "Hetzner API token required.\n" .
                "Set HETZNER_API_TOKEN or run 'ocp init --hetzner' to configure.\n";
        }
        $cloud = WWW::Hetzner::Cloud->new(token => $hetzner_token);
    }

    my $deploy_step = $no_password_mode ? 2 : 3;
    print "Step $deploy_step: Deploy control plane(s)\n";
    print "        Provider: $provider\n";
    print "        Count: $num_control_planes\n\n";

    if ($self->dry_run) {
        print "[Dry run - no changes made]\n";
        return;
    }

    # Deploy first control plane (RKE2 server)
    my $cp_name = 'police1';  # RoboCop naming!

    print "Deploying control plane: $cp_name\n";

    # Create server (Hetzner/SSH)
    my $cp_host;
    my $cp_ip;

    if ($provider eq 'hetzner') {
        print "  [..] Creating Hetzner server...\n";

        # Ensure SSH key in Hetzner Cloud
        my $key_name = "ocp-" . $config->name . "-admin";
        $cloud->ssh_keys->ensure($key_name, $admin_key->{public});

        # Create server
        my $server = $cloud->servers->create(
            name        => $config->name . "-" . $cp_name,
            server_type => $cp_spec->{serverType} // 'cx32',
            image       => $cp_spec->{image} // 'debian-13',
            location    => $cp_spec->{location} // 'fsn1',
            ssh_keys    => [$key_name],
            labels      => {
                'ocp-cluster' => $config->name,
                'ocp-role'    => 'control-plane',
                'ocp-node'    => $cp_name,
            },
        );

        print "  [ok] Server created: " . $server->id . "\n";
        print "  [..] Waiting for server to be running...\n";

        $server = $cloud->servers->wait_for_status($server->id, 'running', 120);
        $cp_ip = $server->ipv4;
        $cp_host = $cp_ip;

        print "  [ok] Server running: $cp_ip\n";

    } elsif ($provider eq 'ssh') {
        # SSH provider - use existing host
        $cp_host = $cp_spec->{host} or die "SSH provider requires 'host' in controlPlanes spec\n";
        $cp_ip = $cp_host;
        print "  [ok] Using existing host: $cp_host\n";

    } else {
        die "Unsupported provider: $provider\n";
    }

    # Wait for SSH
    print "  [..] Waiting for SSH to be ready...\n";

    # Prepare SSH key file (Rex needs both private + .pub!)
    my $ssh_key_path;
    my $temp_key_file;
    my $temp_pub_file;

    if ($no_password_mode) {
        # Dev mode: Use actual key file path directly (has .pub!)
        $ssh_key_path = $config->ssh_private_key_path;
    } else {
        # Secure mode: Write BOTH private and public key to temp files
        require File::Temp;

        # Private key
        $temp_key_file = File::Temp->new(SUFFIX => '.key', UNLINK => 1);
        print $temp_key_file $admin_key->{private};
        close $temp_key_file;
        chmod 0600, $temp_key_file->filename;
        $ssh_key_path = $temp_key_file->filename;

        # Public key (Rex expects key_file.pub!)
        my $pub_path = $temp_key_file->filename . '.pub';
        path($pub_path)->spew($admin_key->{public});
        chmod 0644, $pub_path;
    }

    my $ssh = OCP::SSH->new(
        host     => $cp_host,
        key_file => $ssh_key_path,
        user     => 'root',
    );

    eval { $ssh->wait_for_ssh(120) };
    if ($@) {
        die "  [FAIL] SSH not ready: $@\n";
    }
    print "  [ok] SSH ready\n";

    # Install RKE2 server
    print "  [..] Installing RKE2 server...\n";

    my $rex = OCP::Rex->new(
        host     => $cp_host,
        key_file => $ssh_key_path,
        user     => 'root',
        verbose  => $verbose,
    );

    my $distribution = $config->distribution || 'rke2';
    my $version = $config->version || '';

    my $result = $rex->install_server(
        distribution => $distribution,
        version      => $version,
        node_name    => $cp_name,
    );

    print "  [ok] RKE2 server installed\n";

    # Save kubeconfig (encrypted)
    print "  [..] Saving kubeconfig...\n";
    $secrets->save_kubeconfig($result->{kubeconfig});

    # Also write decrypted to .kube/config for kubectl
    my $kube_dir = $config->project_dir->child('.kube');
    $kube_dir->mkpath unless -d $kube_dir;
    my $kube_config = $kube_dir->child('config');
    $kube_config->spew($result->{kubeconfig});
    $kube_config->chmod(0600);

    print "  [ok] Kubeconfig saved (encrypted to kubeconfig.yaml)\n";
    print "  [ok] Kubeconfig written to .kube/config (for kubectl)\n";

    # Install cert-manager (unless nocert: true)
    unless ($config->no_cert) {
        print "  [..] Installing cert-manager...\n";
        eval {
            $self->_install_cert_manager($config, $result->{kubeconfig});
        };
        if ($@) {
            print "  [WARN] cert-manager installation failed: $@\n";
        } else {
            print "  [ok] cert-manager ready\n";
        }
    }

    # Setup Cilium Gateway API
    print "  [..] Setting up Cilium Gateway API...\n";
    eval {
        $self->_setup_cilium_gateway($config, $result->{kubeconfig});
    };
    if ($@) {
        print "  [WARN] Cilium Gateway setup failed: $@\n";
    } else {
        print "  [ok] Cilium Gateway ready\n";
    }

    # Setup LB-IPAM for bare-metal LoadBalancer support (unless nolbipam: true)
    unless ($config->no_lbipam) {
        print "  [..] Setting up LB-IPAM...\n";
        eval {
            $self->_setup_lb_ipam($cp_ip, $result->{kubeconfig});
        };
        if ($@) {
            print "  [WARN] LB-IPAM setup failed: $@\n";
        } else {
            print "  [ok] LB-IPAM ready\n";
        }
    }

    # Done!
    print "\n";
    print "╔═══════════════════════════════════════════════════════════════╗\n";
    print "║  CONTROL PLANE DEPLOYED SUCCESSFULLY!                        ║\n";
    print "╚═══════════════════════════════════════════════════════════════╝\n\n";

    print "Cluster: ", $config->name, "\n";
    print "Control Plane: $cp_name ($cp_ip)\n";
    print "API Endpoint: https://$cp_ip:9345\n\n";

    print "Next steps:\n";
    print "  1. Test cluster access:\n";
    print "     kubectl get nodes\n\n";
    print "  2. Deploy robocop for automated worker management:\n";
    print "     ocp deploy robocop\n\n";
    print "  3. Or manually add workers:\n";
    print "     kubectl apply -f workers.yaml\n\n";
}

sub _install_cert_manager {
    my ($self, $config, $kubeconfig) = @_;

    die "No kubeconfig available\n" unless $kubeconfig;

    # Write kubeconfig to temp file
    require File::Temp;
    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $kc_fh $kubeconfig;
    close $kc_fh;
    my $kc_path = $kc_fh->filename;

    # Install cert-manager from official manifests
    my $version = 'v1.14.0';
    my $url = "https://github.com/cert-manager/cert-manager/releases/download/$version/cert-manager.yaml";

    system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $url) == 0
        or die "Failed to install cert-manager\n";

    # Wait for cert-manager to be ready
    print "      Waiting for cert-manager to be ready...\n";
    system("kubectl", "--kubeconfig=$kc_path", "wait", "--for=condition=Available",
           "--timeout=300s", "deployment/cert-manager", "-n", "cert-manager") == 0
        or die "cert-manager deployment not ready\n";

    # Create ClusterIssuers
    $self->_create_cert_issuers($config, $kc_path);
}

sub _create_cert_issuers {
    my ($self, $config, $kc_path) = @_;

    my $email = $config->ssl_email;

    # Wait a bit for webhook to be fully ready (timing issue)
    print "      Waiting for cert-manager webhook to stabilize...\n";
    sleep 5;

    # Create self-signed issuer (always, for internal certs)
    my $selfsigned_issuer = <<'YAML';
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
YAML

    my $fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $fh $selfsigned_issuer;
    close $fh;

    # Retry up to 3 times (webhook might not be ready immediately)
    my $retries = 3;
    my $success = 0;
    for my $attempt (1..$retries) {
        if (system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $fh->filename) == 0) {
            $success = 1;
            last;
        }
        if ($attempt < $retries) {
            print "      Webhook not ready, retrying in 5s...\n";
            sleep 5;
        }
    }
    warn "Failed to create selfsigned-issuer after $retries attempts\n" unless $success;

    # If email provided, create Let's Encrypt issuers
    if ($email) {
        print "      Creating Let's Encrypt issuers (email: $email)...\n";

        # Production issuer
        my $le_prod = <<"YAML";
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: $email
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        gatewayHTTPRoute:
          parentRefs:
          - name: cilium-gateway
            namespace: kube-system
YAML

        # Staging issuer
        my $le_staging = <<"YAML";
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: $email
    privateKeySecretRef:
      name: letsencrypt-staging
    solvers:
    - http01:
        gatewayHTTPRoute:
          parentRefs:
          - name: cilium-gateway
            namespace: kube-system
YAML

        my $prod_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
        print $prod_fh $le_prod;
        close $prod_fh;

        my $staging_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
        print $staging_fh $le_staging;
        close $staging_fh;

        system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $prod_fh->filename) == 0
            or warn "Failed to create letsencrypt-prod issuer\n";
        system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $staging_fh->filename) == 0
            or warn "Failed to create letsencrypt-staging issuer\n";

        print "      ClusterIssuers created: selfsigned-issuer, letsencrypt-prod, letsencrypt-staging\n";
    } else {
        print "      ClusterIssuer created: selfsigned-issuer\n";
        print "      (Add 'ssl: { email: your\@email.com }' to ocp.yaml for Let's Encrypt)\n";
    }
}

sub _setup_cilium_gateway {
    my ($self, $config, $kubeconfig) = @_;

    die "No kubeconfig available\n" unless $kubeconfig;

    # Write kubeconfig to temp file
    require File::Temp;
    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $kc_fh $kubeconfig;
    close $kc_fh;
    my $kc_path = $kc_fh->filename;

    # Gateway API CRDs are already installed by Rexfile (before Cilium)

    # Create Cilium Gateway
    print "      Creating Cilium Gateway...\n";
    my $gateway = <<'YAML';
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: cilium-gateway
  namespace: kube-system
spec:
  gatewayClassName: cilium
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
  - name: https
    port: 443
    protocol: HTTPS
    allowedRoutes:
      namespaces:
        from: All
    tls:
      mode: Terminate
      certificateRefs:
      - kind: Secret
        name: default-gateway-cert
        namespace: kube-system
YAML

    my $gw_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $gw_fh $gateway;
    close $gw_fh;

    system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $gw_fh->filename) == 0
        or die "Failed to create Cilium Gateway\n";

    # Wait for Gateway to be ready
    print "      Waiting for Gateway to be ready...\n";
    for my $i (1..30) {
        my $status = `kubectl --kubeconfig=$kc_path get gateway cilium-gateway -n kube-system -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}' 2>/dev/null`;
        if ($status eq 'True') {
            print "      Gateway is ready!\n";
            return;
        }
        sleep 2;
    }
    warn "Gateway may not be fully ready yet\n";
}

sub _setup_lb_ipam {
    my ($self, $node_ip, $kubeconfig) = @_;

    die "No kubeconfig available\n" unless $kubeconfig;

    # Resolve hostname to IP if needed
    require Socket;
    if ($node_ip !~ /^\d+\.\d+\.\d+\.\d+$/) {
        my $packed = Socket::inet_aton($node_ip);
        die "Cannot resolve $node_ip\n" unless $packed;
        $node_ip = Socket::inet_ntoa($packed);
        print "      Resolved to $node_ip\n";
    }

    require File::Temp;
    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $kc_fh $kubeconfig;
    close $kc_fh;
    my $kc_path = $kc_fh->filename;

    my $manifest = <<"YAML";
apiVersion: "cilium.io/v2alpha1"
kind: CiliumLoadBalancerIPPool
metadata:
  name: default-pool
spec:
  blocks:
  - cidr: "$node_ip/32"
---
apiVersion: "cilium.io/v2alpha1"
kind: CiliumL2AnnouncementPolicy
metadata:
  name: default-l2
spec:
  interfaces:
  - ^eth[0-9]+
  - ^en[a-z0-9]+
  externalIPs: true
  loadBalancerIPs: true
YAML

    my $fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $fh $manifest;
    close $fh;

    system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $fh->filename) == 0
        or die "Failed to create LB-IPAM resources\n";

    # Verify Gateway got an IP
    sleep 2;
    my $gw_ip = `kubectl --kubeconfig=$kc_path get gateway cilium-gateway -n kube-system -o jsonpath='{.status.addresses[0].value}' 2>/dev/null`;
    if ($gw_ip) {
        print "      Gateway external IP: $gw_ip\n";
    }
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

=cut
