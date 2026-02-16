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
        print "     Checking components...\n\n";
        $self->_reconcile_components($config);
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
        gpu          => $config->gpu,
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

    # Wait for node to be Ready (Cilium CNI must be running)
    # Nothing can be scheduled until the node is Ready!
    print "  [..] Waiting for node to be Ready (Cilium CNI)...\n";
    {
        require File::Temp;
        my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
        print $kc_fh $result->{kubeconfig};
        close $kc_fh;
        my $kc_path = $kc_fh->filename;

        # Quick connectivity check first
        my $api_check = `kubectl --kubeconfig=$kc_path cluster-info 2>&1`;
        chomp $api_check;
        if ($api_check =~ /running|is running/) {
            print "      API server reachable\n";
        } else {
            print "      WARNING: API server may not be reachable:\n";
            print "      $api_check\n";
        }

        my $node_ready = 0;
        for my $i (1..60) {
            my $output = `kubectl --kubeconfig=$kc_path get nodes 2>&1`;
            my $status = `kubectl --kubeconfig=$kc_path get nodes -o jsonpath='{.items[0].status.conditions[?(\@.type=="Ready")].status}' 2>/dev/null`;
            chomp $status;
            # Also check via simple grep as fallback
            my $is_ready = ($status eq 'True') || ($output =~ /\bReady\b/ && $output !~ /NotReady/);
            if ($is_ready) {
                print "  [ok] Node is Ready after ~${\ ($i * 10)}s\n";
                $node_ready = 1;
                last;
            }
            if ($i == 1 || $i % 6 == 0) {
                print "      ... waiting (${i}/60) status='$status'\n";
                chomp $output;
                print "      $output\n" if $output;
            }
            sleep 10;
        }
        unless ($node_ready) {
            # Last resort: check via SSH directly on the node
            print "  [WARN] Node not Ready after 600s via kubectl, checking via SSH...\n";
            my $ssh_check = $ssh->run("/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes 2>&1");
            my $ssh_output = $ssh_check->{stdout} || '';
            print "      SSH node status: $ssh_output\n";
            if ($ssh_output =~ /\bReady\b/ && $ssh_output !~ /NotReady/) {
                print "  [ok] Node is Ready (confirmed via SSH)\n";
                $node_ready = 1;
            } else {
                # Also check Cilium status via SSH
                my $cilium_check = $ssh->run("cilium status --kubeconfig /etc/rancher/rke2/rke2.yaml 2>&1");
                print "      Cilium status: " . ($cilium_check->{stdout} || 'unknown') . "\n";
                print "  [WARN] Node genuinely not Ready, continuing anyway...\n";
            }
        }
    }

    # Deploy registry (pull-through cache + local) FIRST after node Ready
    # This way all subsequent image pulls (cert-manager, etc.) go through cache
    unless ($config->no_registry) {
        print "  [..] Setting up OCP registry (pull-through cache + local)...\n";
        eval {
            $self->_setup_registry($result->{kubeconfig}, $config);
        };
        if ($@) {
            print "  [WARN] Registry setup failed: $@\n";
        } else {
            print "  [ok] OCP registry ready\n";
        }
    }

    # Deploy GPU support (RuntimeClass + Device Plugin) if node has NVIDIA
    print "  [..] Checking GPU support...\n";
    eval {
        $self->_setup_gpu_support($result->{kubeconfig}, $config);
    };
    if ($@) {
        print "  [WARN] GPU setup failed: $@\n";
    }

    # Apply cert-manager manifests AFTER node is Ready (pods can be scheduled now)
    my $cert_manager_applied = 0;
    unless ($config->no_cert) {
        print "  [..] Applying cert-manager manifests...\n";
        eval {
            $self->_apply_cert_manager($result->{kubeconfig});
            $cert_manager_applied = 1;
            $self->_save_deployed_hash($config, 'certmanager', 'v1.14.0');
        };
        if ($@) {
            print "  [WARN] cert-manager apply failed: $@\n";
        } else {
            print "  [ok] cert-manager applied (starting in background)\n";
        }
    }

    # Setup Cilium Gateway API (while cert-manager starts up)
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

    # Now wait for cert-manager and create issuers (had time to start during Gateway + LB-IPAM setup)
    if ($cert_manager_applied) {
        print "  [..] Waiting for cert-manager to be ready...\n";
        eval {
            $self->_wait_cert_manager_and_create_issuers($config, $result->{kubeconfig});
        };
        if ($@) {
            print "  [WARN] cert-manager setup failed: $@\n";
        } else {
            print "  [ok] cert-manager ready\n";
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

sub _apply_cert_manager {
    my ($self, $kubeconfig) = @_;

    die "No kubeconfig available\n" unless $kubeconfig;

    require File::Temp;
    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $kc_fh $kubeconfig;
    close $kc_fh;
    my $kc_path = $kc_fh->filename;

    my $version = 'v1.14.0';
    my $url = "https://github.com/cert-manager/cert-manager/releases/download/$version/cert-manager.yaml";

    system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $url) == 0
        or die "Failed to apply cert-manager manifests\n";
}

sub _wait_cert_manager_and_create_issuers {
    my ($self, $config, $kubeconfig) = @_;

    die "No kubeconfig available\n" unless $kubeconfig;

    require File::Temp;
    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $kc_fh $kubeconfig;
    close $kc_fh;
    my $kc_path = $kc_fh->filename;

    system("kubectl", "--kubeconfig=$kc_path", "wait", "--for=condition=Available",
           "--timeout=600s", "deployment/cert-manager", "-n", "cert-manager") == 0
        or die "cert-manager deployment not ready\n";

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
    }

    require File::Temp;
    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $kc_fh $kubeconfig;
    close $kc_fh;
    my $kc_path = $kc_fh->filename;

    # If IP is localhost/loopback, get the real node IP from Kubernetes
    if ($node_ip =~ /^127\./) {
        my $real_ip = `kubectl --kubeconfig=$kc_path get nodes -o jsonpath='{.items[0].status.addresses[?\@.type=="InternalIP"].address}' 2>/dev/null`;
        chomp $real_ip;
        if ($real_ip && $real_ip !~ /^127\./) {
            print "      Using node IP $real_ip (instead of $node_ip)\n";
            $node_ip = $real_ip;
        } else {
            print "      WARNING: Only loopback IP available, LB-IPAM may not work externally\n";
        }
    }
    print "      LB-IPAM pool: $node_ip/32\n";

    # Wait for Cilium operator to register LB-IPAM CRDs
    print "      Waiting for CiliumLoadBalancerIPPool CRD...\n";
    my $crd_ready = 0;
    for my $i (1..30) {
        my $check = `kubectl --kubeconfig=$kc_path get crd ciliumloadbalancerippools.cilium.io 2>/dev/null`;
        if ($check =~ /ciliumloadbalancerippools/) {
            $crd_ready = 1;
            last;
        }
        print "      ... waiting for Cilium operator (${i}/30)\n" if $i % 5 == 0;
        sleep 10;
    }
    die "CiliumLoadBalancerIPPool CRD not available after 300s\n" unless $crd_ready;

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

#
# Registry (Pull-Through Cache + Local)
#

sub _setup_registry {
    my ($self, $kubeconfig, $config) = @_;

    die "No kubeconfig available\n" unless $kubeconfig;

    my $manifest = $self->_generate_registry_manifest;

    # Check if already deployed with same manifest
    require Digest::MD5;
    my $hash = Digest::MD5::md5_hex($manifest);
    my $deployed = $self->_load_deployed_hashes($config);

    if (($deployed->{registry} // '') eq $hash) {
        print "      Registry already deployed (up to date)\n";
        return;
    }

    # Apply manifest
    require File::Temp;
    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $kc_fh $kubeconfig;
    close $kc_fh;
    my $kc_path = $kc_fh->filename;

    my $manifest_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $manifest_fh $manifest;
    close $manifest_fh;

    system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $manifest_fh->filename) == 0
        or die "Failed to apply registry manifests\n";

    # Wait for pods to be ready
    print "      Waiting for ocp-cache...\n";
    system("kubectl", "--kubeconfig=$kc_path", "wait", "--for=condition=available",
           "--timeout=120s", "deployment/ocp-cache", "-n", "ocp-system") == 0
        or warn "ocp-cache not ready within 120s\n";

    print "      Waiting for ocp-registry...\n";
    system("kubectl", "--kubeconfig=$kc_path", "wait", "--for=condition=available",
           "--timeout=120s", "deployment/ocp-registry", "-n", "ocp-system") == 0
        or warn "ocp-registry not ready within 120s\n";

    # Save hash so we skip next time if unchanged
    $self->_save_deployed_hash($config, 'registry', $hash);
}

sub _generate_registry_manifest {
    return <<'YAML';
---
apiVersion: v1
kind: Namespace
metadata:
  name: ocp-system
---
# Pull-through cache for docker.io
apiVersion: v1
kind: ConfigMap
metadata:
  name: ocp-cache-config
  namespace: ocp-system
data:
  config.yml: |
    version: 0.1
    proxy:
      remoteurl: https://registry-1.docker.io
    storage:
      filesystem:
        rootdirectory: /var/lib/registry
      delete:
        enabled: true
    http:
      addr: :5000
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ocp-cache
  namespace: ocp-system
  labels:
    app: ocp-cache
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ocp-cache
  template:
    metadata:
      labels:
        app: ocp-cache
    spec:
      containers:
      - name: registry
        image: registry:2
        ports:
        - containerPort: 5000
          name: http
        volumeMounts:
        - name: config
          mountPath: /etc/docker/registry
        - name: data
          mountPath: /var/lib/registry
        resources:
          requests:
            memory: "32Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
      volumes:
      - name: config
        configMap:
          name: ocp-cache-config
      - name: data
        hostPath:
          path: /var/lib/ocp/cache
          type: DirectoryOrCreate
---
apiVersion: v1
kind: Service
metadata:
  name: ocp-cache
  namespace: ocp-system
spec:
  type: NodePort
  selector:
    app: ocp-cache
  ports:
  - port: 5000
    targetPort: 5000
    nodePort: 30500
    protocol: TCP
    name: http
---
# Local registry for user images
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ocp-registry
  namespace: ocp-system
  labels:
    app: ocp-registry
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ocp-registry
  template:
    metadata:
      labels:
        app: ocp-registry
    spec:
      containers:
      - name: registry
        image: registry:2
        ports:
        - containerPort: 5000
          name: http
        env:
        - name: REGISTRY_STORAGE_DELETE_ENABLED
          value: "true"
        volumeMounts:
        - name: data
          mountPath: /var/lib/registry
        resources:
          requests:
            memory: "32Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
      volumes:
      - name: data
        hostPath:
          path: /var/lib/ocp/registry
          type: DirectoryOrCreate
---
apiVersion: v1
kind: Service
metadata:
  name: ocp-registry
  namespace: ocp-system
spec:
  type: NodePort
  selector:
    app: ocp-registry
  ports:
  - port: 5000
    targetPort: 5000
    nodePort: 30501
    protocol: TCP
    name: http
YAML
}

#
# GPU Support (RuntimeClass + NVIDIA Device Plugin)
#

sub _setup_gpu_support {
    my ($self, $kubeconfig, $config) = @_;

    die "No kubeconfig available\n" unless $kubeconfig;

    require File::Temp;
    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $kc_fh $kubeconfig;
    close $kc_fh;
    my $kc_path = $kc_fh->filename;

    # Check if node has nvidia.com/gpu capacity (device plugin already running)
    # or if nvidia runtime is configured in containerd
    my $has_gpu = `kubectl --kubeconfig=$kc_path get nodes -o jsonpath='{.items[0].status.capacity.nvidia\\.com/gpu}' 2>/dev/null`;
    my $has_runtime = `kubectl --kubeconfig=$kc_path get runtimeclass nvidia -o name 2>/dev/null`;

    # Also check: does the node have nvidia containerd runtime?
    # The Rexfile creates /etc/containerd/conf.d/99-nvidia.toml if GPU was detected.
    # We detect this by looking at node labels or just trying to deploy.
    # If no GPU, device plugin is harmless (reports 0 GPUs).

    my $manifest = $self->_generate_gpu_manifest;

    require Digest::MD5;
    my $hash = Digest::MD5::md5_hex($manifest);
    my $deployed = $self->_load_deployed_hashes($config);

    if (($deployed->{gpu} // '') eq $hash) {
        print "      GPU support already deployed (up to date)\n";
        return;
    }

    print "      Deploying NVIDIA RuntimeClass + Device Plugin...\n";

    my $manifest_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $manifest_fh $manifest;
    close $manifest_fh;

    system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $manifest_fh->filename) == 0
        or die "Failed to apply GPU manifests\n";

    # Wait for device plugin (short timeout, it's a DaemonSet)
    print "      Waiting for NVIDIA device plugin...\n";
    for my $i (1..12) {
        my $ready = `kubectl --kubeconfig=$kc_path get ds -n kube-system nvidia-device-plugin-daemonset -o jsonpath='{.status.numberReady}' 2>/dev/null`;
        chomp $ready;
        if ($ready && $ready > 0) {
            # Check if GPU is now visible
            sleep 5;  # Give kubelet time to update capacity
            my $gpu_count = `kubectl --kubeconfig=$kc_path get nodes -o jsonpath='{.items[0].status.capacity.nvidia\\.com/gpu}' 2>/dev/null`;
            chomp $gpu_count;
            if ($gpu_count && $gpu_count > 0) {
                print "  [ok] GPU support ready ($gpu_count GPU(s) available)\n";
            } else {
                print "  [ok] Device plugin running (GPU may not be present on this node)\n";
            }
            last;
        }
        sleep 10;
    }

    $self->_save_deployed_hash($config, 'gpu', $hash);
}

sub _generate_gpu_manifest {
    return <<'YAML';
---
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: nvidia
handler: nvidia
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nvidia-device-plugin-daemonset
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: nvidia-device-plugin-daemonset
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      labels:
        app: nvidia-device-plugin-daemonset
    spec:
      runtimeClassName: nvidia
      tolerations:
      - key: nvidia.com/gpu
        operator: Exists
        effect: NoSchedule
      priorityClassName: system-node-critical
      containers:
      - name: nvidia-device-plugin-ctr
        image: nvcr.io/nvidia/k8s-device-plugin:v0.17.0
        env:
        - name: FAIL_ON_INIT_ERROR
          value: "false"
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
        volumeMounts:
        - name: device-plugin
          mountPath: /var/lib/kubelet/device-plugins
      volumes:
      - name: device-plugin
        hostPath:
          path: /var/lib/kubelet/device-plugins
YAML
}

#
# Deploy hash tracking (.ocp/deployed.yaml)
#

sub _deployed_hashes_path {
    my ($self, $config) = @_;
    return $config->project_dir->child('.ocp', 'deployed.yaml');
}

sub _load_deployed_hashes {
    my ($self, $config) = @_;
    my $path = $self->_deployed_hashes_path($config);
    return {} unless -f $path;
    require YAML::XS;
    return YAML::XS::LoadFile($path->stringify) || {};
}

sub _save_deployed_hash {
    my ($self, $config, $component, $hash) = @_;
    my $hashes = $self->_load_deployed_hashes($config);
    $hashes->{$component} = $hash;
    my $path = $self->_deployed_hashes_path($config);
    $path->parent->mkpath unless -d $path->parent;
    require YAML::XS;
    YAML::XS::DumpFile($path->stringify, $hashes);
}

#
# Reconciliation for existing clusters
#

sub _reconcile_components {
    my ($self, $config) = @_;

    # Read kubeconfig from .kube/config
    my $kube_config_path = $config->project_dir->child('.kube', 'config');
    unless (-f $kube_config_path) {
        print "  No .kube/config found, cannot reconcile components.\n";
        print "  Run 'ocp kubeconfig' first.\n";
        return;
    }
    my $kubeconfig = path($kube_config_path)->slurp;

    my $updated = 0;
    my $checked = 0;

    # Registry
    unless ($config->no_registry) {
        $checked++;
        print "  [..] Checking registry...\n";
        eval {
            my $deployed = $self->_load_deployed_hashes($config);
            my $manifest = $self->_generate_registry_manifest;
            require Digest::MD5;
            my $current_hash = Digest::MD5::md5_hex($manifest);
            my $was_missing = !exists $deployed->{registry};
            my $was_different = ($deployed->{registry} // '') ne $current_hash;

            $self->_setup_registry($kubeconfig, $config);

            if ($was_missing) {
                print "  [ok] Registry deployed (was missing)\n";
                $updated++;
            } elsif ($was_different) {
                print "  [ok] Registry updated (manifest changed)\n";
                $updated++;
            } else {
                print "  [ok] Registry up to date\n";
            }
        };
        if ($@) {
            print "  [WARN] Registry setup failed: $@\n";
        }
    }

    # GPU support
    {
        $checked++;
        print "  [..] Checking GPU support...\n";
        eval {
            my $deployed = $self->_load_deployed_hashes($config);
            my $manifest = $self->_generate_gpu_manifest;
            require Digest::MD5;
            my $current_hash = Digest::MD5::md5_hex($manifest);
            my $was_missing = !exists $deployed->{gpu};
            my $was_different = ($deployed->{gpu} // '') ne $current_hash;

            $self->_setup_gpu_support($kubeconfig, $config);

            if ($was_missing) {
                print "  [ok] GPU support deployed (was missing)\n";
                $updated++;
            } elsif ($was_different) {
                print "  [ok] GPU support updated (manifest changed)\n";
                $updated++;
            } else {
                print "  [ok] GPU support up to date\n";
            }
        };
        if ($@) {
            print "  [WARN] GPU setup failed: $@\n";
        }
    }

    # cert-manager
    unless ($config->no_cert) {
        $checked++;
        my $deployed = $self->_load_deployed_hashes($config);
        if ($deployed->{certmanager}) {
            print "  [ok] cert-manager already deployed\n";
        } else {
            print "  [..] cert-manager not tracked yet, skipping (deploy with fresh 'ocp apply')\n";
        }
    }

    # Summary
    print "\n";
    if ($updated) {
        print "  $updated component(s) updated, $checked checked.\n";
    } else {
        print "  All $checked component(s) up to date.\n";
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
