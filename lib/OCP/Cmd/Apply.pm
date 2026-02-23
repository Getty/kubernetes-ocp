package OCP::Cmd::Apply;
# ABSTRACT: Reconcile cluster to match config

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);
use JSON::PP ();
use FindBin;

use OCP::Config;
use OCP::Secrets;
use OCP::SSH;
use OCP::Rex;
use OCP::Versions;
use WWW::Hetzner::Cloud;

with 'OCP::Role::Cmd';

our $VERSION = '0.1.0';

has _ssh_key_path => (is => 'rw');

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

    # Get control plane spec (now an ArrayRef)
    my $cps = $config->control_planes;
    my $first_cp = $cps->[0] // {};
    my $provider = $first_cp->{provider} // 'hetzner';
    my $num_control_planes = scalar @$cps;

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
            server_type => $first_cp->{serverType} // 'cx32',
            image       => $first_cp->{image} // 'debian-13',
            location    => $first_cp->{location} // 'fsn1',
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
        $cp_host = $first_cp->{host} or die "SSH provider requires 'host' in controlPlanes spec\n";
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

    $self->_ssh_key_path($ssh_key_path);

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
        distribution      => $distribution,
        version           => $version,
        node_name         => $cp_name,
        registry_cache    => $config->registry_cache,
        registry_upstream => $config->registry_upstream,
        registry_name     => $config->registry_name,
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
    # Registry is always deployed — required infrastructure for robocop image delivery
    print "  [..] Setting up OCP registry (pull-through cache + local)...\n";
    eval {
        $self->_setup_registry($result->{kubeconfig}, $config);
    };
    if ($@) {
        print "  [WARN] Registry setup failed: $@\n";
    } else {
        print "  [ok] OCP registry ready\n";
    }

    # Deploy NFD (Node Feature Discovery) — always, detects hardware automatically
    print "  [..] Setting up Node Feature Discovery (NFD)...\n";
    eval {
        $self->_setup_nfd($result->{kubeconfig}, $config);
    };
    if ($@) {
        print "  [WARN] NFD setup failed: $@\n";
    } else {
        print "  [ok] NFD ready\n";
    }

    # Deploy GPU Operator if NFD detects NVIDIA GPU (pci-10de label)
    print "  [..] Checking GPU Operator...\n";
    eval {
        $self->_setup_gpu_operator($result->{kubeconfig}, $config);
    };
    if ($@) {
        print "  [WARN] GPU Operator setup failed: $@\n";
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

    # Build issuer resources
    my @issuers = (_selfsigned_issuer());

    if ($email) {
        print "      Creating Let's Encrypt issuers (email: $email)...\n";
        push @issuers, _acme_issuer('letsencrypt-prod',
            'https://acme-v02.api.letsencrypt.org/directory', $email);
        push @issuers, _acme_issuer('letsencrypt-staging',
            'https://acme-staging-v02.api.letsencrypt.org/directory', $email);
    }

    # Apply each issuer (retry for webhook readiness)
    for my $issuer (@issuers) {
        my $name = $issuer->{metadata}{name};
        my $yaml = $self->ocp->dump($issuer);

        my $fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
        print $fh $yaml;
        close $fh;

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
        warn "Failed to create $name after $retries attempts\n" unless $success;
    }

    my $names = join(', ', map { $_->{metadata}{name} } @issuers);
    print "      ClusterIssuers created: $names\n";

    unless ($email) {
        print "      (Add 'ssl: { email: your\@email.com }' to ocp.yaml for Let's Encrypt)\n";
    }
}

sub _selfsigned_issuer {
    return {
        apiVersion => 'cert-manager.io/v1',
        kind       => 'ClusterIssuer',
        metadata   => { name => 'selfsigned-issuer' },
        spec       => { selfSigned => {} },
    };
}

sub _acme_issuer {
    my ($name, $server, $email) = @_;
    return {
        apiVersion => 'cert-manager.io/v1',
        kind       => 'ClusterIssuer',
        metadata   => { name => $name },
        spec       => {
            acme => {
                server             => $server,
                email              => $email,
                privateKeySecretRef => { name => $name },
                solvers            => [{
                    http01 => {
                        gatewayHTTPRoute => {
                            parentRefs => [{
                                name      => 'cilium-gateway',
                                namespace => 'kube-system',
                            }],
                        },
                    },
                }],
            },
        },
    };
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

    my $gateway = {
        apiVersion => 'gateway.networking.k8s.io/v1',
        kind       => 'Gateway',
        metadata   => { name => 'cilium-gateway', namespace => 'kube-system' },
        spec       => {
            gatewayClassName => 'cilium',
            listeners        => [
                {
                    name     => 'http',
                    port     => 80,
                    protocol => 'HTTP',
                    allowedRoutes => { namespaces => { from => 'All' } },
                },
                {
                    name     => 'https',
                    port     => 443,
                    protocol => 'HTTPS',
                    allowedRoutes => { namespaces => { from => 'All' } },
                    tls => {
                        mode            => 'Terminate',
                        certificateRefs => [{
                            kind      => 'Secret',
                            name      => 'default-gateway-cert',
                            namespace => 'kube-system',
                        }],
                    },
                },
            ],
        },
    };

    my $gw_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $gw_fh $self->ocp->dump($gateway);
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

    my @resources = (
        {
            apiVersion => 'cilium.io/v2alpha1',
            kind       => 'CiliumLoadBalancerIPPool',
            metadata   => { name => 'default-pool' },
            spec       => { blocks => [{ cidr => "$node_ip/32" }] },
        },
        {
            apiVersion => 'cilium.io/v2alpha1',
            kind       => 'CiliumL2AnnouncementPolicy',
            metadata   => { name => 'default-l2' },
            spec       => {
                interfaces      => ['^eth[0-9]+', '^en[a-z0-9]+'],
                externalIPs     => JSON::PP::true,
                loadBalancerIPs => JSON::PP::true,
            },
        },
    );

    my $manifest = $self->ocp->dump(@resources);

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

    my $manifest = $self->_generate_registry_manifest($config);

    # Check if already deployed with same manifest
    require Digest::MD5;
    my $hash = Digest::MD5::md5_hex($manifest);
    my $deployed = $self->_load_deployed_hashes($config);

    if (($deployed->{registry} // '') eq $hash) {
        print "      Registry already deployed (up to date)\n";
        return;
    }

    # Log registry mode
    if ($config->has_external_cache) {
        print "      docker.io cache: ", $config->registry_cache, " (external)\n";
    } else {
        print "      docker.io cache: ocp-cache (built-in)\n";
    }
    if ($config->has_external_upstream) {
        print "      ", $config->registry_name, ": ", $config->registry_upstream, " (external)\n";
    } else {
        print "      ", $config->registry_name, ": ocp-registry (built-in)\n";
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

    # Wait for deployed components
    unless ($config->has_external_cache) {
        print "      Waiting for ocp-cache...\n";
        system("kubectl", "--kubeconfig=$kc_path", "wait", "--for=condition=available",
               "--timeout=120s", "deployment/ocp-cache", "-n", "ocp-system") == 0
            or warn "ocp-cache not ready within 120s\n";
    }

    unless ($config->has_external_upstream) {
        print "      Waiting for ocp-registry...\n";
        system("kubectl", "--kubeconfig=$kc_path", "wait", "--for=condition=available",
               "--timeout=120s", "deployment/ocp-registry", "-n", "ocp-system") == 0
            or warn "ocp-registry not ready within 120s\n";
    }

    # Save hash so we skip next time if unchanged
    $self->_save_deployed_hash($config, 'registry', $hash);
}

sub _generate_registry_manifest {
    my ($self, $config) = @_;

    my $has_external_cache    = $config && $config->has_external_cache;
    my $has_external_upstream = $config && $config->has_external_upstream;

    my @resources;

    # Namespace (always)
    push @resources, {
        apiVersion => 'v1',
        kind       => 'Namespace',
        metadata   => { name => 'ocp-system' },
    };

    # ocp-cache: pull-through cache for docker.io (unless external cache)
    unless ($has_external_cache) {
        my $cache_config_yml = $self->ocp->dump({
            version => '0.1',
            proxy   => { remoteurl => 'https://registry-1.docker.io' },
            storage => {
                filesystem => { rootdirectory => '/var/lib/registry' },
                delete     => { enabled => JSON::PP::true },
            },
            http => { addr => ':5000' },
        });

        push @resources, {
            apiVersion => 'v1',
            kind       => 'ConfigMap',
            metadata   => { name => 'ocp-cache-config', namespace => 'ocp-system' },
            data       => { 'config.yml' => $cache_config_yml },
        };

        push @resources, _registry_deployment('ocp-cache', {
            config_map => 'ocp-cache-config',
            host_path  => '/var/lib/ocp/cache',
        });

        push @resources, _nodeport_service('ocp-cache', 30500);
    }

    # ocp-registry: local registry (unless external upstream)
    unless ($has_external_upstream) {
        push @resources, _registry_deployment('ocp-registry', {
            host_path => '/var/lib/ocp/registry',
            env       => [{ name => 'REGISTRY_STORAGE_DELETE_ENABLED', value => 'true' }],
        });

        push @resources, _nodeport_service('ocp-registry', 30501);
    }

    return $self->ocp->dump(@resources);
}

sub _registry_deployment {
    my ($name, $opts) = @_;

    my @volume_mounts;
    my @volumes;

    if ($opts->{config_map}) {
        push @volume_mounts, { name => 'config', mountPath => '/etc/docker/registry' };
        push @volumes, { name => 'config', configMap => { name => $opts->{config_map} } };
    }

    push @volume_mounts, { name => 'data', mountPath => '/var/lib/registry' };
    push @volumes, {
        name     => 'data',
        hostPath => { path => $opts->{host_path}, type => 'DirectoryOrCreate' },
    };

    my $container = {
        name         => 'registry',
        image        => 'registry:2',
        ports        => [{ containerPort => 5000, name => 'http' }],
        volumeMounts => \@volume_mounts,
        resources    => {
            requests => { memory => '64Mi', cpu => '50m' },
            limits   => { memory => '512Mi' },
        },
    };

    $container->{env} = $opts->{env} if $opts->{env};

    return {
        apiVersion => 'apps/v1',
        kind       => 'Deployment',
        metadata   => { name => $name, namespace => 'ocp-system', labels => { app => $name } },
        spec       => {
            replicas => 1,
            selector => { matchLabels => { app => $name } },
            template => {
                metadata => { labels => { app => $name } },
                spec     => { containers => [$container], volumes => \@volumes },
            },
        },
    };
}

sub _nodeport_service {
    my ($name, $node_port) = @_;
    return {
        apiVersion => 'v1',
        kind       => 'Service',
        metadata   => { name => $name, namespace => 'ocp-system' },
        spec       => {
            type     => 'NodePort',
            selector => { app => $name },
            ports    => [{
                port       => 5000,
                targetPort => 5000,
                nodePort   => $node_port,
                protocol   => 'TCP',
                name       => 'http',
            }],
        },
    };
}

#
# NFD (Node Feature Discovery)
#

sub _setup_nfd {
    my ($self, $kubeconfig, $config) = @_;

    die "No kubeconfig available\n" unless $kubeconfig;

    # Ensure NFD image is built and pushed to ocp-registry
    # (required because released NFD versions crash on K8s 1.34+)
    $self->_ensure_nfd_image($config);

    # Apply CRDs first (before any NFD components)
    my $share_dir = $self->_find_share_dir;
    my $crd_file = $share_dir->child('nfd', 'crds', 'nodefeature-crd.yaml');
    die "NFD CRD file not found: $crd_file\n" unless -f $crd_file;

    my $manifest = $self->_generate_nfd_manifest;

    require Digest::MD5;
    my $hash = Digest::MD5::md5_hex($manifest . path($crd_file)->slurp);
    my $deployed = $self->_load_deployed_hashes($config);

    require File::Temp;
    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $kc_fh $kubeconfig;
    close $kc_fh;

    # Check if NFD is actually running (not just hash match)
    my $ns_exists = system("kubectl", "--kubeconfig=".$kc_fh->filename,
        "get", "ns", "node-feature-discovery", "-o", "name") == 0;
    my $nfd_running = $ns_exists && system("kubectl", "--kubeconfig=".$kc_fh->filename,
        "get", "deployment", "nfd-master", "-n", "node-feature-discovery", "-o", "name") == 0;

    if (($deployed->{nfd} // '') eq $hash && $nfd_running) {
        print "      NFD already deployed (up to date)\n";
        return;
    }
    my $kc_path = $kc_fh->filename;

    # Apply CRDs
    print "      Applying NFD CRDs...\n";
    system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $crd_file->stringify) == 0
        or die "Failed to apply NFD CRDs\n";

    # Apply NFD components
    print "      Deploying NFD master + worker...\n";
    my $manifest_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $manifest_fh $manifest;
    close $manifest_fh;

    system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $manifest_fh->filename) == 0
        or die "Failed to apply NFD manifests\n";

    # Wait for nfd-master
    print "      Waiting for nfd-master...\n";
    system("kubectl", "--kubeconfig=$kc_path", "wait", "--for=condition=available",
           "--timeout=120s", "deployment/nfd-master", "-n", "node-feature-discovery") == 0
        or warn "nfd-master not ready within 120s\n";

    # Wait for nfd-worker DaemonSet
    print "      Waiting for nfd-worker...\n";
    for my $i (1..12) {
        my $ready = `kubectl --kubeconfig=$kc_path get ds -n node-feature-discovery nfd-worker -o jsonpath='{.status.numberReady}' 2>/dev/null`;
        chomp $ready;
        if ($ready && $ready > 0) {
            print "      NFD worker running on $ready node(s)\n";
            last;
        }
        sleep 10;
    }

    # Wait for NFD to label nodes (needs a few seconds after worker starts)
    print "      Waiting for NFD labels...\n";
    for my $i (1..12) {
        my $labels = `kubectl --kubeconfig=$kc_path get nodes -o jsonpath='{.items[0].metadata.labels}' 2>/dev/null`;
        if ($labels =~ /feature\.node\.kubernetes\.io/) {
            print "      NFD labels detected on nodes\n";
            last;
        }
        if ($i == 12) {
            warn "NFD labels not detected after 120s\n";
        }
        sleep 10;
    }

    $self->_save_deployed_hash($config, 'nfd', $hash);
}

sub _ensure_nfd_image {
    my ($self, $config) = @_;

    # Get control plane host for SSH access
    my $cps = $config->control_planes;
    my $first_cp = $cps->[0] // {};
    my $cp_host = $first_cp->{host}
        // do {
            my $nodes = $config->nodes_status;
            my ($cp) = grep { ($_->{role} // '') eq 'control-plane' } @$nodes;
            $cp ? $cp->{publicIp} : undef;
        };

    die "Cannot determine control plane host for NFD image build\n" unless $cp_host;

    # SSH options with admin key
    my $key = $self->_ssh_key_path;
    my @ssh_opts = ("-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5");
    push @ssh_opts, "-i", $key if $key;
    my $ssh_cmd = "ssh " . join(' ', map { quotemeta($_) } @ssh_opts) . " root\@$cp_host";

    # Verify SSH connectivity
    system("ssh", @ssh_opts, "root\@$cp_host", "true") == 0
        or die "Cannot SSH to control plane at $cp_host\n";

    # Verify ocp-registry is accessible (internally via SSH)
    my $registry_check = `$ssh_cmd "curl -sf http://localhost:30501/v2/ 2>&1"`;
    unless ($registry_check && $registry_check =~ /\{/) {
        die "ocp-registry not accessible on $cp_host:30501 — run 'ocp apply' to deploy it first\n";
    }

    # Check if NFD image already exists in ocp-registry
    my $tags_check = `$ssh_cmd "curl -sf http://localhost:30501/v2/nfd/tags/list" 2>/dev/null`;
    if ($tags_check && $tags_check =~ /"master"/) {
        print "      NFD image already in ocp-registry\n";
        return;
    }

    # Verify Docker is available locally (needed for build)
    system("docker", "info", "--format", "{{.ID}}") == 0
        or die "Docker not available locally — needed to build NFD image\n";

    print "      Building NFD from master (K8s 1.34+ compatibility)...\n";

    require File::Temp;
    my $build_dir = File::Temp->newdir(CLEANUP => 1);
    my $dir = $build_dir->dirname;

    # Clone NFD master branch (shallow)
    print "      Cloning NFD master...\n";
    system("git", "clone", "--depth=1", "--branch=master",
           "https://github.com/kubernetes-sigs/node-feature-discovery.git",
           $dir) == 0
        or die "Failed to clone NFD repository — check network connectivity\n";

    # Build the image locally (multi-stage, full target)
    print "      Building Docker image (this may take a few minutes)...\n";
    system("docker", "build", "--target=full", "-t", "nfd:master", $dir) == 0
        or die "Failed to build NFD Docker image\n";

    # Push to ocp-registry via SSH (entirely internal, no insecure-registry config needed):
    # 1. docker save | ssh ctr import — sends image to node's containerd
    # 2. ctr tag + ctr push --plain-http — pushes to ocp-registry at localhost:30501
    my $ctr = '/var/lib/rancher/rke2/bin/ctr --address /run/k3s/containerd/containerd.sock -n k8s.io';

    # Verify ctr is available on node
    system("ssh", @ssh_opts, "root\@$cp_host", "test -x /var/lib/rancher/rke2/bin/ctr") == 0
        or die "containerd CLI (ctr) not found on $cp_host — is RKE2 installed?\n";

    print "      Sending image to cluster node...\n";
    system("docker save nfd:master | $ssh_cmd '$ctr images import -'") == 0
        or die "Failed to import NFD image into node's containerd\n";

    print "      Pushing to ocp-registry (internal)...\n";
    system("ssh", @ssh_opts, "root\@$cp_host",
           "$ctr images tag docker.io/library/nfd:master localhost:30501/nfd:master 2>/dev/null;"
         . "$ctr images push --plain-http localhost:30501/nfd:master") == 0
        or die "Failed to push NFD image to ocp-registry\n";

    # Verify image is now in registry
    my $verify = `$ssh_cmd "curl -sf http://localhost:30501/v2/nfd/tags/list" 2>/dev/null`;
    unless ($verify && $verify =~ /"master"/) {
        die "NFD image push appeared to succeed but image not found in registry\n";
    }

    print "      NFD image available in ocp-registry\n";
}

sub _generate_nfd_manifest {
    my ($self) = @_;

    my $nfd_image = 'localhost:30501/nfd:master';

    my @resources = (
        # Namespace
        {
            apiVersion => 'v1',
            kind       => 'Namespace',
            metadata   => { name => 'node-feature-discovery' },
        },

        # ServiceAccount
        {
            apiVersion => 'v1',
            kind       => 'ServiceAccount',
            metadata   => {
                name      => 'nfd-master',
                namespace => 'node-feature-discovery',
            },
        },
        {
            apiVersion => 'v1',
            kind       => 'ServiceAccount',
            metadata   => {
                name      => 'nfd-worker',
                namespace => 'node-feature-discovery',
            },
        },

        # ClusterRole for nfd-master
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRole',
            metadata   => { name => 'nfd-master' },
            rules      => [
                {
                    apiGroups => [''],
                    resources => ['nodes', 'nodes/status'],
                    verbs     => ['get', 'list', 'watch', 'patch', 'update'],
                },
                {
                    apiGroups => ['nfd.k8s-sigs.io'],
                    resources => ['nodefeatures', 'nodefeaturerules'],
                    verbs     => ['get', 'list', 'watch'],
                },
                {
                    apiGroups => ['coordination.k8s.io'],
                    resources => ['leases'],
                    verbs     => ['create', 'delete', 'get', 'list', 'update', 'watch'],
                },
            ],
        },

        # ClusterRoleBinding for nfd-master
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRoleBinding',
            metadata   => { name => 'nfd-master' },
            roleRef    => {
                apiGroup => 'rbac.authorization.k8s.io',
                kind     => 'ClusterRole',
                name     => 'nfd-master',
            },
            subjects => [{
                kind      => 'ServiceAccount',
                name      => 'nfd-master',
                namespace => 'node-feature-discovery',
            }],
        },

        # ClusterRole for nfd-worker
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRole',
            metadata   => { name => 'nfd-worker' },
            rules      => [
                {
                    apiGroups => ['nfd.k8s-sigs.io'],
                    resources => ['nodefeatures'],
                    verbs     => ['create', 'get', 'update'],
                },
            ],
        },

        # ClusterRoleBinding for nfd-worker
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRoleBinding',
            metadata   => { name => 'nfd-worker' },
            roleRef    => {
                apiGroup => 'rbac.authorization.k8s.io',
                kind     => 'ClusterRole',
                name     => 'nfd-worker',
            },
            subjects => [{
                kind      => 'ServiceAccount',
                name      => 'nfd-worker',
                namespace => 'node-feature-discovery',
            }],
        },

        # nfd-master Deployment (Controller)
        {
            apiVersion => 'apps/v1',
            kind       => 'Deployment',
            metadata   => {
                name      => 'nfd-master',
                namespace => 'node-feature-discovery',
                labels    => { app => 'nfd-master' },
            },
            spec => {
                replicas => 1,
                selector => { matchLabels => { app => 'nfd-master' } },
                template => {
                    metadata => { labels => { app => 'nfd-master' } },
                    spec     => {
                        serviceAccountName => 'nfd-master',
                        tolerations        => [{
                            key      => 'node-role.kubernetes.io/master',
                            operator => 'Exists',
                            effect   => 'NoSchedule',
                        }, {
                            key      => 'node-role.kubernetes.io/control-plane',
                            operator => 'Exists',
                            effect   => 'NoSchedule',
                        }],
                        affinity => {
                            nodeAffinity => {
                                preferredDuringSchedulingIgnoredDuringExecution => [{
                                    weight     => 1,
                                    preference => {
                                        matchExpressions => [{
                                            key      => 'node-role.kubernetes.io/control-plane',
                                            operator => 'Exists',
                                        }],
                                    },
                                }],
                            },
                        },
                        containers => [{
                            name            => 'nfd-master',
                            image           => $nfd_image,
                            imagePullPolicy => 'IfNotPresent',
                            command         => ['nfd-master'],
                            ports           => [{ containerPort => 8080, name => 'grpc' }],
                            env             => [{ name => 'NODE_NAME', valueFrom => { fieldRef => { fieldPath => 'spec.nodeName' } } }],
                            securityContext => {
                                allowPrivilegeEscalation => JSON::PP::false,
                                capabilities             => { drop => ['ALL'] },
                                readOnlyRootFilesystem   => JSON::PP::true,
                                runAsNonRoot             => JSON::PP::true,
                            },
                            resources => {
                                requests => { cpu => '50m',  memory => '64Mi' },
                                limits   => { cpu => '200m', memory => '128Mi' },
                            },
                        }],
                    },
                },
            },
        },

        # nfd-worker DaemonSet
        {
            apiVersion => 'apps/v1',
            kind       => 'DaemonSet',
            metadata   => {
                name      => 'nfd-worker',
                namespace => 'node-feature-discovery',
                labels    => { app => 'nfd-worker' },
            },
            spec => {
                selector => { matchLabels => { app => 'nfd-worker' } },
                template => {
                    metadata => { labels => { app => 'nfd-worker' } },
                    spec     => {
                        serviceAccountName => 'nfd-worker',
                        dnsPolicy          => 'ClusterFirstWithHostNet',
                        tolerations        => [{
                            operator => 'Exists',
                            effect   => 'NoSchedule',
                        }],
                        containers => [{
                            name            => 'nfd-worker',
                            image           => $nfd_image,
                            imagePullPolicy => 'IfNotPresent',
                            command         => ['nfd-worker'],
                            env             => [{ name => 'NODE_NAME', valueFrom => { fieldRef => { fieldPath => 'spec.nodeName' } } }],
                            securityContext => {
                                allowPrivilegeEscalation => JSON::PP::false,
                                capabilities             => { drop => ['ALL'] },
                                readOnlyRootFilesystem   => JSON::PP::true,
                                runAsNonRoot             => JSON::PP::true,
                            },
                            resources => {
                                requests => { cpu => '50m',  memory => '64Mi' },
                                limits   => { cpu => '200m', memory => '128Mi' },
                            },
                            volumeMounts => [
                                { name => 'host-boot',     mountPath => '/host-boot',     readOnly => JSON::PP::true },
                                { name => 'host-os-release', mountPath => '/host-etc/os-release', readOnly => JSON::PP::true },
                                { name => 'host-sys',      mountPath => '/host-sys',      readOnly => JSON::PP::true },
                                { name => 'host-usr-lib',  mountPath => '/host-usr/lib',   readOnly => JSON::PP::true },
                                { name => 'host-lib',      mountPath => '/host-lib',       readOnly => JSON::PP::true },
                            ],
                        }],
                        volumes => [
                            { name => 'host-boot',       hostPath => { path => '/boot' } },
                            { name => 'host-os-release', hostPath => { path => '/etc/os-release' } },
                            { name => 'host-sys',        hostPath => { path => '/sys' } },
                            { name => 'host-usr-lib',    hostPath => { path => '/usr/lib' } },
                            { name => 'host-lib',        hostPath => { path => '/lib' } },
                        ],
                    },
                },
            },
        },

        # Service for nfd-master gRPC
        {
            apiVersion => 'v1',
            kind       => 'Service',
            metadata   => {
                name      => 'nfd-master',
                namespace => 'node-feature-discovery',
            },
            spec => {
                selector => { app => 'nfd-master' },
                ports    => [{ port => 8080, targetPort => 8080, protocol => 'TCP', name => 'grpc' }],
                type     => 'ClusterIP',
            },
        },
    );

    return $self->ocp->dump(@resources);
}

#
# GPU Operator (NVIDIA)
#

sub _setup_gpu_operator {
    my ($self, $kubeconfig, $config) = @_;

    die "No kubeconfig available\n" unless $kubeconfig;

    require File::Temp;
    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $kc_fh $kubeconfig;
    close $kc_fh;
    my $kc_path = $kc_fh->filename;

    # Check if any node has NVIDIA GPU via NFD labels
    my $gpu_nodes = `kubectl --kubeconfig=$kc_path get nodes -l feature.node.kubernetes.io/pci-10de.present=true -o name 2>/dev/null`;
    chomp $gpu_nodes;

    unless ($gpu_nodes) {
        print "      No GPU nodes detected (no NFD label feature.node.kubernetes.io/pci-10de.present)\n";
        print "  [ok] GPU Operator skipped (no GPU hardware)\n";
        return;
    }

    print "      GPU node(s) detected: ", join(', ', split(/\n/, $gpu_nodes)), "\n";

    # Apply CRDs first
    my $share_dir = $self->_find_share_dir;
    my $crd_file = $share_dir->child('gpu-operator', 'crds', 'clusterpolicy-crd.yaml');
    die "GPU Operator CRD file not found: $crd_file\n" unless -f $crd_file;

    my $manifest = $self->_generate_gpu_operator_manifest;

    require Digest::MD5;
    my $hash = Digest::MD5::md5_hex($manifest . path($crd_file)->slurp);
    my $deployed = $self->_load_deployed_hashes($config);

    # Check if GPU Operator is actually running (not just hash match)
    my $gpu_ns_exists = system("kubectl", "--kubeconfig=$kc_path",
        "get", "ns", "gpu-operator", "-o", "name") == 0;
    my $gpu_running = $gpu_ns_exists && system("kubectl", "--kubeconfig=$kc_path",
        "get", "deployment", "gpu-operator", "-n", "gpu-operator", "-o", "name") == 0;

    if (($deployed->{'gpu-operator'} // '') eq $hash && $gpu_running) {
        print "      GPU Operator already deployed (up to date)\n";
        return;
    }

    # Apply CRDs
    print "      Applying GPU Operator CRDs...\n";
    system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $crd_file->stringify) == 0
        or die "Failed to apply GPU Operator CRDs\n";

    # Wait briefly for CRD to be established
    sleep 2;

    # Apply operator + ClusterPolicy
    print "      Deploying GPU Operator...\n";
    my $manifest_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print $manifest_fh $manifest;
    close $manifest_fh;

    system("kubectl", "--kubeconfig=$kc_path", "apply", "-f", $manifest_fh->filename) == 0
        or die "Failed to apply GPU Operator manifests\n";

    # Wait for operator deployment
    print "      Waiting for gpu-operator...\n";
    system("kubectl", "--kubeconfig=$kc_path", "wait", "--for=condition=available",
           "--timeout=120s", "deployment/gpu-operator", "-n", "gpu-operator") == 0
        or warn "gpu-operator not ready within 120s\n";

    # Check ClusterPolicy status
    for my $i (1..12) {
        my $state = `kubectl --kubeconfig=$kc_path get clusterpolicy gpu-cluster-policy -o jsonpath='{.status.state}' 2>/dev/null`;
        chomp $state;
        if ($state eq 'ready') {
            print "  [ok] GPU Operator ready (ClusterPolicy state: ready)\n";
            last;
        }
        if ($i == 12) {
            print "      ClusterPolicy state: $state (may still be reconciling)\n";
        }
        sleep 10;
    }

    $self->_save_deployed_hash($config, 'gpu-operator', $hash);
}

sub _generate_gpu_operator_manifest {
    my ($self) = @_;

    my $operator_image = 'nvcr.io/nvidia/gpu-operator:v24.9.2';

    my @resources = (
        # Namespace
        {
            apiVersion => 'v1',
            kind       => 'Namespace',
            metadata   => { name => 'gpu-operator' },
        },

        # ServiceAccount
        {
            apiVersion => 'v1',
            kind       => 'ServiceAccount',
            metadata   => {
                name      => 'gpu-operator',
                namespace => 'gpu-operator',
            },
        },

        # ClusterRole
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRole',
            metadata   => { name => 'gpu-operator' },
            rules      => [
                {
                    apiGroups => [''],
                    resources => ['nodes', 'nodes/status', 'pods', 'pods/eviction', 'configmaps', 'events',
                                  'secrets', 'serviceaccounts', 'services', 'namespaces',
                                  'endpoints', 'persistentvolumeclaims'],
                    verbs     => ['*'],
                },
                {
                    apiGroups => ['apps'],
                    resources => ['deployments', 'daemonsets', 'replicasets', 'statefulsets'],
                    verbs     => ['*'],
                },
                {
                    apiGroups => ['rbac.authorization.k8s.io'],
                    resources => ['clusterroles', 'clusterrolebindings', 'roles', 'rolebindings'],
                    verbs     => ['*'],
                },
                {
                    apiGroups => ['nvidia.com'],
                    resources => ['clusterpolicies', 'clusterpolicies/status', 'clusterpolicies/finalizers'],
                    verbs     => ['*'],
                },
                {
                    apiGroups => ['security.openshift.io'],
                    resources => ['securitycontextconstraints'],
                    verbs     => ['*'],
                },
                {
                    apiGroups => ['scheduling.k8s.io'],
                    resources => ['priorityclasses'],
                    verbs     => ['get', 'list', 'watch', 'create', 'update'],
                },
                {
                    apiGroups => ['coordination.k8s.io'],
                    resources => ['leases'],
                    verbs     => ['*'],
                },
                {
                    apiGroups => ['node.k8s.io'],
                    resources => ['runtimeclasses'],
                    verbs     => ['*'],
                },
                {
                    apiGroups => ['apiextensions.k8s.io'],
                    resources => ['customresourcedefinitions'],
                    verbs     => ['get', 'list', 'watch'],
                },
            ],
        },

        # ClusterRoleBinding
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRoleBinding',
            metadata   => { name => 'gpu-operator' },
            roleRef    => {
                apiGroup => 'rbac.authorization.k8s.io',
                kind     => 'ClusterRole',
                name     => 'gpu-operator',
            },
            subjects => [{
                kind      => 'ServiceAccount',
                name      => 'gpu-operator',
                namespace => 'gpu-operator',
            }],
        },

        # GPU Operator Deployment
        {
            apiVersion => 'apps/v1',
            kind       => 'Deployment',
            metadata   => {
                name      => 'gpu-operator',
                namespace => 'gpu-operator',
                labels    => { app => 'gpu-operator' },
            },
            spec => {
                replicas => 1,
                selector => { matchLabels => { app => 'gpu-operator' } },
                template => {
                    metadata => { labels => { app => 'gpu-operator' } },
                    spec     => {
                        serviceAccountName => 'gpu-operator',
                        tolerations        => [{
                            key      => 'node-role.kubernetes.io/control-plane',
                            operator => 'Exists',
                            effect   => 'NoSchedule',
                        }],
                        containers => [{
                            name            => 'gpu-operator',
                            image           => $operator_image,
                            command         => ['gpu-operator'],
                            env             => [
                                { name => 'WATCH_NAMESPACE', value => '' },
                                { name => 'OPERATOR_NAMESPACE', value => 'gpu-operator' },
                                { name => 'POD_NAME', valueFrom => { fieldRef => { fieldPath => 'metadata.name' } } },
                            ],
                            securityContext => {
                                allowPrivilegeEscalation => JSON::PP::false,
                                capabilities             => { drop => ['ALL'] },
                            },
                            resources => {
                                requests => { cpu => '100m',  memory => '128Mi' },
                                limits   => { cpu => '500m',  memory => '256Mi' },
                            },
                            ports => [{ containerPort => 8080, name => 'metrics' }],
                        }],
                    },
                },
            },
        },

        # ClusterPolicy CR (GPU Operator configuration)
        # driver.enabled: false — Rex installs host-level NVIDIA drivers
        # nfd.enabled: false — we deploy NFD ourselves
        # gfd.enabled: false — NFD handles GPU feature discovery
        {
            apiVersion => 'nvidia.com/v1',
            kind       => 'ClusterPolicy',
            metadata   => { name => 'gpu-cluster-policy' },
            spec       => {
                operator => {
                    defaultRuntime => 'containerd',
                },
                driver => {
                    enabled => JSON::PP::false,  # Rex installs drivers on the host
                },
                toolkit => {
                    enabled => JSON::PP::true,
                    version => 'v1.17.1-ubuntu22.04',
                },
                devicePlugin => {
                    enabled => JSON::PP::true,
                    version => 'v0.17.0',
                },
                dcgmExporter => {
                    enabled => JSON::PP::true,
                    version => '3.3.9-3.6.1-ubuntu22.04',
                },
                dcgm => {
                    enabled => JSON::PP::true,
                },
                gfd => {
                    enabled => JSON::PP::false,  # NFD handles feature discovery
                },
                nfd => {
                    enabled => JSON::PP::false,  # We deploy NFD ourselves
                },
                migManager => {
                    enabled => JSON::PP::false,
                },
                validator => {
                    enabled => JSON::PP::true,
                },
                nodeStatusExporter => {
                    enabled => JSON::PP::false,
                },
            },
        },
    );

    return $self->ocp->dump(@resources);
}

#
# Share directory (static CRDs, etc.)
#

sub _find_share_dir {
    my ($self) = @_;

    my @locations = (
        '/opt/ocp/src/share',                            # Docker
        path($FindBin::Bin)->parent->child('share'),     # Dev
    );

    eval {
        require File::ShareDir;
        push @locations, path(File::ShareDir::dist_dir('OCP'));
    };

    for my $dir (@locations) {
        return path($dir) if -d $dir;
    }

    die "OCP share directory not found. Tried:\n" . join("\n", map { "  - $_" } @locations) . "\n";
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

    return $self->ocp->load_file($path->stringify) || {};
}

sub _save_deployed_hash {
    my ($self, $config, $component, $hash) = @_;
    my $hashes = $self->_load_deployed_hashes($config);
    $hashes->{$component} = $hash;
    my $path = $self->_deployed_hashes_path($config);
    $path->parent->mkpath unless -d $path->parent;

    $self->ocp->dump_file($path->stringify, $hashes);
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

    # Registry (always deployed — required infrastructure)
    {
        $checked++;
        print "  [..] Checking registry...\n";
        eval {
            my $deployed = $self->_load_deployed_hashes($config);
            my $manifest = $self->_generate_registry_manifest($config);
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

    # NFD (Node Feature Discovery) — always deployed
    {
        $checked++;
        print "  [..] Checking NFD...\n";
        eval {
            my $deployed = $self->_load_deployed_hashes($config);

            my $share_dir = $self->_find_share_dir;
            my $crd_file = $share_dir->child('nfd', 'crds', 'nodefeature-crd.yaml');
            my $manifest = $self->_generate_nfd_manifest;
            require Digest::MD5;
            my $current_hash = Digest::MD5::md5_hex($manifest . path($crd_file)->slurp);
            my $was_missing = !exists $deployed->{nfd};
            my $was_different = ($deployed->{nfd} // '') ne $current_hash;

            $self->_setup_nfd($kubeconfig, $config);

            if ($was_missing) {
                print "  [ok] NFD deployed (was missing)\n";
                $updated++;
            } elsif ($was_different) {
                print "  [ok] NFD updated (manifest changed)\n";
                $updated++;
            } else {
                print "  [ok] NFD up to date\n";
            }
        };
        if ($@) {
            print "  [WARN] NFD setup failed: $@\n";
        }
    }

    # GPU Operator (only if NFD detects NVIDIA GPU)
    {
        $checked++;
        print "  [..] Checking GPU Operator...\n";
        eval {
            my $deployed = $self->_load_deployed_hashes($config);

            # GPU Operator reconciliation: _setup_gpu_operator handles
            # the NFD label check internally and skips if no GPU
            my $was_missing = !exists $deployed->{'gpu-operator'};

            $self->_setup_gpu_operator($kubeconfig, $config);

            my $deployed_after = $self->_load_deployed_hashes($config);
            if ($deployed_after->{'gpu-operator'} && $was_missing) {
                print "  [ok] GPU Operator deployed (was missing)\n";
                $updated++;
            } elsif ($deployed_after->{'gpu-operator'} && ($deployed->{'gpu-operator'} // '') ne ($deployed_after->{'gpu-operator'} // '')) {
                print "  [ok] GPU Operator updated (manifest changed)\n";
                $updated++;
            } elsif ($deployed_after->{'gpu-operator'}) {
                print "  [ok] GPU Operator up to date\n";
            }
            # If no gpu-operator key after setup, it was skipped (no GPU) — already printed
        };
        if ($@) {
            print "  [WARN] GPU Operator setup failed: $@\n";
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
