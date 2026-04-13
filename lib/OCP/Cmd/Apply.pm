package OCP::Cmd::Apply;
# ABSTRACT: Reconcile cluster to match config

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);
use JSON::PP ();
use FindBin;

use YAML::XS ();

use Digest::MD5;
use File::ShareDir;
use File::Temp;
use HTTP::Tiny;
use Kubernetes::REST::Kubeconfig;
use Socket;

use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Provider;
use OCP::Secrets;
use OCP::SSH;
use OCP::Rex;
use OCP::Versions;

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

    # Get provider configuration
    my $hetzner_token = $secrets->hetzner_token;

    # Get control plane spec (now an ArrayRef)
    my $cps = $config->control_planes;
    my $first_cp = $cps->[0] // {};
    my $provider = $first_cp->{provider} // 'hetzner';
    my $num_control_planes = scalar @$cps;

    # Initialize provider
    my $prov = OCP::Provider->for_spec($first_cp,
        token        => $hetzner_token,
        cluster_name => $config->name,
        ssh_key_path => $config->ssh_private_key_path,
        verbose      => $verbose,
    );

    my $deploy_step = $no_password_mode ? 2 : 3;
    print "Step $deploy_step: Deploy control plane(s)\n";
    print "        Provider: $provider\n";
    print "        Count: $num_control_planes\n\n";

    if ($self->dry_run) {
        print "[Dry run - no changes made]\n";
        return;
    }

    # Deploy first control plane
    # SSH: derive node name from host (avatar.conflict.industries -> avatar)
    # Hetzner: use RoboCop naming (police1)
    my $cp_name;
    my ($cp_hostname, $cp_domain);
    if ($provider eq 'ssh' && $first_cp->{host}) {
        my $host = $first_cp->{host};
        if ($host =~ /\./) {
            ($cp_hostname, $cp_domain) = split(/\./, $host, 2);
        } else {
            $cp_hostname = $host;
            $cp_domain = '';
        }
        $cp_name = $cp_hostname;
    } else {
        $cp_name = 'police1';  # RoboCop naming!
        $cp_hostname = $config->name . "-" . $cp_name;
        $cp_domain = '';
    }

    print "Deploying control plane: $cp_name\n";

    # Create server via provider
    my $cp_host;
    my $cp_ip;

    print "  [..] Provisioning server ($provider)...\n";

    # Upload SSH key (Hetzner uploads to cloud, SSH/Local is no-op)
    my $key_name = "ocp-" . $config->name . "-admin";
    $prov->upload_ssh_key($key_name, $admin_key->{public});

    # Create server (idempotent for Hetzner — checks labels first)
    my $server_info = $prov->create_server(
        name        => $cp_hostname,
        cluster     => $config->name,
        node        => $cp_name,
        role        => 'control-plane',
        server_type => $first_cp->{serverType} // 'cx32',
        image       => $first_cp->{image} // 'debian-13',
        location    => $first_cp->{location} // 'fsn1',
        ssh_keys    => [$key_name],
        host        => $first_cp->{host},
    );

    if ($server_info->{newly_created}) {
        print "  [ok] Server created: " . ($server_info->{id} // 'n/a') . "\n";
        print "  [..] Waiting for server to be running...\n";
        $prov->wait_for_running($server_info, 120);
        print "  [ok] Server running: $server_info->{ip}\n";
    } else {
        print "  [ok] Using existing server: $server_info->{ip}\n";
    }

    $cp_ip = $server_info->{ip};
    $cp_host = $cp_ip;

    # Wait for SSH
    print "  [..] Waiting for SSH to be ready...\n";

    # Prepare SSH key file (Rex needs both private + .pub!)
    my $ssh_key_path;
    my $temp_key_file;
    my $temp_pub_file;

    if ($no_password_mode || $provider eq 'ssh') {
        # Dev mode or SSH provider: Use bootstrap key (.ocp/id_ed25519)
        # SSH provider servers already have this key in authorized_keys.
        # For Hetzner, admin-key is uploaded via API before server creation.
        $ssh_key_path = $config->ssh_private_key_path;
    } else {
        # Secure mode + Hetzner: Use admin-key (uploaded via Hetzner API)


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

    # Install RKE2 server (wrapped for failure cleanup)
    print "  [..] Installing RKE2 server...\n";

    my $rex = OCP::Rex->new(
        host     => $cp_host,
        key_file => $ssh_key_path,
        user     => 'root',
        verbose  => $verbose,
    );

    my $distribution = $config->distribution || 'rke2';
    my $version = $config->version || '';

    my $result;
    eval {
        $result = $rex->install_server(
            distribution      => $distribution,
            version           => $version,
            node_name         => $cp_name,
            registry_cache    => $config->registry_cache,
            registry_upstream => $config->registry_upstream,
            registry_name     => $config->registry_name,
            hostname          => $cp_hostname // '',
            domain            => $cp_domain // '',
            timezone          => $config->timezone,
            locale            => $config->locale,
            ntp               => $config->ntp_enabled,
        );
    };
    if ($@) {
        my $err = $@;
        if ($server_info->{newly_created}) {
            print "  [!!] Installation failed, cleaning up server...\n";
            $prov->cleanup_on_failure($server_info->{id});
        }
        die $err;
    }

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

    # Initialize K8s API for all subsequent component deployments
    my $api = $self->_k8s_api($result->{kubeconfig});

    # Wait for node to be Ready (Cilium CNI must be running)
    # Nothing can be scheduled until the node is Ready!
    print "  [..] Waiting for node to be Ready (Cilium CNI)...\n";
    {
        # Quick connectivity check first
        my $api_ok = eval { $api->_request('GET', '/api/v1/namespaces/kube-system'); 1 };
        if ($api_ok) {
            print "      API server reachable\n";
        } else {
            print "      WARNING: API server may not be reachable: $@\n";
        }

        my $node_ready = 0;
        for my $i (1..60) {
            my $nodes = eval { $api->list('Node') };
            my $is_ready = 0;
            if ($nodes && $nodes->items && @{ $nodes->items }) {
                for my $cond (@{ $nodes->items->[0]->status->conditions || [] }) {
                    if ($cond->type eq 'Ready' && $cond->status eq 'True') {
                        $is_ready = 1;
                        last;
                    }
                }
            }
            if ($is_ready) {
                print "  [ok] Node is Ready after ~${\ ($i * 10)}s\n";
                $node_ready = 1;
                last;
            }
            if ($i == 1 || $i % 6 == 0) {
                my $status = 'unknown';
                if ($nodes && $nodes->items && @{ $nodes->items }) {
                    for my $cond (@{ $nodes->items->[0]->status->conditions || [] }) {
                        $status = $cond->status if $cond->type eq 'Ready';
                    }
                }
                print "      ... waiting (${i}/60) status='$status'\n";
            }
            sleep 10;
        }
        unless ($node_ready) {
            # Last resort: check via SSH directly on the node
            print "  [WARN] Node not Ready after 600s via API, checking via SSH...\n";
            my $ssh_check = $ssh->run("/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes 2>&1");
            my $ssh_output = $ssh_check->{stdout} || '';
            print "      SSH node status: $ssh_output\n";
            if ($ssh_output =~ /\bReady\b/ && $ssh_output !~ /NotReady/) {
                print "  [ok] Node is Ready (confirmed via SSH)\n";
                $node_ready = 1;
            } else {
                my $cilium_check = $ssh->run("cilium status --kubeconfig /etc/rancher/rke2/rke2.yaml 2>&1");
                print "      Cilium status: " . ($cilium_check->{stdout} || 'unknown') . "\n";
                print "  [WARN] Node genuinely not Ready, continuing anyway...\n";
            }
        }
    }

    # Deploy registry (pull-through cache + local) FIRST after node Ready.
    # MUST succeed: all image pulls go through this.
    print "  [..] Setting up OCP registry (pull-through cache + local)...\n";
    $self->_setup_registry($config);
    print "  [ok] OCP registry ready\n";

    # Configure CoreDNS for registry.local
    eval {
        $self->_configure_registry_dns($cp_ip);
    };
    if ($@) {
        print "  [WARN] registry.local DNS setup failed: $@\n";
    }

    # Deploy NFD (Node Feature Discovery) — always, detects hardware automatically.
    # This MUST succeed: GPU Operator gating depends on NFD labels, and a silent
    # NFD failure produces a "successful" cluster that has no GPU workloads.
    print "  [..] Setting up Node Feature Discovery (NFD)...\n";
    $self->_setup_nfd($config);
    print "  [ok] NFD ready\n";

    # Deploy GPU Operator if NFD detects NVIDIA GPU (pci-10de label)
    print "  [..] Checking GPU Operator...\n";
    eval {
        $self->_setup_gpu_operator($config);
    };
    if ($@) {
        print "  [WARN] GPU Operator setup failed: $@\n";
    }

    # Apply cert-manager manifests AFTER node is Ready (pods can be scheduled now)
    # Apply cert-manager — MUST succeed: TLS certificates depend on it.
    my $cert_manager_applied = 0;
    unless ($config->no_cert) {
        print "  [..] Applying cert-manager manifests...\n";
        $self->_apply_cert_manager();
        $cert_manager_applied = 1;
        $self->_save_deployed_hash($config, 'certmanager', OCP::Versions->get_component_version('cert_manager'));
        print "  [ok] cert-manager applied (starting in background)\n";
    }

    # Setup Cilium Gateway API (while cert-manager starts up).
    # MUST succeed: the Gateway is the entry point for all HTTP(S) traffic.
    print "  [..] Setting up Cilium Gateway API...\n";
    $self->_setup_cilium_gateway($config);
    print "  [ok] Cilium Gateway ready\n";

    # Setup LB-IPAM for bare-metal LoadBalancer support.
    # OPT-IN: set 'lbipam: true' in ocp.yaml to enable. Disabled by default
    # because the host-public-IP-as-pool + L2 announcement combo makes Cilium
    # hijack ARP for the host IP and drop all host-bound traffic (sshd,
    # kube-apiserver) that isn't a registered Service. If you need external
    # web access, enable this manually and be prepared for the tradeoffs —
    # see https://docs.cilium.io/en/stable/network/lb-ipam/
    if ($config->lbipam) {
        print "  [..] Setting up LB-IPAM (opt-in)...\n";
        eval {
            $self->_setup_lb_ipam($cp_ip);
        };
        if ($@) {
            print "  [WARN] LB-IPAM setup failed: $@\n";
        } else {
            print "  [ok] LB-IPAM ready\n";
        }
    } else {
        print "  [ok] LB-IPAM skipped (opt-in — set 'lbipam: true' in ocp.yaml if needed)\n";
    }

    # Now wait for cert-manager and create issuers (had time to start during Gateway + LB-IPAM setup)
    if ($cert_manager_applied) {
        print "  [..] Waiting for cert-manager to be ready...\n";
        $self->_wait_cert_manager_and_create_issuers($config);
        print "  [ok] cert-manager ready\n";
    }

    # Deploy workers (if configured)
    my $workers = $config->workers;
    if (@$workers && (!$self->only || $self->only eq 'workers')) {
        print "\n";
        print "Step " . ($deploy_step + 1) . ": Deploy workers\n";
        $self->_deploy_workers($config, $workers, $ssh_key_path, $cp_ip, $secrets);
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
    print "  1. Inspect the cluster:\n";
    print "     ocp status\n\n";
    print "  2. Export the kubeconfig for your local kubectl:\n";
    print "     ocp kubeconfig -e\n\n";
}

sub _apply_cert_manager {
    my ($self) = @_;

    my $api = $self->_k8s_api;

    my $version = OCP::Versions->get_component_version('cert_manager');
    my $url = "https://github.com/cert-manager/cert-manager/releases/download/$version/cert-manager.yaml";

    # Download manifest via HTTP

    my $http = HTTP::Tiny->new(timeout => 60);
    my $response = $http->get($url);
    die "Failed to download cert-manager manifest: $response->{status} $response->{reason}\n"
        unless $response->{success};

    # Parse multi-document YAML and server-side apply each resource
    $self->_apply_yaml_string($api, $response->{content});
}

sub _wait_cert_manager_and_create_issuers {
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;

    # Poll for cert-manager deployment to become available (up to 600s)
    unless ($self->_poll_deployment_ready($api, 'cert-manager', 'cert-manager', 600)) {
        die "cert-manager deployment not ready\n";
    }

    $self->_create_cert_issuers($config);
}

sub _create_cert_issuers {
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;
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

    # Server-side apply each issuer (retry for webhook readiness)
    for my $issuer (@issuers) {
        my $name = $issuer->{metadata}{name};

        my $retries = 3;
        my $success = 0;
        for my $attempt (1..$retries) {
            if (eval { $self->_server_side_apply($api, $issuer); 1 }) {
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
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;

    # Gateway API CRDs are already installed by Rexfile (before Cilium)

    # Create Cilium Gateway via server-side apply
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

    $self->_server_side_apply($api, $gateway);

    # Wait for the Gateway resource to be *Accepted* by the Cilium gateway
    # controller. We deliberately do NOT wait for Programmed=True: the HTTPS
    # listener references a cert-manager Secret that won't exist yet at this
    # point, so Programmed stays False until cert-manager finishes its work
    # later. Accepted is the "controller has claimed this Gateway" signal and
    # is enough for our setup ordering.
    print "      Waiting for Gateway to be Accepted by Cilium...\n";
    # Gateway is a CRD (gateway.networking.k8s.io), not a core resource —
    # $api->get('Gateway', ...) fails silently because Kubernetes::REST has
    # no IO::K8s class for it. Use raw API path instead.
    my $gw_path = '/apis/gateway.networking.k8s.io/v1/namespaces/kube-system/gateways/cilium-gateway';
    for my $i (1..30) {
        my $gw = $self->_crd_get($api, $gw_path);
        if ($gw && $gw->{status} && $gw->{status}{conditions}) {
            for my $cond (@{ $gw->{status}{conditions} }) {
                if ($cond->{type} eq 'Accepted' && $cond->{status} eq 'True') {
                    print "      Gateway is accepted (Programmed will follow once cert-manager provides the Secret)\n";
                    return;
                }
            }
        }
        sleep 2;
    }
    die "Gateway 'cilium-gateway' did not become Accepted within 60s\n";
}

sub _setup_lb_ipam {
    my ($self, $node_ip) = @_;

    my $api = $self->_k8s_api;

    # Resolve hostname to IP if needed

    if ($node_ip !~ /^\d+\.\d+\.\d+\.\d+$/) {
        my $packed = Socket::inet_aton($node_ip);
        die "Cannot resolve $node_ip\n" unless $packed;
        $node_ip = Socket::inet_ntoa($packed);
    }

    # If IP is localhost/loopback, get the real node IP from Kubernetes
    if ($node_ip =~ /^127\./) {
        my $nodes = eval { $api->list('Node') };
        if ($nodes && $nodes->items && @{ $nodes->items }) {
            for my $addr (@{ $nodes->items->[0]->status->addresses || [] }) {
                if ($addr->type eq 'InternalIP' && $addr->address !~ /^127\./) {
                    print "      Using node IP " . $addr->address . " (instead of $node_ip)\n";
                    $node_ip = $addr->address;
                    last;
                }
            }
        }
        if ($node_ip =~ /^127\./) {
            print "      WARNING: Only loopback IP available, LB-IPAM may not work externally\n";
        }
    }
    print "      LB-IPAM pool: $node_ip/32\n";

    # Wait for Cilium to serve the LB-IPAM API. In Cilium 1.19+ both
    # CiliumLoadBalancerIPPool and most BGP resources are served under v2;
    # CiliumL2AnnouncementPolicy is still v2alpha1. This matches the typed
    # classes in IO::K8s::Cilium 1.100.
    print "      Waiting for CiliumLoadBalancerIPPool API...\n";
    my $crd_ready = 0;
    for my $i (1..30) {
        my $resp = eval {
            $api->_request('GET', '/apis/cilium.io/v2/ciliumloadbalancerippools');
        };
        if ($resp && $resp->status < 400) {
            $crd_ready = 1;
            last;
        }
        print "      ... waiting for Cilium operator (${i}/30)\n" if $i % 5 == 0;
        sleep 10;
    }
    die "CiliumLoadBalancerIPPool API (cilium.io/v2) not served after 300s\n"
        unless $crd_ready;

    my @resources = (
        {
            apiVersion => 'cilium.io/v2',
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

    $self->_server_side_apply_all($api, @resources);

    # Verify Gateway got an IP (raw CRD get — Gateway has no IO::K8s class)
    sleep 2;
    my $gw_path = '/apis/gateway.networking.k8s.io/v1/namespaces/kube-system/gateways/cilium-gateway';
    my $gw = $self->_crd_get($api, $gw_path);
    if ($gw && $gw->{status} && $gw->{status}{addresses} && @{ $gw->{status}{addresses} }) {
        print "      Gateway external IP: $gw->{status}{addresses}[0]{value}\n";
    }
}

#
# Registry (Pull-Through Cache + Local)
#

sub _setup_registry {
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;

    my $manifest = $self->_generate_registry_manifest($config);

    # Check if already deployed with same manifest

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

    # Server-side apply all registry resources
    $self->_apply_yaml_string($api, $manifest);

    # Wait for deployed components
    unless ($config->has_external_cache) {
        print "      Waiting for ocp-cache...\n";
        $self->_poll_deployment_ready($api, 'ocp-cache', 'ocp-system', 120)
            or die "ocp-cache not ready within 120s\n";
    }

    unless ($config->has_external_upstream) {
        print "      Waiting for ocp-registry...\n";
        $self->_poll_deployment_ready($api, 'ocp-registry', 'ocp-system', 120)
            or die "ocp-registry not ready within 120s\n";
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
# CoreDNS registry.local
#

sub _configure_registry_dns {
    my ($self, $node_ip) = @_;

    my $api = $self->_k8s_api;

    # Resolve to IP if hostname
    if ($node_ip !~ /^\d+\.\d+\.\d+\.\d+$/) {
        my $packed = Socket::inet_aton($node_ip);
        die "Cannot resolve $node_ip\n" unless $packed;
        $node_ip = Socket::inet_ntoa($packed);
    }

    # Get current CoreDNS ConfigMap
    my $cm = eval { $api->get('ConfigMap', 'coredns', namespace => 'kube-system') };
    return unless $cm;

    my $corefile = $cm->data->{Corefile} // '';

    # Check if already configured
    return if $corefile =~ /registry\.local/;

    # Add hosts block before the first "ready" or "kubernetes" directive
    my $hosts_block = "    hosts {\n        $node_ip registry.local\n        fallthrough\n    }\n";

    if ($corefile =~ s/(^\s*ready\b)/  $hosts_block$1/m) {
        # Inserted before 'ready'
    } elsif ($corefile =~ s/(^\s*kubernetes\b)/$hosts_block$1/m) {
        # Inserted before 'kubernetes'
    } else {
        # Fallback: append inside the main server block
        $corefile =~ s/(\n\s*\})/$hosts_block$1/;
    }

    # Patch the ConfigMap via server-side apply
    $self->_server_side_apply($api, {
        apiVersion => 'v1',
        kind       => 'ConfigMap',
        metadata   => { name => 'coredns', namespace => 'kube-system' },
        data       => { Corefile => $corefile },
    });

    print "  [ok] CoreDNS configured for registry.local -> $node_ip\n";
}

#
# NFD (Node Feature Discovery)
#

sub _setup_nfd {
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;

    # Ensure NFD image is built and pushed to ocp-registry
    # (required because released NFD versions crash on K8s 1.34+)
    $self->_ensure_nfd_image($config);

    # Apply CRDs first (before any NFD components)
    my $share_dir = $self->_find_share_dir;
    # Full upstream CRD bundle: NodeFeature + NodeFeatureGroup + NodeFeatureRule.
    # All three are required — nfd-master v0.17 watches NodeFeatureGroup and
    # gets stuck in an error loop if the CRD is missing, never processing labels.
    my $crd_file = $share_dir->child('nfd', 'crds', 'nfd-api-crds.yaml');
    die "NFD CRD file not found: $crd_file\n" unless -f $crd_file;

    my $manifest = $self->_generate_nfd_manifest;


    my $hash = Digest::MD5::md5_hex($manifest . path($crd_file)->slurp);
    my $deployed = $self->_load_deployed_hashes($config);

    # Check if NFD is actually running (not just hash match)
    my $ns_exists = $self->_resource_exists($api, 'Namespace', 'node-feature-discovery');
    my $nfd_running = $ns_exists &&
        $self->_resource_exists($api, 'Deployment', 'nfd-master', namespace => 'node-feature-discovery');

    if (($deployed->{nfd} // '') eq $hash && $nfd_running) {
        print "      NFD already deployed (up to date)\n";
        return;
    }

    # Apply CRDs
    print "      Applying NFD CRDs...\n";
    $self->_apply_yaml_file($api, $crd_file->stringify);

    # Apply NFD components
    print "      Deploying NFD master + worker...\n";
    $self->_apply_yaml_string($api, $manifest);

    # Wait for nfd-master
    print "      Waiting for nfd-master...\n";
    $self->_poll_deployment_ready($api, 'nfd-master', 'node-feature-discovery', 120)
        or die "nfd-master not ready within 120s\n";

    # Wait for nfd-worker DaemonSet
    print "      Waiting for nfd-worker...\n";
    for my $i (1..12) {
        my $ds = eval { $api->get('DaemonSet', 'nfd-worker', namespace => 'node-feature-discovery') };
        if ($ds && $ds->status && ($ds->status->numberReady // 0) > 0) {
            print "      NFD worker running on " . $ds->status->numberReady . " node(s)\n";
            last;
        }
        sleep 10;
    }

    # Wait for NFD to label nodes (needs a few seconds after worker starts)
    print "      Waiting for NFD labels...\n";
    for my $i (1..12) {
        my $nodes = eval { $api->list('Node') };
        if ($nodes && $nodes->items && @{ $nodes->items }) {
            my $labels = $nodes->items->[0]->metadata->labels;
            if ($labels && grep { /^feature\.node\.kubernetes\.io/ } keys %$labels) {
                print "      NFD labels detected on nodes\n";
                last;
            }
        }
        if ($i == 12) {
            die "NFD labels not detected on any node after 120s\n";
        }
        sleep 10;
    }

    $self->_save_deployed_hash($config, 'nfd', $hash);
}

sub _ensure_nfd_image {
    my ($self, $config) = @_;

    # Use pinned release image from registry.k8s.io (no Kaniko build needed)
    my $nfd_version = OCP::Versions->get_component_version('nfd');
    print "      Using NFD release image: registry.k8s.io/nfd/node-feature-discovery:$nfd_version\n";

    # No build needed — the manifest references the upstream image directly
    return;
}

sub _generate_nfd_manifest {
    my ($self) = @_;

    my $nfd_version = OCP::Versions->get_component_version('nfd');
    my $nfd_image = "registry.k8s.io/nfd/node-feature-discovery:$nfd_version";

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

        # ClusterRole for nfd-master — mirrors upstream NFD v0.17 RBAC.
        # Every rule here is required: missing any single one makes nfd-master
        # start cleanly but silently stop processing NodeFeatures somewhere
        # along the pipeline, with the symptom of "no labels appearing".
        # In particular, 'namespaces: watch, list' is needed for NodeFeature
        # discovery, and 'nodefeaturegroups' was introduced in v0.16.
        {
            apiVersion => 'rbac.authorization.k8s.io/v1',
            kind       => 'ClusterRole',
            metadata   => { name => 'nfd-master' },
            rules      => [
                {
                    apiGroups => [''],
                    resources => ['namespaces'],
                    verbs     => ['list', 'watch'],
                },
                {
                    apiGroups => [''],
                    resources => ['nodes', 'nodes/status'],
                    verbs     => ['get', 'list', 'watch', 'patch', 'update'],
                },
                {
                    apiGroups => ['nfd.k8s-sigs.io'],
                    resources => ['nodefeatures', 'nodefeaturerules', 'nodefeaturegroups'],
                    verbs     => ['get', 'list', 'watch'],
                },
                {
                    apiGroups => ['nfd.k8s-sigs.io'],
                    resources => ['nodefeaturegroups/status'],
                    verbs     => ['patch', 'update'],
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

        # ClusterRole for nfd-worker — upstream NFD v0.17 uses a namespaced
        # Role, but ClusterRole is a valid superset here and matches our
        # pattern elsewhere. The 'pods: get' rule is required because the
        # worker reads its own pod spec for some feature sources.
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
                {
                    apiGroups => [''],
                    resources => ['pods'],
                    verbs     => ['get'],
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
                            # Mirror upstream v0.17 helm template defaults.
                            # Without explicit args, v0.17 master starts but
                            # doesn't enable the featurerules controller or
                            # leader election, and never writes node labels.
                            # NFD v0.17 CLI flags — no -featurerules-controller
                            # (that's a config-file option, not a CLI flag; passing
                            # it causes a flag-parse panic). The featurerules
                            # controller is enabled by default in v0.17+.
                            args => [
                                '-enable-leader-election',
                                '-enable-taints',
                                '-resync-period=1h',
                                '-metrics=8081',
                                '-grpc-health=8082',
                            ],
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
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;

    # Check if any node has NVIDIA GPU via NFD labels.
    # NFD v0.17 labels use the format pci-{CLASS}_{VENDOR}.present:
    #   0300 = VGA controller (consumer/workstation GPUs: RTX, GTX, Quadro)
    #   0302 = 3D controller  (datacenter GPUs: Tesla, A100, H100, L40)
    my @gpu_nodes;
    for my $pci_class (qw(0300_10de 0302_10de)) {
        my $list = eval {
            $api->list('Node', labelSelector => "feature.node.kubernetes.io/pci-${pci_class}.present=true")
        };
        if ($list && $list->items) {
            push @gpu_nodes, @{ $list->items };
        }
    }
    # Deduplicate (a node could theoretically have both classes)
    my %seen;
    @gpu_nodes = grep { !$seen{$_->metadata->name}++ } @gpu_nodes;

    unless (@gpu_nodes) {
        print "      No GPU nodes detected (no NFD pci-0300_10de or pci-0302_10de label)\n";
        print "  [ok] GPU Operator skipped (no GPU hardware)\n";
        return;
    }

    my @gpu_names = map { $_->metadata->name } @gpu_nodes;
    print "      GPU node(s) detected: ", join(', ', @gpu_names), "\n";

    # Apply CRDs first
    my $share_dir = $self->_find_share_dir;
    my $crd_file = $share_dir->child('gpu-operator', 'crds', 'clusterpolicy-crd.yaml');
    die "GPU Operator CRD file not found: $crd_file\n" unless -f $crd_file;
    my $driver_crd_file = $share_dir->child('gpu-operator', 'crds', 'nvidiadriver-crd.yaml');
    die "NVIDIADriver CRD file not found: $driver_crd_file\n" unless -f $driver_crd_file;

    my $manifest = $self->_generate_gpu_operator_manifest($config);

    my $hash = Digest::MD5::md5_hex($manifest . path($crd_file)->slurp . path($driver_crd_file)->slurp);
    my $deployed = $self->_load_deployed_hashes($config);

    # Check if GPU Operator is actually running (not just hash match)
    my $gpu_ns_exists = $self->_resource_exists($api, 'Namespace', 'gpu-operator');
    my $gpu_running = $gpu_ns_exists &&
        $self->_resource_exists($api, 'Deployment', 'gpu-operator', namespace => 'gpu-operator');

    if (($deployed->{'gpu-operator'} // '') eq $hash && $gpu_running) {
        print "      GPU Operator already deployed (up to date)\n";
        return;
    }

    # Apply CRDs (ClusterPolicy + NVIDIADriver)
    print "      Applying GPU Operator CRDs...\n";
    $self->_apply_yaml_file($api, $crd_file->stringify);
    $self->_apply_yaml_file($api, $driver_crd_file->stringify);

    # Wait briefly for CRDs to be established
    sleep 3;

    # Apply operator + ClusterPolicy
    print "      Deploying GPU Operator...\n";
    $self->_apply_yaml_string($api, $manifest);

    # Wait for operator deployment
    print "      Waiting for gpu-operator...\n";
    $self->_poll_deployment_ready($api, 'gpu-operator', 'gpu-operator', 120)
        or die "gpu-operator not ready within 120s\n";

    # Check ClusterPolicy status via raw API (CRD, no IO::K8s class)
    my $cp_path = '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy';
    for my $i (1..12) {
        my $cp = $self->_crd_get($api, $cp_path);
        if ($cp && $cp->{status} && ($cp->{status}{state} // '') eq 'ready') {
            print "  [ok] GPU Operator ready (ClusterPolicy state: ready)\n";
            last;
        }
        if ($i == 12) {
            my $state = ($cp && $cp->{status}) ? ($cp->{status}{state} // 'unknown') : 'unknown';
            print "      ClusterPolicy state: $state (may still be reconciling)\n";
        }
        sleep 10;
    }

    $self->_save_deployed_hash($config, 'gpu-operator', $hash);
}

sub _generate_gpu_operator_manifest {
    my ($self, $config) = @_;

    my $gpu_version = OCP::Versions->get_component_version('gpu_operator');
    my $operator_image = "nvcr.io/nvidia/gpu-operator:$gpu_version";
    my $distribution = $config->distribution || 'rke2';

    # Containerd socket path differs between RKE2 and K3s
    my $containerd_socket = $distribution eq 'k3s'
        ? '/run/k3s/containerd/containerd.sock'
        : '/var/lib/rancher/rke2/agent/containerd/containerd.sock';
    my $containerd_config = $distribution eq 'k3s'
        ? '/var/lib/rancher/k3s/agent/etc/containerd/config.toml'
        : '/var/lib/rancher/rke2/agent/etc/containerd/config.toml';
    my $containerd_set_as_default = '1';
    my $containerd_runtime_class = 'nvidia';

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
                    # GPU Operator probes config.openshift.io to detect OpenShift.
                    # On non-OpenShift clusters the API group doesn't exist, so this
                    # returns 404 ("not OpenShift") — but only if RBAC allows the
                    # request.  Without this rule the SA gets 403 Forbidden, which
                    # the operator treats as a fatal error.
                    apiGroups => ['config.openshift.io'],
                    resources => ['clusterversions'],
                    verbs     => ['get', 'list', 'watch'],
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
                                { name => 'USE_OSHIFT_DRIVER_TOOLKIT', value => 'false' },
                                { name => 'CLUSTER_PLATFORM', value => 'container' },
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
                    version => OCP::Versions->get_component_version('nvidia_toolkit'),
                    env => [
                        { name => 'CONTAINERD_SOCKET', value => $containerd_socket },
                        { name => 'CONTAINERD_CONFIG', value => $containerd_config },
                        { name => 'CONTAINERD_SET_AS_DEFAULT', value => $containerd_set_as_default },
                        { name => 'CONTAINERD_RUNTIME_CLASS', value => $containerd_runtime_class },
                    ],
                },
                devicePlugin => {
                    enabled => JSON::PP::true,
                    version => OCP::Versions->get_component_version('nvidia_device_plugin'),
                },
                dcgmExporter => {
                    enabled => JSON::PP::true,
                    version => OCP::Versions->get_component_version('dcgm_exporter'),
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

sub _k8s_api {
    my ($self, $kubeconfig) = @_;

    # Return cached API if available and no new kubeconfig given
    return $self->{_k8s_api} if $self->{_k8s_api} && !$kubeconfig;

    if ($kubeconfig) {



        my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
        print $kc_fh $kubeconfig;
        close $kc_fh;

        # Keep temp file alive on $self so it doesn't get cleaned up
        $self->{_kc_temp} = $kc_fh;

        $self->{_k8s_api} = Kubernetes::REST::Kubeconfig->new(
            kubeconfig_path => $kc_fh->filename,
        )->api;

        # Register CRD providers for typed access
        $self->{_k8s_api}->k8s->add(
            'IO::K8s::Cilium',
            'IO::K8s::CertManager',
            'IO::K8s::GatewayAPI',
        );

        return $self->{_k8s_api};
    }

    die "No kubeconfig available and no cached API\n";
}

#
# Kubernetes API helpers
#

sub _pluralize_kind {
    my ($self, $kind) = @_;
    my $plural = lc($kind);

    # Standard pluralization rules (matches Kubernetes conventions)
    if ($plural =~ /(?:s|x|z|sh|ch)$/) {
        return "${plural}es";
    } elsif ($plural =~ /[^aeiou]y$/) {
        $plural =~ s/y$/ies/;
        return $plural;
    } else {
        return "${plural}s";
    }
}

sub _build_resource_path {
    my ($self, $resource) = @_;

    my $api_version = $resource->{apiVersion};
    my $kind = $resource->{kind};
    my $name = $resource->{metadata}{name};
    my $ns = $resource->{metadata}{namespace};

    my $plural = $self->_pluralize_kind($kind);

    my $base;
    if ($api_version =~ m{/}) {
        $base = "/apis/$api_version";
    } else {
        $base = "/api/$api_version";
    }

    if ($ns) {
        return "$base/namespaces/$ns/$plural/$name";
    } else {
        return "$base/$plural/$name";
    }
}

sub _server_side_apply {
    my ($self, $api, $resource) = @_;

    my $kind = $resource->{kind};
    my $name = $resource->{metadata}{name};
    my $ns   = $resource->{metadata}{namespace};

    # Use API's path building when the kind is registered (correct resource_plural)
    my $class = eval { $api->expand_class($kind) };
    my $path;
    if ($class) {
        # May fail if class lacks api_version() (e.g. auto-generated CRD classes)
        $path = eval { $api->_build_path($class, name => $name, ($ns ? (namespace => $ns) : ())) };
    }
    if (!$path) {
        # Fallback: build path from resource hash (works for all resources)
        $path = $self->_build_resource_path($resource);
    }

    $api->_request('PATCH', $path, $resource,
        content_type => 'application/apply-patch+yaml',
        parameters   => { fieldManager => 'ocp', force => 'true' },
    );
}

sub _server_side_apply_all {
    my ($self, $api, @resources) = @_;

    for my $resource (@resources) {
        $self->_server_side_apply($api, $resource);
    }
}

sub _apply_yaml_string {
    my ($self, $api, $yaml_string) = @_;

    my @resources = grep { $_ && ref $_ eq 'HASH' && $_->{kind} }
        YAML::XS::Load($yaml_string);

    for my $resource (@resources) {
        $self->_server_side_apply($api, $resource);
    }
}

sub _apply_yaml_file {
    my ($self, $api, $file_path) = @_;
    $self->_apply_yaml_string($api, path($file_path)->slurp_utf8);
}

sub _poll_deployment_ready {
    my ($self, $api, $name, $namespace, $timeout) = @_;
    $timeout //= 120;

    my $polls = int($timeout / 5) || 1;
    for my $i (1..$polls) {
        my $deploy = eval { $api->get('Deployment', $name, namespace => $namespace) };
        if ($deploy && $deploy->status && ($deploy->status->availableReplicas // 0) > 0) {
            return 1;
        }
        sleep 5;
    }
    return 0;
}

sub _resource_exists {
    my ($self, $api, $kind, $name, %opts) = @_;
    my $obj = eval { $api->get($kind, $name, %opts) };
    return defined $obj;
}

sub _crd_get {
    my ($self, $api, $resource_path) = @_;
    my $response = eval { $api->_request('GET', $resource_path) };
    return undef unless $response && $response->status < 400;
    return eval { JSON::PP::decode_json($response->content) };
}

sub _setup_ssh_key {
    my ($self, $config) = @_;

    my $keys_file = $config->project_dir->child('keys.yaml');
    my $no_password_mode = !-f $keys_file;

    # SSH provider: always use bootstrap key (.ocp/id_ed25519)
    my $cps = $config->control_planes;
    my $provider = ($cps->[0] // {})->{provider} // 'hetzner';

    if ($no_password_mode || $provider eq 'ssh') {
        $self->_ssh_key_path($config->ssh_private_key_path);
    } else {




        my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
        $secrets->ensure_age_key();

        my $keys = OCP::Keys->new(project_dir => $config->project_dir);
        my $pin2 = OCP::Password::prompt_password("Enter PIN2 (admin-key for SSH): ");
        my $admin_key = $keys->get_admin_key($pin2);
        unless ($admin_key) {
            die "ERROR: Wrong PIN2 or no admin-key found!\n";
        }

        my $temp_key_file = File::Temp->new(SUFFIX => '.key', UNLINK => 0);
        print $temp_key_file $admin_key->{private};
        close $temp_key_file;
        chmod 0600, $temp_key_file->filename;

        my $pub_path = $temp_key_file->filename . '.pub';
        path($pub_path)->spew($admin_key->{public});
        chmod 0644, $pub_path;

        $self->_ssh_key_path($temp_key_file->filename);
        # Keep ref so temp file lives as long as $self
        $self->{_temp_ssh_key} = $temp_key_file;
    }
}

#
# Worker deployment
#

sub _deploy_workers {
    my ($self, $config, $workers, $ssh_key_path, $cp_ip, $secrets) = @_;

    my $hetzner_token = $secrets->hetzner_token;
    my $distribution = $config->distribution || 'rke2';
    my $version = $config->version || '';
    my $verbose = $self->ocp->verbose;

    # Get join token from control plane
    my $cp_ssh = OCP::SSH->new(
        host     => $cp_ip,
        key_file => $ssh_key_path,
        user     => 'root',
    );

    my $token_path = $distribution eq 'k3s'
        ? '/var/lib/rancher/k3s/server/node-token'
        : '/var/lib/rancher/rke2/server/node-token';
    my $token_result = $cp_ssh->run("cat $token_path");
    my $join_token = $token_result->{stdout};
    chomp $join_token;

    die "Could not retrieve join token from control plane\n" unless $join_token;

    my $server_url = "https://$cp_ip:9345";
    my $worker_idx = 0;

    for my $pool (@$workers) {
        my $pool_name = $pool->{name} // 'pool' . ++$worker_idx;
        my $pool_provider = $pool->{provider} // 'hetzner';
        my $pool_nodes = $pool->{nodes} // 1;

        # Normalize: SSH pool with host list
        my @hosts;
        if ($pool_provider eq 'ssh') {
            if (ref $pool->{nodes} eq 'ARRAY') {
                @hosts = map { ref $_ ? $_->{host} : $_ } @{$pool->{nodes}};
            } elsif ($pool->{host}) {
                @hosts = ($pool->{host});
            }
            $pool_nodes = scalar @hosts || 1;
        }

        print "  Pool '$pool_name': $pool_nodes x $pool_provider\n";

        my $w_prov = OCP::Provider->for_spec($pool,
            token        => $hetzner_token,
            cluster_name => $config->name,
            ssh_key_path => $ssh_key_path,
            verbose      => $verbose,
        );

        for my $i (1 .. $pool_nodes) {
            my $w_name = "$pool_name-$i";
            my $w_hostname = $config->name . "-$w_name";
            my $w_host;

            if ($pool_provider eq 'ssh') {
                $w_host = $hosts[$i - 1] // next;
                ($w_hostname) = split(/\./, $w_host, 2);
                $w_name = $w_hostname;
            }

            print "  [..] Deploying worker: $w_name\n";

            my $server_info = $w_prov->create_server(
                name        => $w_hostname,
                cluster     => $config->name,
                node        => $w_name,
                role        => 'worker',
                server_type => $pool->{serverType} // 'cx21',
                image       => $pool->{image} // 'debian-13',
                location    => $pool->{location} // 'fsn1',
                ssh_keys    => ["ocp-" . $config->name . "-admin"],
                host        => $w_host,
            );

            if ($server_info->{newly_created}) {
                $w_prov->wait_for_running($server_info, 120);
            }

            $w_host //= $server_info->{ip};

            # Wait for SSH
            my $w_ssh = OCP::SSH->new(
                host     => $w_host,
                key_file => $ssh_key_path,
                user     => 'root',
            );
            eval { $w_ssh->wait_for_ssh(120) };
            if ($@) {
                print "  [WARN] SSH not ready for $w_name: $@\n";
                next;
            }

            # Install agent via Rex
            my $rex = OCP::Rex->new(
                host     => $w_host,
                key_file => $ssh_key_path,
                user     => 'root',
                verbose  => $verbose,
            );

            eval {
                $rex->install_agent(
                    distribution      => $distribution,
                    version           => $version,
                    server            => $server_url,
                    token             => $join_token,
                    node_name         => $w_name,
                    registry_cache    => $config->registry_cache,
                    registry_upstream => $config->registry_upstream,
                    registry_name     => $config->registry_name,
                    hostname          => $w_hostname,
                    timezone          => $config->timezone,
                    locale            => $config->locale,
                    ntp               => $config->ntp_enabled,
                );
            };
            if ($@) {
                print "  [WARN] Worker $w_name install failed: $@\n";
                if ($server_info->{newly_created}) {
                    $w_prov->cleanup_on_failure($server_info->{id});
                }
                next;
            }

            # Save node status
            $config->save_node_status({
                name       => $w_name,
                role       => 'worker',
                pool       => $pool_name,
                provider   => $pool_provider,
                providerId => $server_info->{id},
                publicIp   => $w_host,
            });

            print "  [ok] Worker $w_name deployed ($w_host)\n";
        }
    }
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

    # Initialize K8s API for reconciliation
    $self->_k8s_api($kubeconfig);

    my $updated = 0;
    my $checked = 0;

    # Cilium version drift check.
    # The reconcile path can only do API-driven things, not SSH/Rex, so we
    # can't upgrade Cilium here. But we can detect the drift and refuse to
    # pretend everything is fine, giving the user a clear recovery path.
    {
        $checked++;
        print "  [..] Checking Cilium version...\n";
        my $target = OCP::Versions->get_component_version('cilium');
        my $api    = $self->_k8s_api;
        my $op     = eval {
            $api->get('Deployment', 'cilium-operator', namespace => 'kube-system');
        };
        if (!$op) {
            die "Cilium operator not found in kube-system. Run a full deploy:\n" .
                "  rm kubeconfig.yaml .ocp/deployed.yaml && ocp apply\n";
        }
        my $image  = eval { $op->spec->template->spec->containers->[0]->image } || '';
        my ($running) = $image =~ /:v?([^\@]+?)(?:\@|$)/;
        $running //= 'unknown';
        if ($running eq $target) {
            print "  [ok] Cilium $target running\n";
        } else {
            die "Cilium version drift: running '$running', target '$target'.\n" .
                "The reconcile path cannot upgrade Cilium — trigger a full deploy:\n" .
                "  rm kubeconfig.yaml .ocp/deployed.yaml && ocp apply\n";
        }
    }

    # Registry (always deployed — required infrastructure)
    {
        $checked++;
        print "  [..] Checking registry...\n";
        eval {
            my $deployed = $self->_load_deployed_hashes($config);
            my $manifest = $self->_generate_registry_manifest($config);
        
            my $current_hash = Digest::MD5::md5_hex($manifest);
            my $was_missing = !exists $deployed->{registry};
            my $was_different = ($deployed->{registry} // '') ne $current_hash;

            $self->_setup_registry($config);

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
            my $crd_file = $share_dir->child('nfd', 'crds', 'nfd-api-crds.yaml');
            my $manifest = $self->_generate_nfd_manifest;
        
            my $current_hash = Digest::MD5::md5_hex($manifest . path($crd_file)->slurp);
            my $was_missing = !exists $deployed->{nfd};
            my $was_different = ($deployed->{nfd} // '') ne $current_hash;

            $self->_setup_nfd($config);

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

            $self->_setup_gpu_operator($config);

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
        print "  [..] Checking cert-manager...\n";
        eval {
            my $deployed = $self->_load_deployed_hashes($config);
            my $api = $self->_k8s_api;

            # Check if cert-manager is actually running
            my $cm_running = $self->_resource_exists($api, 'Deployment', 'cert-manager',
                namespace => 'cert-manager');

            if ($cm_running && $deployed->{certmanager}) {
                print "  [ok] cert-manager up to date\n";
            } else {
                my $was_missing = !$cm_running;
                print "  [..] " . ($was_missing ? "Installing" : "Updating") . " cert-manager...\n";
                $self->_apply_cert_manager();
                $self->_wait_cert_manager_and_create_issuers($config);
                $self->_save_deployed_hash($config, 'certmanager', OCP::Versions->get_component_version('cert_manager'));
                print "  [ok] cert-manager " . ($was_missing ? "deployed" : "updated") . "\n";
                $updated++;
            }
        };
        if ($@) {
            print "  [WARN] cert-manager setup failed: $@\n";
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
