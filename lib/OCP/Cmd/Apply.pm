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

use OCP::Cmd::Apply::DeployedHash;
use OCP::Cmd::Apply::K8s;

with 'OCP::Role::Cmd';

our $VERSION = '0.001';

has _ssh_key_path => (is => 'rw');

# Control-plane identity, as both apply paths have to agree on it: an SSH
# cluster is named after the first label of its host, a Hetzner one uses
# RoboCop naming. The reconcile path needs the same answer as the deploy path
# to address the OCPNode CR of a cluster it did not bootstrap itself.
sub _cp_identity {
    my ($self, $config) = @_;

    my $first_cp = $config->control_planes->[0] // {};
    my $provider = $first_cp->{provider} // 'hetzner';

    my ($name, $hostname, $domain);
    if ($provider eq 'ssh' && $first_cp->{host}) {
        my $host = $first_cp->{host};
        if ($host =~ /\./) {
            ($hostname, $domain) = split(/\./, $host, 2);
        } else {
            ($hostname, $domain) = ($host, '');
        }
        $name = $hostname;
    } else {
        $name     = 'police1';  # RoboCop naming!
        $hostname = $config->name . "-" . $name;
        $domain   = '';
    }

    return {
        name     => $name,
        provider => $provider,
        hostname => $hostname,
        domain   => $domain,
        host     => $first_cp->{host},
    };
}

# Display name for a distribution id. Apply hardcoded "RKE2" in its progress
# lines, so a `dist: k3s` cluster was announced as "Installing RKE2 server..."
# while install_k3s_server was the task actually running.
sub _dist_label {
    my ($dist) = @_;
    $dist //= '';
    return { rke2 => 'RKE2', k3s => 'K3s' }->{ lc $dist } // uc $dist;
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
    my $cp_id = $self->_cp_identity($config);
    my $cp_name     = $cp_id->{name};
    my $cp_hostname = $cp_id->{hostname};
    my $cp_domain   = $cp_id->{domain};

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
        server_type => $first_cp->{server_type} // 'cx32',
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

    my $distribution = $config->distribution || 'rke2';
    my $dist_label   = _dist_label($distribution);

    # Install the server (wrapped for failure cleanup)
    print "  [..] Installing $dist_label server...\n";

    my $rex = OCP::Rex->new(
        host     => $cp_host,
        key_file => $ssh_key_path,
        user     => 'root',
        verbose  => $verbose,
    );

    # Fall back to the version manifest, not to '' — an empty version makes the
    # Rex task resolve the distribution's *stable* channel, while OCP::Drift and
    # OCP::Node both answer this same question from OCP::Versions. Leaving it
    # empty installed a control plane that OCP then reported as drifted against
    # its own manifest, and joined workers (OCP::Node) one minor ahead of the
    # apiserver, which the Kubernetes version skew policy forbids.
    my $version = $config->version
        || OCP::Versions->get_component_version($distribution)
        || '';

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
            gpu               => $config->gpu_enabled,
            gpu_driver        => $config->gpu_driver,
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

    print "  [ok] $dist_label server installed\n";

    # Save kubeconfig (encrypted)
    print "  [..] Saving kubeconfig...\n";
    $secrets->save_kubeconfig($result->{kubeconfig});

    print "  [ok] Kubeconfig saved (encrypted to kubeconfig.yaml)\n";
    print "       Install it with: ocp kubeconfig -e\n";

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

    # CR-first worker flow:
    #   1. Ensure CRDs always (regardless of robocop_enabled) so observational
    #      CP CR + any future node tooling can work.
    #   2. Ensure OCPNodeProvider + Secret CRs for every provider referenced.
    #   3. Write CP OCPNode CR (phase=Ready, observational).
    #   4. Write Pending OCPNode CR for each worker pool entry.
    #   5. If robocop_enabled: deploy robocop, wait briefly, let it drive.
    #   6. Else (or robocop didn't come up): drive worker reconcile from CLI
    #      via OCP::Node.
    my $workers = $config->workers;
    print "\n";
    print "Step " . ($deploy_step + 1) . ": Ensure CRDs and provider CRs\n";
    $self->_ensure_crds($api);
    $self->_ensure_providers($api, $config, $secrets);
    $self->_migrate_legacy_nodes($api);
    $self->_ensure_cp_ocpnode($api, {
        name     => $cp_name,
        provider => $provider,
        host     => $cp_ip,
    });

    my $worker_step = @$workers && (!$self->only || $self->only eq 'workers');
    if ($worker_step) {
        print "\n";
        print "Step " . ($deploy_step + 2) . ": Deploy workers (CR-driven)\n";
        $self->_ensure_worker_ocpnodes($api, $config);

        my $robocop_ready = 0;
        if ($config->robocop_enabled) {
            print "  [..] Deploying robocop controller...\n";
            eval { $self->_ensure_robocop($api) };
            if ($@) {
                print "  [WARN] robocop deploy failed: $@\n";
            } else {
                $robocop_ready = $self->_wait_robocop_ready($api, 60);
                if ($robocop_ready) {
                    print "  [ok] robocop ready — grace period (5s)\n";
                    sleep 5;
                } else {
                    print "  [WARN] robocop not ready after 60s — falling back to CLI reconcile\n";
                }
            }
        }

        my @results = $self->_drive_workers($api, $config, {
            robocop_ready => $robocop_ready,
            ssh_key_path  => $ssh_key_path,
            cp_ip         => $cp_ip,
            secrets       => $secrets,
        });
        $self->_print_worker_status(\@results);
    }

    return $self->_finish_apply(
        config  => $config,
        api     => $api,
        step    => $deploy_step + 2 + ($worker_step ? 1 : 0),
        cp_name => $cp_name,
        cp_ip   => $cp_ip,
    );
}

#
# The single exit of `ocp apply`.
#
# Both paths end here on purpose. The fresh-deploy path grew a health gate
# while the reconcile path returned before it, so `ocp apply` over an existing
# cluster still printed component results and exited 0 without having looked at
# the cluster at all. A shared finisher is the structural fix: a path that
# wants to return has to come through the same evaluation, the same banner and
# the same exit code.
#
sub _finish_apply {
    my ($self, %args) = @_;

    my $config = $args{config};
    my $api    = $args{api};

    print "\n";
    print(defined $args{step} ? "Step $args{step}: Verify cluster health\n"
                              : "Verifying cluster health\n");

    my $health = eval { $self->_check_cluster_health($api) };
    unless ($health) {
        # A malfunctioning health check must not be the thing that fails a
        # deploy that otherwise went fine.
        print "  [WARN] could not verify cluster health: $@";
        $health = { critical => [], warnings => [], starting => [] };
    }
    $self->_print_health($health);

    print "\n";
    my $unhealthy = $self->_health_is_fatal($health);
    $self->_banner($self->_health_banner_text($health));

    print "Cluster: ", $config->name, "\n";
    print "Control Plane: $args{cp_name} ($args{cp_ip})\n" if $args{cp_name};
    print "API Endpoint: ", $config->api_url($args{cp_ip}), "\n" if $args{cp_ip};
    print "\n";

    if ($unhealthy) {
        print "Core cluster components are unhealthy — the cluster is up but\n";
        print "not functional. Inspect them before using it:\n";
        print "  ocp status\n\n";
    } else {
        print "Next steps:\n";
        print "  1. Inspect the cluster:\n";
        print "     ocp status\n\n";
        print "  2. Export the kubeconfig for your local kubectl:\n";
        print "     ocp kubeconfig -e\n\n";
    }

    $self->_stamp_ocp_version($config);

    return $unhealthy ? 1 : 0;
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
    my (@created, @failed);
    for my $issuer (@issuers) {
        my $name = $issuer->{metadata}{name};

        # cert-manager's webhook can take ~30s after the Deployment reports
        # Ready — endpoints, then admissionregistration. 15s of retries was
        # not enough on a fresh install: the first three attempts all hit
        # "no endpoints available for service cert-manager-webhook" and the
        # whole run failed. 90s with backoff is enough in practice.
        my $retries = 12;
        my $error;
        for my $attempt (1..$retries) {
            if (eval { $self->_server_side_apply($api, $issuer); 1 }) {
                push @created, $name;
                undef $error;
                last;
            }
            $error = $@;
            if ($attempt < $retries) {
                my $delay = $attempt < 4 ? 5 : 10;
                print "      Webhook not ready (attempt $attempt/$retries), retrying in ${delay}s...\n";
                sleep $delay;
            }
        }
        push @failed, [$name, $error] if defined $error;
    }

    # Report what actually exists, not what we intended to create. This used to
    # print the planned list unconditionally, with failures going to a warn() on
    # stderr — so a run where no issuer was created at all still announced
    # "ClusterIssuers created: selfsigned-issuer" and looked clean in the log.
    print "      ClusterIssuers created: " . join(', ', @created) . "\n" if @created;

    if (@failed) {
        for my $f (@failed) {
            my ($name, $error) = @$f;
            chomp(my $msg = $error // 'unknown error');
            print "      [FAILED] ClusterIssuer $name: $msg\n";
        }
        die "cert-manager issuers not created: "
            . join(', ', map { $_->[0] } @failed) . "\n";
    }

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

    # "Up to date" is a statement about the cluster (ADR 0017), so the local
    # hash alone may never make it. `ocp destroy` left .ocp/deployed.yaml
    # behind, and the next apply — against a cluster built from scratch —
    # announced "Registry already deployed", skipped it, and pointed CoreDNS
    # at a registry that did not exist. NFD, the GPU operator and cert-manager
    # already ask the cluster first; the registry was the one that did not.
    my $hash = Digest::MD5::md5_hex($manifest);
    my $deployed = $self->_load_deployed_hashes($config);

    my $recorded = exists $deployed->{registry};
    my $running  = $self->_registry_running($config);

    if ($running && ($deployed->{registry} // '') eq $hash) {
        print "      Registry already deployed (up to date)\n";
        return 'unchanged';
    }

    # What the caller gets told afterwards. "restored" is the case this check
    # exists for: OCP had a record, the cluster had nothing.
    my $outcome = !$recorded ? 'deployed'
                : !$running  ? 'restored'
                :              'updated';

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

    return $outcome;
}

# The registry as the cluster has it: the namespace, plus whichever of the two
# deployments this configuration actually rolls out. Mirrors
# _generate_registry_manifest — an external cache or upstream means OCP
# deploys nothing for that half and must not expect it to be there.
sub _registry_running {
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;

    return 0 unless $self->_resource_exists($api, 'Namespace', 'ocp-system');

    unless ($config->has_external_cache) {
        return 0 unless $self->_resource_exists($api, 'Deployment', 'ocp-cache',
            namespace => 'ocp-system');
    }

    unless ($config->has_external_upstream) {
        return 0 unless $self->_resource_exists($api, 'Deployment', 'ocp-registry',
            namespace => 'ocp-system');
    }

    return 1;
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
        my $upstream_host = 'registry-1.docker.io';

        my $cache_config_yml = $self->ocp->dump({
            version => '0.1',
            proxy   => { remoteurl => "https://$upstream_host" },
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
            config_map    => 'ocp-cache-config',
            host_path     => '/var/lib/ocp/cache',
            wait_for_host => $upstream_host,
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

# `ocp update` and `ocp version` both read status.ocpVersion — update refuses
# to run without it, version cannot name what is deployed. Nothing ever wrote
# it except update itself, so on a cluster this very CLI had just bootstrapped
# `ocp update` answered "Cluster not yet deployed. Run 'ocp apply' first."
sub _stamp_ocp_version {
    my ($self, $config) = @_;
    $config->set_status('ocpVersion', $OCP::VERSION);
    $config->save_status;
    return;
}

sub _registry_deployment {
    my ($name, $opts) = @_;

    my $image = 'registry:2';

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
        image        => $image,
        ports        => [{ containerPort => 5000, name => 'http' }],
        volumeMounts => \@volume_mounts,
        # /v2/ answers 200 as soon as the registry serves, in proxy mode too.
        # Without a probe the deployment counts as ready the moment the
        # container starts, which is what _poll_deployment_ready then believes.
        readinessProbe => {
            httpGet             => { path => '/v2/', port => 5000 },
            initialDelaySeconds => 2,
            periodSeconds       => 5,
        },
        resources    => {
            requests => { memory => '64Mi', cpu => '50m' },
            limits   => { memory => '512Mi' },
        },
    };

    $container->{env} = $opts->{env} if $opts->{env};

    # A proxying registry resolves its upstream once, while starting, and
    # panics if DNS does not answer yet. On a fresh cluster CoreDNS is
    # regularly a few seconds behind, so the cache crash-looped its way to
    # readiness. Wait for the name to resolve before the registry looks it up.
    my @init_containers;
    if (my $host = $opts->{wait_for_host}) {
        push @init_containers, {
            name    => 'wait-for-dns',
            image   => $image,
            command => ['/bin/sh', '-c'],
            args    => [
                join(' ',
                    'i=0;',
                    'while [ $i -lt 60 ]; do',
                    "nslookup $host >/dev/null 2>&1 && exit 0;",
                    'i=$((i+1)); sleep 2;',
                    'done;',
                    "echo 'DNS never resolved $host' >&2; exit 1",
                ),
            ],
            resources => { requests => { memory => '16Mi', cpu => '10m' } },
        };
    }

    return {
        apiVersion => 'apps/v1',
        kind       => 'Deployment',
        metadata   => { name => $name, namespace => 'ocp-system', labels => { app => $name } },
        spec       => {
            replicas => 1,
            selector => { matchLabels => { app => $name } },
            template => {
                metadata => { labels => { app => $name } },
                spec     => {
                    (@init_containers ? (initContainers => \@init_containers) : ()),
                    containers => [$container],
                    volumes    => \@volumes,
                },
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

# CoreDNS ships under a different name per distribution: k3s (like stock
# Kubernetes) calls the ConfigMap "coredns", RKE2 installs CoreDNS from a Helm
# chart and ends up with "rke2-coredns-rke2-coredns". OCP::Drift holds the
# list because `ocp status` reads the same ConfigMap to report the
# registry.local record missing; sharing it keeps writer and reader from ever
# looking in different places.
our @COREDNS_CONFIGMAPS = @OCP::Drift::COREDNS_CONFIGMAPS;

sub _configure_registry_dns {
    my ($self, $node_ip) = @_;

    my $api = $self->_k8s_api;

    # Resolve to IP if hostname. Through OCP::Drift, because `ocp status`
    # reports on this record and has to arrive at the same address from the
    # same starting value — a project whose control plane is a DNS name
    # (control_planes: host:) otherwise reads as permanently drifted.
    $node_ip = OCP::Drift::resolve_address($node_ip)
        // die "Cannot resolve $node_ip\n";

    # Get current CoreDNS ConfigMap
    my ($cm_name, $cm);
    for my $candidate (@COREDNS_CONFIGMAPS) {
        $cm = eval { $api->get('ConfigMap', $candidate, namespace => 'kube-system') };
        next unless $cm;
        $cm_name = $candidate;
        last;
    }
    return 0 unless $cm;

    my $corefile = $cm->data->{Corefile} // '';
    my $patched  = _corefile_with_host($corefile, $node_ip, 'registry.local');

    # Already resolves to this node
    return 0 if $patched eq $corefile;

    # Patch the ConfigMap via server-side apply
    $self->_server_side_apply($api, {
        apiVersion => 'v1',
        kind       => 'ConfigMap',
        metadata   => { name => $cm_name, namespace => 'kube-system' },
        data       => { Corefile => $patched },
    });

    print "  [ok] CoreDNS configured for registry.local -> $node_ip\n";
    return 1;
}

#
# Point a name at an address in a Corefile.
#
# CoreDNS allows the hosts plugin only once per server block — a second one
# and it refuses to start with "plugin/hosts: this plugin can only be used
# once per Server Block", taking cluster DNS down with it. k3s ships a
# Corefile whose root block already runs hosts for /etc/coredns/NodeHosts (a
# file k3s' own controller owns and rewrites), RKE2's has no hosts plugin at
# all. So the record goes *into* an existing hosts block as an inline entry,
# and only a Corefile without one gets a block of its own.
#
sub _corefile_with_host {
    my ($corefile, $ip, $hostname) = @_;

    # A cluster bootstrapped by an older OCP carries the block that broke it.
    # Take that back out first: the record inside it would otherwise read as
    # "already configured" and re-running apply would leave CoreDNS down.
    $corefile = _corefile_drop_added_hosts($corefile, $hostname);

    my @lines = split /\n/, $corefile, -1;

    # Brace depth at the start of each line: 0 on a server block header,
    # 1 on the plugin lines inside it, 2 inside a plugin's config block.
    my @depth;
    my $level = 0;
    for my $i (0 .. $#lines) {
        $depth[$i] = $level;
        my $opens  = () = $lines[$i] =~ /\{/g;
        my $closes = () = $lines[$i] =~ /\}/g;
        $level += $opens - $closes;
    }

    my ($from, $to) = _corefile_root_block(\@lines, \@depth);
    return $corefile unless defined $from;

    # Already listed somewhere in the block: only the address may need fixing
    for my $i ($from + 1 .. $to) {
        my ($indent, $rest) = $lines[$i] =~ /^(\s*)(\S.*?)\s*$/ or next;
        my @token = split /\s+/, $rest;
        next unless @token >= 2 && $token[0] =~ /^[0-9a-fA-F.:]+$/;
        next unless grep { $_ eq $hostname } @token[1 .. $#token];
        return $corefile if $token[0] eq $ip;
        $token[0] = $ip;
        $lines[$i] = $indent . join ' ', @token;
        return join "\n", @lines;
    }

    # One indentation step, as this Corefile writes it
    my $indent = '    ';
    for my $i ($from + 1 .. $to - 1) {
        next unless $depth[$i] == 1 && $lines[$i] =~ /^(\s+)\S/;
        $indent = $1;
        last;
    }

    # Merge into the hosts plugin the distribution already runs
    for my $i ($from + 1 .. $to) {
        next unless $depth[$i] == 1;
        my ($args, $open) = $lines[$i] =~ /^\s*hosts\b([^{]*?)\s*(\{?)\s*$/;
        next unless defined $args;

        if ($open) {
            my $inner = ($i < $#lines && $lines[$i + 1] =~ /^(\s+)\S/) ? $1 : "$indent$indent";
            splice @lines, $i + 1, 0, "$inner$ip $hostname";
        }
        else {
            # "hosts FILE" without a config block — wrap it around the entry,
            # adding no option that would change what the plugin already does
            splice @lines, $i, 1,
                "${indent}hosts$args {",
                "$indent$indent$ip $hostname",
                "$indent}";
        }
        return join "\n", @lines;
    }

    # No hosts plugin in this block: add one, in front of the first plugin
    # that has an opinion about names, or last if there is none
    my $at = $to;
    for my $i ($from + 1 .. $to - 1) {
        next unless $depth[$i] == 1 && $lines[$i] =~ /^\s*(?:ready|kubernetes)\b/;
        $at = $i;
        last;
    }

    splice @lines, $at, 0,
        "${indent}hosts {",
        "$indent$indent$ip $hostname",
        "$indent${indent}fallthrough",
        "$indent}";

    return join "\n", @lines;
}

#
# Undo the block an older OCP added: a hosts plugin that names no file and
# lists the record OCP itself writes. Only ever when the block is a duplicate,
# so a Corefile CoreDNS is happy with is never touched — and never the last
# hosts plugin standing, which is the distribution's own.
#
sub _corefile_drop_added_hosts {
    my ($corefile, $hostname) = @_;

    my @lines = split /\n/, $corefile, -1;

    my @depth;
    my $level = 0;
    for my $i (0 .. $#lines) {
        $depth[$i] = $level;
        my $opens  = () = $lines[$i] =~ /\{/g;
        my $closes = () = $lines[$i] =~ /\}/g;
        $level += $opens - $closes;
    }

    my ($from, $to) = _corefile_root_block(\@lines, \@depth);
    return $corefile unless defined $from;

    my @hosts = grep { $depth[$_] == 1 && $lines[$_] =~ /^\s*hosts\b/ } ($from + 1 .. $to);
    return $corefile if @hosts < 2;

    my $left = scalar @hosts;
    for my $i (reverse @hosts) {
        last if $left < 2;
        next unless $lines[$i] =~ /^\s*hosts\s*\{\s*$/;

        my $end = $i;
        $end++ while $end < $to && $depth[$end + 1] > $depth[$i];
        next unless grep { /\b\Q$hostname\E\b/ } @lines[$i + 1 .. $end];

        splice @lines, $i, $end - $i + 1;
        $left--;
    }

    return join "\n", @lines;
}

# First server block serving the root zone (".", ".:53", "dns://.:53"),
# as ($header_line, $closing_brace_line).
sub _corefile_root_block {
    my ($lines, $depth) = @_;

    my $from;
    for my $i (0 .. $#$lines) {
        if (!defined $from) {
            next unless $depth->[$i] == 0 && $lines->[$i] =~ /^(.*?)\{\s*$/;
            my $zones = $1;
            next unless grep { m{^(?:[a-z]+://)?\.(?::\d+)?$} } split ' ', $zones;
            $from = $i;
            next;
        }
        return ($from, $i) if $depth->[$i] == 1 && $lines->[$i] =~ /^\s*\}\s*$/;
    }

    return;
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

    my $recorded = exists $deployed->{nfd};

    if (($deployed->{nfd} // '') eq $hash && $nfd_running) {
        print "      NFD already deployed (up to date)\n";
        return 'unchanged';
    }

    my $outcome = !$recorded    ? 'deployed'
                : !$nfd_running ? 'restored'
                :                 'updated';

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

    return $outcome;
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
                            # Mirror the upstream helm template defaults. Without
                            # explicit args the master starts but doesn't enable
                            # leader election, and never writes node labels.
                            #
                            # Keep this list minimal: nfd-master rejects any flag
                            # it doesn't know, and its usage dump then trips a Go
                            # bug (`panic calling String method on zero
                            # featuregate.featureGate`) that buries the real cause.
                            # Two flags that look plausible but do NOT exist:
                            #   -featurerules-controller — config-file option only;
                            #     the controller is on by default since v0.17.
                            #   -metrics / -grpc-health   — folded into the single
                            #     -port flag (default 8080) as of v0.18.
                            args => [
                                '-enable-leader-election',
                                '-enable-taints',
                                '-resync-period=1h',
                            ],
                            # -port serves metrics and healthz. Not gRPC: the
                            # gRPC transport is gone since v0.17, workers report
                            # through the NodeFeature API instead.
                            ports           => [{ containerPort => 8080, name => 'metrics' }],
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

        # Service for nfd-master metrics/healthz
        {
            apiVersion => 'v1',
            kind       => 'Service',
            metadata   => {
                name      => 'nfd-master',
                namespace => 'node-feature-discovery',
            },
            spec => {
                selector => { app => 'nfd-master' },
                ports    => [{ port => 8080, targetPort => 8080, protocol => 'TCP', name => 'metrics' }],
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

    # `gpu.enabled: false` is one switch for the whole GPU story: Rex skips the
    # host driver, and nothing gets deployed in-cluster either. Deploying the
    # operator anyway would put the stack back on a node the spec asked to keep
    # GPU-free.
    unless ($config->gpu_enabled) {
        print "  [ok] GPU Operator skipped (gpu.enabled: false)\n";
        return;
    }

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

    # Where the operator finds containerd. Both values are paths on the *node*:
    # the operator mounts the directory of each into the toolkit DaemonSet, as
    # /runtime/sock-dir and /runtime/config-dir. A directory that merely exists
    # is therefore not good enough — what has to be in it is the socket.
    #
    # The socket does NOT differ between the distributions. RKE2 runs k3s' agent
    # code and inherits its containerd invocation along with it; measured on an
    # RKE2 node (v1.36.3+rke2r1, aarch64), the process is:
    #
    #   containerd -c /var/lib/rancher/rke2/agent/etc/containerd/config.toml
    #              -a /run/k3s/containerd/containerd.sock
    #              --state /run/k3s/containerd
    #              --root  /var/lib/rancher/rke2/agent/containerd
    #
    # The value here used to be .../rke2/agent/containerd/containerd.sock for
    # RKE2, which is --root with a socket name pinned on: the directory exists,
    # so the hostPath mounted without complaint and the DaemonSet only fell over
    # much later, when it tried to SIGHUP containerd through a socket that had
    # never been there ("unable to dial: connect: no such file or directory",
    # CrashLoopBackOff). Same reason the RKE2 GPU docs name /run/k3s/... too.
    #
    # /run, not /var/run: /run is the path containerd binds and the one in the
    # command line above. /var/run is a compatibility symlink onto it, so it
    # resolves to the same socket — but only as long as the symlink exists, and
    # it buys nothing.
    my $containerd_socket = '/run/k3s/containerd/containerd.sock';

    # The config path DOES differ, because each distribution keeps its agent
    # state under its own name. Only that name varies, so vary only the name:
    # two full paths side by side is what let the socket drift in the first
    # place. Unknown values fall back to RKE2 rather than interpolating into
    # the path — kubernetes.dist is not validated anywhere.
    my $rancher_dir = $distribution eq 'k3s' ? 'k3s' : 'rke2';
    my $containerd_config = "/var/lib/rancher/$rancher_dir/agent/etc/containerd/config.toml";

    # CONTAINERD_SET_AS_DEFAULT / CONTAINERD_RUNTIME_CLASS are the archived
    # 22.9 recipe and measured inert at the pinned operator (see karr #30): the
    # operator derives NVIDIA_RUNTIME_SET_AS_DEFAULT from cdi.enabled and hands
    # the toolkit that instead, so the node keeps runc as its default runtime
    # no matter what stands here. Left in place deliberately — removing them is
    # #30's job, not a bug fix's.
    my $containerd_set_as_default = '1';
    my $containerd_runtime_class = 'nvidia';

    # Who installs the driver, and does the toolkit need installing at all?
    #
    # driver: the two halves must never both be on — a driver container on top
    # of a host driver is two drivers for one card. 'host' is the default and
    # what Rex does; 'operator' flips both sides at once (OCP::Rex stops the
    # Rex-side install with the same config value).
    #
    # toolkit: on by default, because a plain host has no NVIDIA runtime. A
    # vendor image does: on a DGX, /usr/bin/nvidia-container-runtime and
    # nvidia-ctk are there before OCP is, and NVIDIA's guidance for those hosts
    # is toolkit.enabled=false next to driver.enabled=false, so the toolkit
    # DaemonSet does not rewrite a containerd configuration that already works.
    my $driver_by_operator = $config->gpu_driver eq 'operator';
    my $toolkit_enabled    = $config->gpu_toolkit;

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
                    resources => [
                        'clusterpolicies', 'clusterpolicies/status', 'clusterpolicies/finalizers',
                        'nvidiadrivers', 'nvidiadrivers/status', 'nvidiadrivers/finalizers',
                    ],
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
                        # Operator needs host's /etc/os-release to detect OS for
                        # templating DaemonSets like dcgm-exporter.
                        volumes => [{
                            name     => 'host-os-release',
                            hostPath => { path => '/etc/os-release' },
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
                            volumeMounts => [{
                                name      => 'host-os-release',
                                mountPath => '/host-etc/os-release',
                                readOnly  => JSON::PP::true,
                            }],
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
        # driver.enabled follows gpu.driver — see above
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
                driver => $driver_by_operator
                    ? {
                        enabled         => JSON::PP::true,
                        repository      => 'nvcr.io/nvidia',
                        image           => 'driver',
                        version         => OCP::Versions->get_component_version('nvidia_driver'),
                        imagePullPolicy => 'IfNotPresent',
                    }
                    : { enabled => JSON::PP::false },
                toolkit => {
                    enabled         => $toolkit_enabled ? JSON::PP::true : JSON::PP::false,
                    repository      => 'nvcr.io/nvidia/k8s',
                    image           => 'container-toolkit',
                    version         => OCP::Versions->get_component_version('nvidia_toolkit'),
                    imagePullPolicy => 'IfNotPresent',
                    env => [
                        { name => 'CONTAINERD_SOCKET', value => $containerd_socket },
                        { name => 'CONTAINERD_CONFIG', value => $containerd_config },
                        { name => 'CONTAINERD_SET_AS_DEFAULT', value => $containerd_set_as_default },
                        { name => 'CONTAINERD_RUNTIME_CLASS', value => $containerd_runtime_class },
                    ],
                },
                devicePlugin => {
                    enabled         => JSON::PP::true,
                    repository      => 'nvcr.io/nvidia',
                    image           => 'k8s-device-plugin',
                    version         => OCP::Versions->get_component_version('nvidia_device_plugin'),
                    imagePullPolicy => 'IfNotPresent',
                },
                dcgmExporter => {
                    enabled         => JSON::PP::true,
                    repository      => 'nvcr.io/nvidia/k8s',
                    image           => 'dcgm-exporter',
                    version         => OCP::Versions->get_component_version('dcgm_exporter'),
                    imagePullPolicy => 'IfNotPresent',
                },
                dcgm => {
                    enabled         => JSON::PP::true,
                    repository      => 'nvcr.io/nvidia/cloud-native',
                    image           => 'dcgm',
                    version         => OCP::Versions->get_component_version('nvidia_dcgm'),
                    imagePullPolicy => 'IfNotPresent',
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
                # The standalone gpu-operator-validator image stops at v25.3.4:
                # from v25.10 on the operator image carries the validator
                # itself (/usr/bin/nvidia-validator), which is why upstream's
                # values.yaml points validator at nvcr.io/nvidia/gpu-operator
                # with the chart's own appVersion. Anything else 404s and every
                # GPU DaemonSet stays in Init:ImagePullBackOff — its init
                # container is the validator.
                validator => {
                    enabled         => JSON::PP::true,
                    repository      => 'nvcr.io/nvidia',
                    image           => 'gpu-operator',
                    version         => $gpu_version,
                    imagePullPolicy => 'IfNotPresent',
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
# Worker deployment is CR-driven. The previous _deploy_workers method (a
# ~150-line imperative Hetzner/Rex-only loop) has been replaced with a
# handful of small helpers below: _ensure_crds, _ensure_providers,
# _ensure_cp_ocpnode, _ensure_worker_ocpnodes, _ensure_robocop,
# _wait_robocop_ready, _drive_workers, _print_worker_status. Actual
# provisioning runs through OCP::Node->reconcile_until_ready (CLI path)
# or via Robocop once the controller is live.
#

# Ensure the OCPNode/OCPNodeProvider CRDs exist. Always — independent of
# whether Robocop itself is deployed — because the CP CR and any future
# node-tooling need the schemas to be registered.
sub _ensure_crds {
    my ($self, $api) = @_;
    my $share_dir = $self->_find_share_dir;
    my $crd_dir   = $share_dir->child('robocop', 'crds');
    return unless -d $crd_dir;

    # Server-side apply the CRDs as raw manifests instead of ensure().
    #
    # ensure() inflates the hashref into a typed CustomResourceDefinition, and a
    # CRD schema is full of union-typed fields — `default: false`, `enum:`,
    # `items:`, `additionalProperties:`. IO::K8s ships no classes for those
    # unions (JSON, JSONSchemaPropsOr{Array,Bool,StringArray}), so the inflate
    # dies outright. Even once those classes exist, a union arm that is a bare
    # scalar has nowhere to go in an attribute-based inflate, and the CRD would
    # be written back missing its defaults — silent damage instead of a crash.
    #
    # Nothing here needs a typed round-trip; the NFD and GPU CRDs already go the
    # same way via _apply_yaml_file.
    for my $file_path (sort $crd_dir->children(qr/\.ya?ml$/)) {
        my @docs = YAML::XS::LoadFile($file_path->stringify);
        for my $doc (@docs) {
            next unless ref $doc eq 'HASH' && $doc->{kind} && $doc->{metadata}{name};
            $self->_server_side_apply($api, $doc);
            print "  [ok] ensured $doc->{kind}/$doc->{metadata}{name}\n";
        }
    }
}

# Ensure Namespace + one OCPNodeProvider CR per unique provider referenced
# in ocp.yaml (and its backing Secret for hetzner). The ocp.yaml schema
# uses inline `provider: hetzner|ssh|local` — we normalise each unique
# provider type to a deterministic CR name (e.g. "hetzner-default",
# "ssh-default", "local-default").
sub _ensure_providers {
    my ($self, $api, $config, $secrets) = @_;
    my $ns = 'ocp-system';

    # Ensure ocp-system namespace exists (idempotent via ensure).
    $api->ensure({
        apiVersion => 'v1',
        kind       => 'Namespace',
        metadata   => { name => $ns },
    });

    my %seen;
    for my $entry (@{$config->control_planes}, @{$config->workers}) {
        my $type = $entry->{provider} // 'hetzner';
        next if $seen{$type}++;
        $self->_ensure_provider_cr($api, $type, $ns, $config, $secrets);
    }
}

sub _ensure_provider_cr {
    my ($self, $api, $type, $ns, $config, $secrets) = @_;

    my $name = "$type-default";

    my $spec = { type => $type };
    if ($type eq 'hetzner') {
        my $secret_name = "hetzner-api-token-$type";
        my $token = eval { $secrets->hetzner_token };
        if ($token) {
            $api->ensure({
                apiVersion => 'v1',
                kind       => 'Secret',
                type       => 'Opaque',
                metadata   => {
                    name      => $secret_name,
                    namespace => $ns,
                },
                data => {
                    token => MIME::Base64::encode_base64($token, ''),
                },
            });
            print "  [ok] ensured Secret/$secret_name\n";
        }
        $spec->{hetzner} = {
            tokenSecretRef => { name => $secret_name, key => 'token' },
        };
    } elsif ($type eq 'ssh') {
        $spec->{ssh} = { user => 'root' };
    }

    $api->ensure({
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNodeProvider',
        metadata   => { name => $name, namespace => $ns },
        spec       => $spec,
    });
    print "  [ok] ensured OCPNodeProvider/$name\n";
}

# Address of a Kubernetes Node object: ExternalIP wins, InternalIP is the
# fallback. Returns undef when the Node is not (yet) registered.
sub _k8s_node_ip {
    my ($self, $api, $name) = @_;

    my $node = eval { $api->get('Node', $name) } or return undef;
    my $hash = ref($node) eq 'HASH' ? $node : $api->k8s->object_to_struct($node);

    for my $want (qw(ExternalIP InternalIP)) {
        for my $addr (@{ $hash->{status}{addresses} // [] }) {
            return $addr->{address} if $addr->{type} eq $want && $addr->{address};
        }
    }
    return undef;
}

# Write an observational OCPNode CR for the just-bootstrapped control
# plane with phase=Ready. CP reconcile is not in scope; this CR makes
# `ocp node ls` show CP + workers uniformly.
#
# Ownership: robocop only ever reconciles workers, and on a CLI-only cluster it
# is not running at all — so nobody but `ocp apply` can report the state of the
# control plane it just bootstrapped. Hence status is written here, stamped
# reconciler=cli, and stays observational: no reconcile loop reads it back.
#
# Spec and status are two writes on purpose. The CRD enables the status
# subresource, so the API server drops status from the ensure (see
# OCP::K8s::patch_status) — it has to go to /status separately.
sub _ensure_cp_ocpnode {
    my ($self, $api, $cp_info) = @_;
    my $ns   = 'ocp-system';
    my $name = $cp_info->{name};
    my $type = $cp_info->{provider} // 'hetzner';

    $api->ensure({
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => $name, namespace => $ns },
        spec       => {
            role        => 'control-plane',
            providerRef => "$type-default",
        },
    });

    # Prefer the address the Node object reports, so `ocp node ls` and
    # `ocp status` agree. cp_info->{host} is whatever the user configured and
    # is frequently a DNS name rather than an IP.
    my $ip = $self->_k8s_node_ip($api, $name) // $cp_info->{host};

    my $ok = eval {
        OCP::K8s->patch_status($api,
            kind      => 'OCPNode',
            name      => $name,
            namespace => $ns,
            status    => {
                phase              => 'Ready',
                ($ip ? (publicIP => $ip) : ()),
                kubernetesNodeName => $name,
                reconciler         => 'cli',
            },
        );
        1;
    };

    if ($ok) {
        print "  [ok] ensured OCPNode/$name (control-plane, Ready)\n";
    } else {
        print "  [WARN] ensured OCPNode/$name, but its status stayed unwritten: $@";
    }
}

# For each k8s Node not yet tracked by an OCPNode CR, synthesize an
# observational OCPNode CR with phase=Ready and providerRef=legacy.
# Safe to run on every apply — already-synthesized CRs are no-ops via ensure.
sub _migrate_legacy_nodes {
    my ($self, $api) = @_;

    my $cr_list = eval { $api->list('OCPNode', namespace => 'ocp-system') };
    return unless $cr_list;

    my %tracked = map {
        my $n = $api->k8s->object_to_struct($_);
        ($n->{metadata}{name} => 1);
    } @{ $cr_list->items // [] };

    my $node_list = eval { $api->list('Node') };
    return unless $node_list;

    my @untracked;
    for my $obj (@{ $node_list->items // [] }) {
        my $n    = $api->k8s->object_to_struct($obj);
        my $name = $n->{metadata}{name};
        next if $tracked{$name};
        push @untracked, $n;
    }

    return unless @untracked;

    $api->ensure({
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNodeProvider',
        metadata   => {
            name        => 'legacy',
            namespace   => 'ocp-system',
            annotations => { 'ocp.internal/synthetic' => 'true' },
        },
        spec => { type => 'ssh' },
    });

    for my $n (@untracked) {
        my $name  = $n->{metadata}{name};
        my $is_cp = exists $n->{metadata}{labels}{'node-role.kubernetes.io/control-plane'};
        my $public_ip;
        for my $addr (@{ $n->{status}{addresses} // [] }) {
            $public_ip = $addr->{address}, last if $addr->{type} eq 'ExternalIP';
        }
        unless ($public_ip) {
            for my $addr (@{ $n->{status}{addresses} // [] }) {
                $public_ip = $addr->{address}, last if $addr->{type} eq 'InternalIP';
            }
        }

        my $cr = {
            apiVersion => 'ocp.internal/v1',
            kind       => 'OCPNode',
            metadata   => {
                name        => $name,
                namespace   => 'ocp-system',
                annotations => { 'ocp.internal/synthetic' => 'true' },
            },
            spec => {
                role        => $is_cp ? 'control-plane' : 'worker',
                providerRef => 'legacy',
            },
        };
        $api->ensure($cr);

        # Separate write: the ensure above cannot carry status past the
        # status subresource (see OCP::K8s::patch_status).
        eval {
            OCP::K8s->patch_status($api,
                kind      => 'OCPNode',
                name      => $name,
                namespace => 'ocp-system',
                status    => {
                    phase              => 'Ready',
                    kubernetesNodeName => $name,
                    ($public_ip ? (publicIP => $public_ip) : ()),
                },
            );
            1;
        } or print "  [WARN] status for migrated OCPNode/$name stayed unwritten: $@";

        printf "  [migrated] %s (%s, %s)\n", $name,
               $cr->{spec}{role}, $public_ip // 'no-ip';
    }
}

# Write one Pending OCPNode CR per worker entry. If role/provider/etc. on
# the CR already differs in the cluster, the ensure preserves status
# (patch semantics are owned by the controller/CLI later).
sub _ensure_worker_ocpnodes {
    my ($self, $api, $config) = @_;
    my $ns = 'ocp-system';
    my @crs;

    my $pool_idx = 0;
    for my $pool (@{$config->workers}) {
        my $pool_name = $pool->{name} // 'pool' . ++$pool_idx;
        my $type      = $pool->{provider} // 'hetzner';
        my $count     = $pool->{nodes} // 1;

        my @hosts;
        if ($type eq 'ssh') {
            if (ref $pool->{nodes} eq 'ARRAY') {
                @hosts = map { ref $_ ? $_->{host} : $_ } @{$pool->{nodes}};
            } elsif ($pool->{host}) {
                @hosts = ($pool->{host});
            }
            $count = scalar @hosts || 1;
        }

        for my $i (1 .. $count) {
            my $w_name = "$pool_name-$i";
            my $host;
            if ($type eq 'ssh') {
                $host = $hosts[$i - 1] // next;
                ($w_name) = split(/\./, $host, 2);
            }

            my $spec = {
                role        => 'worker',
                providerRef => "$type-default",
            };
            $spec->{host}       = $host                     if $host;
            $spec->{serverType} = $pool->{server_type}      if $pool->{server_type};
            $spec->{image}      = $pool->{image}            if $pool->{image};
            $spec->{location}   = $pool->{location}         if $pool->{location};

            my $cr = {
                apiVersion => 'ocp.internal/v1',
                kind       => 'OCPNode',
                metadata   => { name => $w_name, namespace => $ns },
                spec       => $spec,
            };
            $api->ensure($cr);
            print "  [ok] ensured OCPNode/$w_name (worker, Pending)\n";
            push @crs, $cr;
        }
    }
    return @crs;
}

# Apply RBAC + Deployment for robocop. CRDs were already applied in
# _ensure_crds. Mirrors OCP::Cmd::DeployRobocop's loop but scoped to the
# non-CRD files under share/robocop/.
sub _ensure_robocop {
    my ($self, $api) = @_;
    my $share_dir   = $self->_find_share_dir;
    my $robocop_dir = $share_dir->child('robocop');

    my @other_files = grep { $_->basename ne 'kustomization.yaml' }
                           $robocop_dir->children(qr/\.ya?ml$/);

    for my $file_path (sort @other_files) {
        my @docs = YAML::XS::LoadFile($file_path->stringify);
        for my $doc (@docs) {
            next unless ref $doc eq 'HASH' && $doc->{kind} && $doc->{metadata}{name};
            $api->ensure($doc);
            print "  [ok] ensured $doc->{kind}/$doc->{metadata}{name}\n";
        }
    }
}

sub _wait_robocop_ready {
    my ($self, $api, $timeout) = @_;
    $timeout //= 60;

    my $deadline = time + $timeout;
    while (time < $deadline) {
        my $dep = eval { $api->get('Deployment', 'robocop', namespace => 'ocp-system') };
        if ($dep) {
            my $ready = eval { $dep->status->readyReplicas } // 0;
            return 1 if $ready && $ready >= 1;
        }
        sleep 5;
    }
    return 0;
}

# Drive worker reconcile. Either poll CR phases (if robocop is running)
# or run the CLI reconcile path (via OCP::Node) in-process. Returns a
# list of { name, phase, message } results.
sub _drive_workers {
    my ($self, $api, $config, $deps) = @_;

    my $ns      = 'ocp-system';
    my $workers = $config->workers;
    my @names;

    my $pool_idx = 0;
    for my $pool (@$workers) {
        my $pool_name = $pool->{name} // 'pool' . ++$pool_idx;
        my $type      = $pool->{provider} // 'hetzner';
        my $count     = $pool->{nodes} // 1;

        my @hosts;
        if ($type eq 'ssh') {
            if (ref $pool->{nodes} eq 'ARRAY') {
                @hosts = map { ref $_ ? $_->{host} : $_ } @{$pool->{nodes}};
            } elsif ($pool->{host}) {
                @hosts = ($pool->{host});
            }
            $count = scalar @hosts || 1;
        }

        for my $i (1 .. $count) {
            my $w_name = "$pool_name-$i";
            if ($type eq 'ssh') {
                my $host = $hosts[$i - 1] // next;
                ($w_name) = split(/\./, $host, 2);
            }
            push @names, $w_name;
        }
    }

    if ($deps->{robocop_ready}) {
        return $self->_poll_nodes_until_terminal($api, \@names, 600);
    }

    # CLI fallback: drive each OCPNode via OCP::Node.
    return $self->_cli_reconcile_workers($api, $config, \@names, $deps);
}

sub _poll_nodes_until_terminal {
    my ($self, $api, $names, $timeout) = @_;
    $timeout //= 600;
    my $ns = 'ocp-system';

    my $deadline = time + $timeout;
    my %terminal;

    while (time < $deadline && scalar(keys %terminal) < scalar(@$names)) {
        for my $name (@$names) {
            next if $terminal{$name};
            my $cr = eval { $api->get('OCPNode', $name, namespace => $ns) };
            my $hash = $cr
                ? (ref($cr) eq 'HASH' ? $cr : $api->k8s->object_to_struct($cr))
                : undef;
            my $phase = $hash && $hash->{status} && $hash->{status}{phase} || 'Pending';
            my $msg   = $hash && $hash->{status} && $hash->{status}{message} || '';
            if ($phase eq 'Ready' || $phase eq 'Failed') {
                $terminal{$name} = { name => $name, phase => $phase, message => $msg };
            }
        }
        last if scalar(keys %terminal) == scalar(@$names);
        sleep 10;
    }

    my @results;
    for my $name (@$names) {
        push @results, $terminal{$name} // {
            name    => $name,
            phase   => 'Unknown',
            message => "timed out waiting for phase (after ${timeout}s)",
        };
    }
    return @results;
}

sub _cli_reconcile_workers {
    my ($self, $api, $config, $names, $deps) = @_;
    my $ns = 'ocp-system';

    my $ssh_key_path = $deps->{ssh_key_path};
    my $cp_ip        = $deps->{cp_ip};
    my $secrets      = $deps->{secrets};
    my $distribution = $config->distribution || 'rke2';

    # Retrieve join token from the CP once, reused for every worker.
    my $join_token = '';
    my $server_url = $config->join_url($cp_ip);
    my $ssh_key    = eval { path($ssh_key_path)->slurp } // '';

    eval {
        my $cp_ssh = OCP::SSH->new(
            host     => $cp_ip,
            key_file => $ssh_key_path,
            user     => 'root',
        );
        my $token_path = $distribution eq 'k3s'
            ? '/var/lib/rancher/k3s/server/node-token'
            : '/var/lib/rancher/rke2/server/node-token';
        my $res = $cp_ssh->run("cat $token_path");
        $join_token = $res->{stdout} // '';
        chomp $join_token;
    };
    if ($@ || !$join_token) {
        my @results = map { {
            name    => $_,
            phase   => 'Failed',
            message => "Could not read join token from CP: " . ($@ // 'empty'),
        } } @$names;
        return @results;
    }

    my @results;
    for my $name (@$names) {
        my $cr = eval { $api->get('OCPNode', $name, namespace => $ns) };
        my $hash = $cr
            ? (ref($cr) eq 'HASH' ? $cr : $api->k8s->object_to_struct($cr))
            : undef;
        unless ($hash) {
            push @results, { name => $name, phase => 'Failed',
                             message => 'CR not found after ensure' };
            next;
        }

        # from_cr reads its argument as a plain hash ($cr->{spec}{hetzner}...).
        # get() returns a typed IO::K8s object, which only answers that because
        # IO::K8s objects happen to be blessed hashes -- convert it, the way
        # the OCPNode above and OCP::Robocop::Controller already do.
        my $provider = eval {
            my $prov_cr = $api->get('OCPNodeProvider',
                $hash->{spec}{providerRef}, namespace => $ns);
            OCP::Provider->from_cr(
                ref($prov_cr) eq 'HASH' ? $prov_cr : $api->k8s->object_to_struct($prov_cr),
                k8s => $api,
            );
        };
        if ($@ || !$provider) {
            push @results, { name => $name, phase => 'Failed',
                             message => "Provider resolve failed: " . ($@ // 'unknown') };
            next;
        }

        my $node = OCP::Node->from_cr($hash,
            k8s          => $api,
            provider     => $provider,
            ssh_key      => $ssh_key,
            server_url   => $server_url,
            join_token   => $join_token,
            distribution => $distribution,
            verbose      => $self->ocp->verbose,
        );

        my $ok = eval { $node->reconcile_until_ready(timeout => 600, interval => 10) };
        my $phase = $ok ? 'Ready' : ($node->phase || 'Failed');
        push @results, {
            name    => $name,
            phase   => $phase,
            message => $hash->{status}{message} // '',
        };
    }
    return @results;
}

sub _print_worker_status {
    my ($self, $results) = @_;
    return unless $results && @$results;
    print "\n";
    print "  Worker status:\n";
    for my $r (@$results) {
        my $tag = $r->{phase} eq 'Ready'  ? '[ok]'
                : $r->{phase} eq 'Failed' ? '[!!]'
                :                           '[..]';
        print "    $tag $r->{name} — $r->{phase}" .
              ($r->{message} ? " ($r->{message})" : "") . "\n";
    }
}

#
# Post-deploy cluster health gate
#
# `ocp apply` printed DEPLOYED SUCCESSFULLY and exited 0 whenever the deploy
# steps had run to the end. On cortex it did exactly that while CoreDNS sat in
# CrashLoopBackOff — cluster DNS entirely dead — and five gpu-operator pods
# hung in ImagePullBackOff. The banner was a statement about the script, not
# about the cluster. xt/smoke.sh already checked this from the outside; the
# check belongs in apply.
#
# Two properties decide whether such a gate is worth anything.
#
# It must not be flaky. Straight after a deploy pods are legitimately still
# coming up: ContainerCreating, PodInitializing, or a readiness probe that has
# not passed yet are all normal. So apply first waits for the cluster to settle
# — until nothing is in a starting state, or the timeout — and only judges what
# is still broken on the final scan, and only on reasons that do not heal by
# waiting. CrashLoopBackOff additionally requires the kubelet to have actually
# looped; one crash during startup is not a verdict.
#
# And it must not cry wolf. A gate that fails the whole apply because an opt-in
# add-on could not pull an image teaches people to ignore the exit code, which
# costs more than the check buys — the gpu-operator failure above was an arm64
# image availability problem on a working cluster. Hence the severity split
# below.
#

# Waiting reasons that do not resolve themselves by waiting longer.
my %DURABLE_WAIT = map { $_ => 1 } qw(
    CrashLoopBackOff
    ImagePullBackOff
    ErrImagePull
    InvalidImageName
    CreateContainerConfigError
    CreateContainerError
    RunContainerError
);

# Namespaces whose health IS the cluster: CNI, DNS, core controllers. A durable
# fault in one of these means the deploy did not produce a working cluster, so
# it is fatal. Everything else OCP installs is either opt-in (gpu-operator,
# node-feature-discovery) or already has its own readiness wait earlier in
# apply, so it warns and leaves the exit code alone.
my %CRITICAL_NS = map { $_ => 1 } qw(kube-system);

my $CRASHLOOP_MIN_RESTARTS = 2;

# healthy | starting | failing (+reason)
sub _classify_pod {
    my ($self, $pod) = @_;

    my $phase = $pod->{status}{phase} // '';
    return ('healthy') if $phase eq 'Succeeded';

    # Init containers carry their own waiting reasons — that is where
    # "Init:ImagePullBackOff" lives, which is how all five gpu-operator pods
    # failed. Scanning only containerStatuses would have missed every one.
    my @waiting_scan = (
        @{ $pod->{status}{initContainerStatuses} // [] },
        @{ $pod->{status}{containerStatuses}     // [] },
    );

    my %reasons;
    for my $cs (@waiting_scan) {
        my $reason = $cs->{state}{waiting}{reason} // '';
        next unless $reason && $DURABLE_WAIT{$reason};
        next if $reason eq 'CrashLoopBackOff'
            && ($cs->{restartCount} // 0) < $CRASHLOOP_MIN_RESTARTS;
        $reasons{$reason} = 1;
    }
    return ('failing', join(', ', sort keys %reasons)) if %reasons;
    return ('failing', 'Failed') if $phase eq 'Failed';

    # Readiness is judged on the regular containers only: a completed init
    # container's `ready` flag is not a reliable signal across versions.
    my @regular = @{ $pod->{status}{containerStatuses} // [] };
    return ('starting') unless $phase eq 'Running' && @regular;
    for my $cs (@regular) {
        return ('starting') unless $cs->{ready};
    }
    return ('healthy');
}

sub _scan_pods {
    my ($self, $api) = @_;

    my $list = $api->list('Pod');
    my @pods = map { ref($_) eq 'HASH' ? $_ : $api->k8s->object_to_struct($_) }
               @{ ($list && $list->items) || [] };

    my %out = (failing => [], starting => []);
    for my $pod (@pods) {
        my ($state, $reason) = $self->_classify_pod($pod);
        next if $state eq 'healthy';
        push @{ $out{$state} }, {
            namespace => $pod->{metadata}{namespace} // '',
            name      => $pod->{metadata}{name}      // '',
            reason    => $reason                     // '',
        };
    }
    return \%out;
}

sub _check_cluster_health {
    my ($self, $api, %opts) = @_;
    my $timeout  = $opts{timeout}  // 120;
    my $interval = $opts{interval} // 5;

    my $deadline = time + $timeout;
    my $scan;
    while (1) {
        $scan = $self->_scan_pods($api);
        last unless @{ $scan->{starting} };
        last if time >= $deadline;
        sleep $interval;
    }

    my (@critical, @warnings);
    for my $pod (@{ $scan->{failing} }) {
        push @{ $CRITICAL_NS{ $pod->{namespace} } ? \@critical : \@warnings }, $pod;
    }

    return {
        critical => \@critical,
        warnings => \@warnings,
        starting => $scan->{starting},
    };
}

sub _print_health {
    my ($self, $health) = @_;

    for my $p (@{ $health->{critical} }) {
        printf "  [!!] %s/%s — %s\n", $p->{namespace}, $p->{name}, $p->{reason};
    }
    for my $p (@{ $health->{warnings} }) {
        printf "  [WARN] %s/%s — %s\n", $p->{namespace}, $p->{name}, $p->{reason};
    }
    for my $p (@{ $health->{starting} }) {
        printf "  [..] %s/%s — still starting\n", $p->{namespace}, $p->{name};
    }
    print "  [ok] all pods healthy\n"
        unless @{ $health->{critical} }
            || @{ $health->{warnings} }
            || @{ $health->{starting} };
    return;
}

# Only a critical (core-namespace) finding is fatal. Warnings are loud but
# leave the exit code alone — see the severity split above.
sub _health_is_fatal {
    my ($self, $health) = @_;
    return scalar @{ $health->{critical} };
}

sub _health_banner_text {
    my ($self, $health) = @_;
    return 'CONTROL PLANE DEPLOYED — CLUSTER IS NOT HEALTHY'
        if $self->_health_is_fatal($health);
    return 'CONTROL PLANE DEPLOYED — WITH WARNINGS'
        if @{ $health->{warnings} };
    return 'CONTROL PLANE DEPLOYED SUCCESSFULLY!';
}

sub _banner {
    my ($self, $text) = @_;
    my $width = 63;
    print "╔" . ("═" x $width) . "╗\n";
    printf "║  %-*s║\n", $width - 2, $text;
    print "╚" . ("═" x $width) . "╝\n\n";
    return;
}

#
# Reconciliation for existing clusters
#

sub _reconcile_components {
    my ($self, $config) = @_;

    # Read the kubeconfig from the encrypted store — never from a plaintext
    # copy lying around in the project directory.
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    my $kubeconfig = $secrets->read_kubeconfig;
    unless ($kubeconfig) {
        print "  Cannot decrypt kubeconfig.yaml, skipping component reconcile.\n";
        print "  Make sure .ocp/age.key exists.\n";
        return;
    }

    # Initialize K8s API for reconciliation
    $self->_k8s_api($kubeconfig);

    my $cp_id   = $self->_cp_identity($config);
    my $cp_name = $cp_id->{name};
    my $cp_ip   = $config->cluster_status->{public_ip} // $cp_id->{host};

    my $updated = 0;
    my $checked = 0;

    # Drift: compare the running cluster against the version manifest and
    # ocp.yaml, then run whatever step brings it back.
    {
        $checked++;
        print "  [..] Checking for drift...\n";

        my $drift = OCP::Drift->new(
            config => $config,
            api    => $self->_k8s_api,
        )->detect;

        if (!@$drift) {
            print "  [ok] No drift detected\n";
        }

        for my $entry (@$drift) {
            print "  [drift] $entry->{message}\n";

            unless ($entry->{remedy}) {
                # Missing components are deployed by the checks below; the
                # rest (distribution upgrades, moved IPs) needs a human.
                print "        No automatic step for this — see 'ocp update'\n"
                    if $entry->{kind} ne 'missing';
                next;
            }

            print "  [..] Running $entry->{remedy}{task}...\n";
            my $done = eval { $self->_run_remedy($config, $entry) };
            if ($@) {
                print "  [WARN] $entry->{remedy}{task} failed: $@";
            } elsif ($done) {
                print "  [ok] $entry->{label} updated to $entry->{expected}\n";
                $updated++;
            }
        }
    }

    # Registry (always deployed — required infrastructure)
    {
        $checked++;
        print "  [..] Checking registry...\n";
        eval {
            # What happened is decided where the deploy happens. Recomputing
            # the hash out here made this the second place that judged the
            # same fact, and it judged it from the local file only: it printed
            # "up to date" for a registry _setup_registry had just had to put
            # back on the cluster.
            $updated += $self->_report_component('Registry', $self->_setup_registry($config));
        };
        if ($@) {
            print "  [WARN] Registry setup failed: $@\n";
        }
    }

    # registry.local in CoreDNS.
    #
    # This is the step whose absence made "self-healing on the next ocp apply"
    # untrue: k3s' addon manager restores its own default Corefile whenever it
    # decides the ConfigMap drifted, which silently takes the registry.local
    # record with it. The record is spec, the Corefile is cluster state, and
    # nothing else puts it back — so a cluster whose DNS entry k3s removed
    # stayed broken no matter how often apply ran.
    #
    # Cheap enough for the frequently-run path: one GET, and an apply only when
    # the Corefile actually differs. _corefile_with_host is pure and repairs an
    # already-broken file, so re-running it is free.
    if ($cp_ip) {
        $checked++;
        print "  [..] Checking registry.local DNS...\n";
        eval {
            my $patched = $self->_configure_registry_dns($cp_ip);
            if ($patched) {
                $updated++;
            } else {
                print "  [ok] registry.local DNS up to date\n";
            }
            1;
        } or print "  [WARN] registry.local DNS setup failed: $@";
    }

    # NFD (Node Feature Discovery) — always deployed
    {
        $checked++;
        print "  [..] Checking NFD...\n";
        eval {
            $updated += $self->_report_component('NFD', $self->_setup_nfd($config));
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

    # Cilium Gateway — a plain server-side apply of one Gateway CR, and the
    # entry point for all HTTP(S) traffic. Deleting it is exactly the kind of
    # divergence from spec that reconcile exists to undo.
    {
        $checked++;
        print "  [..] Checking Cilium Gateway...\n";
        eval { $self->_setup_cilium_gateway($config); 1 }
            ? print "  [ok] Cilium Gateway up to date\n"
            : print "  [WARN] Cilium Gateway setup failed: $@";
    }

    # LB-IPAM stays behind the same opt-in as in the deploy path.
    if ($config->lbipam && $cp_ip) {
        $checked++;
        print "  [..] Checking LB-IPAM (opt-in)...\n";
        eval { $self->_setup_lb_ipam($cp_ip); 1 }
            ? print "  [ok] LB-IPAM up to date\n"
            : print "  [WARN] LB-IPAM setup failed: $@";
    }

    # The CR layer: CRDs, provider CRs and the observational control-plane
    # OCPNode. All idempotent ensures, a handful of API calls, no waiting.
    #
    # Without this, a cluster bootstrapped by an older OCP kept an OCPNode with
    # no status forever — `ocp node ls` showed its control plane as Pending
    # with no IP and no amount of `ocp apply` fixed it, because only the
    # fresh-deploy path ever wrote the CR.
    {
        $checked++;
        print "  [..] Checking node CRs...\n";
        eval {
            my $api = $self->_k8s_api;
            $self->_ensure_crds($api);
            $self->_ensure_providers($api, $config, $secrets);
            $self->_migrate_legacy_nodes($api);
            $self->_ensure_cp_ocpnode($api, {
                name     => $cp_name,
                provider => $cp_id->{provider},
                host     => $cp_ip,
            });
            1;
        } or print "  [WARN] node CR reconcile failed: $@";
    }

    # Summary
    print "\n";
    if ($updated) {
        print "  $updated component(s) updated, $checked checked.\n";
    } else {
        print "  All $checked component(s) up to date.\n";
    }

    return { cp_name => $cp_name, cp_ip => $cp_ip };
}

# Run the step a drift entry asks for. Returns true when it ran, false when
# it could not (and says why). Dies only if the step itself fails.
sub _run_remedy {
    my ($self, $config, $entry) = @_;

    my $remedy = $entry->{remedy} or return 0;
    return 0 unless ($remedy->{type} // '') eq 'rex';

    my $key = $config->ssh_private_key_path;
    unless (-f $key) {
        print "  [!!] Needs SSH access to the control plane, but $key is missing.\n";
        print "       Run 'ocp update --component $entry->{component}' instead.\n";
        return 0;
    }

    my $host = $config->cluster_status->{public_ip};
    unless ($host) {
        print "  [!!] No control plane address known, cannot run $remedy->{task}.\n";
        return 0;
    }

    OCP::Rex->new(
        host     => $host,
        key_file => $key,
        verbose  => $self->ocp->verbose,
    )->run_task($remedy->{task}, %{ $remedy->{params} // {} });

    return 1;
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
