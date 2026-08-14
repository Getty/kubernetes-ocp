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


use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::DeployedHash;
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
