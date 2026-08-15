package OCP::Cmd::Apply::Bootstrap;
# ABSTRACT: First-deploy server provisioning and K8s install

use strict;
use warnings;

use File::Temp;
use Path::Tiny qw(path);

use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Provider;
use OCP::Rex;
use OCP::Secrets;
use OCP::SSH;
use OCP::Versions;

=head1 SYNOPSIS

    # One call: provision server, install K8s, wait for the node to be
    # Ready (Cilium CNI up), save the kubeconfig. Returns the K8s api
    # handle for the component deploy steps that follow.
    my $api = OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
        $self, $config, $secrets,
        admin_key      => $admin_key,
        ssh_public_key => $ssh_public_key,
        verbose        => $self->ocp->verbose,
    );

    # Pure identity helpers — same answer as the deploy path needs to
    # write a control-plane OCPNode CR for a cluster this OCP did not
    # bootstrap itself.
    my $cp_id = OCP::Cmd::Apply::Bootstrap::cp_identity($config);
    my $label = OCP::Cmd::Apply::Bootstrap::dist_label($distribution);

    # Mutating helper: pick the SSH key path the rest of the deploy
    # will use, prompt PIN2 if secure mode, drop a temp admin-key file
    # otherwise. Same rules as the original _setup_ssh_key.
    OCP::Cmd::Apply::Bootstrap::setup_ssh_key($self, $config);

=head1 DESCRIPTION

The first-deploy half of `ocp apply`: pick the right SSH key, ask the
provider for a control-plane server, install RKE2/K3s via Rex, save the
kubeconfig, and wait for the node to be Ready. Everything past that
(registry, NFD, GPU operator, cert-manager, Cilium Gateway, LB-IPAM,
workers) lives in the other phase modules and is wired up by
OCP::Cmd::Apply::execute.

Splitting this out of execute() serves two purposes:

=over

=item *

One cohesive operation becomes one callable name. t/38's reconcile-path
tests can stay narrow: the reconcile path never reaches provision /
install / wait-ready, and the deploy path always does.

=item *

The "the wrong distribution was installed" regression (see the comment
on OCP::Versions in execute) is local to one place that has to answer
the same question as Drift and Node.

=back

The identity helpers (cp_identity, dist_label) live here too — they
are spec-shaped, not state-shaped, so they belong with the deploy
helpers rather than with the reconcile path.

=cut

# Spec-shaped helper: the deploy path and the reconcile path have to
# agree on the name of the control plane (and its hostname/domain) so
# that the OCPNode CR for a cluster this OCP did not bootstrap itself
# can still be addressed.
sub cp_identity {
    my ($config) = @_;

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

# Display name for a distribution id. Apply hardcoded "RKE2" in its
# progress lines, so a `dist: k3s` cluster was announced as "Installing
# RKE2 server..." while install_k3s_server was the task actually
# running.
sub dist_label {
    my ($dist) = @_;
    $dist //= '';
    return { rke2 => 'RKE2', k3s => 'K3s' }->{ lc $dist } // uc $dist;
}

# Pick the SSH key the rest of the deploy will use. Dev mode / SSH
# provider: the bootstrap key in .ocp/id_ed25519. Secure mode +
# Hetzner: drop the admin-key into a temp file so Rex can read it; the
# public half gets written alongside because Rex expects key_file.pub.
#
# The split follows who owns the machine. Hetzner servers are created
# here, so OCP uploads the admin public key via the API before the
# server exists and can rely on it being there. An ssh-provider machine
# is pre-existing: the only key it trusts is the one the operator put
# into authorized_keys by hand, which is the bootstrap key. That is why
# `provider eq 'ssh'` overrides the mode rather than following it.
#
# OCP::Cmd::Init::_ensure_bootstrap_key is the other half of this
# contract — it creates .ocp/id_ed25519 in BOTH modes. It used to create
# it only under --nopassword, so this branch reached for a file that a
# secure-mode project never had, and apply failed as "SSH not reachable".
sub setup_ssh_key {
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

# The whole first-deploy sequence: provision, install, kubeconfig,
# wait-Ready. Returns the Kubernetes api handle plus the control-plane
# identity the caller needs to write the OCPNode CR afterwards.
#
# This is the call site that used to be 240 lines of inline Perl in
# execute(). Splitting it does not change behaviour — same provider
# dispatch, same Rex task, same wait loop — but the entry point gets
# one name that tests can reason about.
sub bootstrap_control_plane {
    my ($self, $config, $secrets, %opts) = @_;

    my $admin_key      = $opts{admin_key}      or die "bootstrap_control_plane: admin_key is required";
    my $ssh_public_key = $opts{ssh_public_key} // $admin_key->{public};
    my $verbose        = $opts{verbose};
    my $no_password_mode = $opts{no_password_mode};

    # Resolve control plane identity (RoboCop naming for Hetzner, host
    # label for SSH).
    my $cp_id        = cp_identity($config);
    my $cp_name      = $cp_id->{name};
    my $cp_hostname  = $cp_id->{hostname};
    my $cp_domain    = $cp_id->{domain};

    my $hetzner_token = $secrets->hetzner_token;
    my $cps = $config->control_planes;
    my $first_cp = $cps->[0] // {};
    my $provider = $first_cp->{provider} // 'hetzner';

    # Initialize provider
    my $prov = OCP::Provider->for_spec($first_cp,
        token        => $hetzner_token,
        cluster_name => $config->name,
        ssh_key_path => $config->ssh_private_key_path,
        verbose      => $verbose,
    );

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
    my $dist_label   = dist_label($distribution);

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

    return {
        api       => $api,
        cp_name   => $cp_name,
        cp_hostname => $cp_hostname,
        cp_domain => $cp_domain,
        cp_ip     => $cp_ip,
        provider  => $provider,
        ssh_key_path => $ssh_key_path,
    };
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::Provider>, L<OCP::Rex>, L<OCP::SSH>,
L<OCP::Versions>.

=cut
