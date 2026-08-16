package OCP::Cmd::Apply::Bootstrap;
# ABSTRACT: First-deploy server provisioning and K8s install

use strict;
use warnings;

use OCP::ClusterKey;
use OCP::Config;
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

    # Mutating helper: pick the SSH key the rest of the deploy will use
    # (OCP::ClusterKey decides which), publish its path on the command
    # object and keep the object alive so its temp files outlive the
    # call. Pass admin_key when PIN2 was already entered further up.
    my $key = OCP::Cmd::Apply::Bootstrap::setup_ssh_key($self, $config,
        admin_key => $admin_key,
    );

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

# Pick the SSH key the rest of the deploy will use, and remember it on the
# command object so its temp files live exactly as long as the run that needs
# them.
#
# Which key that is, and why, lives in OCP::ClusterKey — the same question is
# asked by `ocp update`, `ocp node add` and the reconcile path's Rex remedy,
# and four separate answers to it is what karr #87 was. The short version: the
# MODE decides. Secure mode reaches every machine with the admin key, on every
# provider — Hetzner uploads it through the API before the server exists, an
# ssh-provider machine gets it from a human with `ocp keys show --purpose
# admin`. The bootstrap key is dev mode's only key and nothing else's.
#
# OCP::Cmd::Init::_ensure_bootstrap_key is the other half of that contract:
# it creates .ocp/id_ed25519 only under --nopassword.
#
# The result is cached in the slot OCP::Role::Cmd::cluster_ssh_key uses, so a
# later reconcile step on the same command object reuses this key instead of
# prompting for PIN2 a second time.
sub setup_ssh_key {
    my ($self, $config, %opt) = @_;

    my $key = OCP::ClusterKey->for_config($config, %opt);

    $self->_ssh_key_path($key->path);
    $self->{_cluster_ssh_key}{ OCP::ClusterKey::cache_slot($config, %opt) } = $key;

    return $key;
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

    # no_password_mode is deliberately NOT read here any more. It used to gate
    # the inline key selection below; OCP::ClusterKey derives the same fact
    # from the absence of keys.yaml, which is where every other caller reads
    # it from too. Accepting the option and ignoring it would be the silently
    # swallowed flag this repo keeps having to fix (karr #67, #37, #85), so
    # OCP::Cmd::Apply stops passing it.

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

    # The SSH key first, because the provider needs it too. This used to be
    # picked further down (see the block above the OCP::SSH call below) while
    # the provider was handed $config->ssh_private_key_path unconditionally —
    # .ocp/id_ed25519, which in secure mode is now a file that does not exist
    # on any provider. OCP::Provider::SSH runs its reachability check and its
    # uninstall over that path, so it has to be the same key everything else
    # uses.
    #
    # admin_key is passed through because `ocp apply` already unlocked it with
    # PIN2 further up: prompting again here would be a bug, not extra safety.
    # setup_ssh_key parks the key on $self, so it lives as long as the command
    # object and its temp files go away together with it.
    my $key = setup_ssh_key($self, $config, admin_key => $admin_key);
    my $ssh_key_path = $key->path;

    # Initialize provider
    my $prov = OCP::Provider->for_spec($first_cp,
        token        => $hetzner_token,
        cluster_name => $config->name,
        ssh_key_path => $ssh_key_path,
        verbose      => $verbose,
    );

    print "Deploying control plane: $cp_name\n";

    # Create server via provider
    my $cp_host;
    my $cp_ip;

    print "  [..] Provisioning server ($provider)...\n";

    # Upload SSH key (Hetzner uploads to cloud, SSH/Local is no-op).
    #
    # The name is derived, not spelled out here: the worker path has to
    # reference this exact key later, and it reads the name off the
    # OCPNodeProvider CR that OCP::Cmd::Apply::CR writes from the same
    # derivation. One source, so the two paths cannot drift (karr #92).
    my $key_name = $config->admin_ssh_key_name;
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
        # Takes the module's default; naming our own 120 used to silently
        # disagree with what workers spent (karr #112).
        $prov->wait_for_running($server_info);
        print "  [ok] Server running: $server_info->{ip}\n";
    } else {
        print "  [ok] Using existing server: $server_info->{ip}\n";
    }

    $cp_ip = $server_info->{ip};
    $cp_host = $cp_ip;

    # Wait for SSH
    print "  [..] Waiting for SSH to be ready...\n";

    # The key was picked before the provider (Rex needs both private + .pub,
    # and the provider needs the same file). It used to be picked here, in a
    # second inline copy of setup_ssh_key with one fatal difference: it held
    # the File::Temp object in a lexical of THIS sub and returned only
    # ssh_key_path. For secure mode + Hetzner that meant the admin key was
    # unlinked the moment bootstrap_control_plane returned, and the caller —
    # OCP::Cmd::Apply::Deploy, which slurps that path to hand OCP::Node an
    # ssh_key for every worker — got a path to a file that no longer existed.
    # Workers then failed as "Could not read join token from CP". The .pub
    # written next to it had no owner at all and stayed in /tmp forever.
    my $ssh = OCP::SSH->new(
        host     => $cp_host,
        key_file => $ssh_key_path,
        user     => 'root',
    );

    # The 120s this has always spent, now taken from $OCP::SSH::WAIT_TIMEOUT
    # rather than restated here -- OCP::Node does the same wait on a worker and
    # had drifted to half of it (karr #109).
    eval { $ssh->wait_for_ssh };
    if ($@) {
        # The one failure that is usually not a network problem: an existing
        # ssh-provider machine that only ever had the bootstrap key
        # authorised. migration_hint says so when the evidence is there and
        # stays quiet otherwise — there is deliberately no fallback to that
        # key (ADR: two tiers, robo and admin, nothing else).
        die "  [FAIL] SSH not ready: $@" . $key->migration_hint . "\n";
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
            $self->wait_seconds(10);
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

L<OCP::Cmd::Apply>, L<OCP::ClusterKey>, L<OCP::Provider>, L<OCP::Rex>,
L<OCP::SSH>, L<OCP::Versions>.

=cut
