package OCP::Cmd::Apply::Drift;
# ABSTRACT: Reconcile existing clusters against the spec

use strict;
use warnings;

use OCP::Drift;
use OCP::Rex;
use OCP::Secrets;
use OCP::Versions;

=head1 SYNOPSIS

    my $result = OCP::Cmd::Apply::Drift::reconcile_components($apply, $config);
    my $ran    = OCP::Cmd::Apply::Drift::run_remedy($apply, $config, $entry);

=head1 DESCRIPTION

The "cluster already exists" branch of `ocp apply`: read the kubeconfig, run
OCP::Drift, then walk every component the deploy path owns and undo any
drift that has a remedy. Cluster-truth checks are unchanged from the deploy
path; the only structural difference is which steps we tolerate leaving
out (server provisioning, control-plane install, robocop rollout, long
waits) — those are one-time, not convergence.

The shape of reconcile is forced by t/38 in OCP::Cmd::Apply::Drift's
source: it regex-extraps _reconcile_components and checks the body for
the steps it must run (_configure_registry_dns, _ensure_cp_ocpnode,
_setup_cilium_gateway, _setup_lb_ipam, ...) and the steps it must NOT
(_drive_workers, install_server, reconcile_until_ready). Moving the
function but not the body would be a regression.

L<OCP::Cmd::Apply> re-exports both helpers as thin forwarders so the
existing test surface (t/20, t/38) keeps working.

=cut

sub reconcile_components {
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
sub run_remedy {
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

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::Drift>, L<OCP::Rex>.

=cut
