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
    OCP::Cmd::Apply::Drift::dry_run_report($apply, $config);   # --dry-run

=head1 DESCRIPTION

The "cluster already exists" branch of `ocp apply`: read the kubeconfig, run
OCP::Drift, then walk every component the deploy path owns and undo any
drift that has a remedy. Cluster-truth checks are unchanged from the deploy
path; the only structural difference is which steps we tolerate leaving
out (server provisioning, control-plane install, robocop rollout, long
waits) — those are one-time, not convergence.

Under C<--dry-run> the walk is replaced by C<dry_run_report>: the detector
runs, its findings are printed, and not one write leaves the process.
C<reconcile_components> then returns false, which is how the dispatcher
knows to stop without stamping a version.

C<run_remedy> is the only step here that leaves the process over SSH, and
therefore the only one that can cost a PIN2 prompt (see L<OCP::ClusterKey>).
It asks for the key at the point of use rather than up front, so a reconcile
that finds nothing to repair — the common case — never prompts, and neither
does the read-only dry run, which returns before this point. When no key can
be had, the remedy is declined out loud and counted as unresolved: the
closing summary then says the run did not bring the cluster back to spec
rather than "all components up to date".

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

    # --dry-run stops here. Everything below this line writes — see
    # dry_run_report for why that is the whole list and what it costs.
    return dry_run_report($self, $config) if $self->dry_run;

    my $updated = 0;
    my $checked = 0;

    # Drift entries this run named a repair for and did not carry out. Kept
    # apart from $updated because the closing summary has to be able to tell
    # "nothing was wrong" from "something was wrong and is still wrong" —
    # printing "All N component(s) up to date" over a Rex task that declined
    # to run is the same class of untruth as #43/#46, where a step that never
    # looked reported success.
    my @unresolved;

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
                # Missing components are deployed by the checks below, and a
                # self-healing entry is one whose manifest this very run
                # re-applies — a GPU-stack version bump lands in the generated
                # manifest, so the hash changes and the component rolls out
                # two blocks further down. Only what neither covers
                # (distribution upgrades, moved IPs) needs a human.
                print "        No automatic step for this — see 'ocp update'\n"
                    unless $entry->{kind} eq 'missing' || $entry->{self_healing};
                next;
            }

            print "  [..] Running $entry->{remedy}{task}...\n";
            my $done = eval { $self->_run_remedy($config, $entry) };
            if ($@) {
                print "  [WARN] $entry->{remedy}{task} failed: $@";
                push @unresolved, $entry->{label} // $entry->{component};
            } elsif ($done) {
                print "  [ok] $entry->{label} updated to $entry->{expected}\n";
                $updated++;
            } else {
                # _run_remedy has already said why. What it cannot do is stop
                # the summary below from speaking for the whole run.
                push @unresolved, $entry->{label} // $entry->{component};
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
            # Same rule as registry and NFD above: the deploy step decides
            # what happened, this only says it. Reading the hash file before
            # and after and diffing the two was a second judge with less
            # evidence — it never saw an operator that had gone missing from
            # the cluster and was put back at an unchanged hash, and called
            # that "up to date". 'skipped' is the fifth answer, for the
            # cluster this component is not part of.
            $updated += $self->_report_component('GPU Operator',
                $self->_setup_gpu_operator($config));
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
    } elsif (@unresolved) {
        print "  $checked component(s) checked, none updated.\n";
    } else {
        print "  All $checked component(s) up to date.\n";
    }

    if (@unresolved) {
        print "  " . scalar(@unresolved)
            . " known difference(s) left as they were: "
            . join(', ', @unresolved) . ".\n";
        print "  This run did NOT bring the cluster back to spec.\n";
    }

    return { cp_name => $cp_name, cp_ip => $cp_ip };
}

# `ocp apply --dry-run` against a cluster that already exists.
#
# The flag used to be read in exactly one place — the bootstrap path, behind
# the `cluster_exists` branch — so a reconcile ran every write a real run
# runs. Measured on cortex, that is: the registry manifest, the CoreDNS
# Corefile, the NFD bundle, the GPU operator, cert-manager plus its issuers,
# the Cilium Gateway, the LB-IPAM pool and L2 policy, the CRDs, the provider
# CRs and Secrets, the control-plane OCPNode — and, before all of them,
# whatever Rex task a drift entry asked for, over SSH, on the control plane.
# Nothing came of it, but only because those writes are idempotent. The flag
# had no part in it, and `ocp apply --dry-run` is precisely the command a
# user types when they are not sure that holds.
#
# What runs instead is read-only: OCP::Drift is a detector by contract (its
# own POD says so — "Detection is read-only"), and nothing else is called.
# That is also why a dry run returns short of OCP::Cmd::Apply::Health::finish:
# the health gate only reads the cluster, but it stamps status.ocpVersion on
# its way out, and a run that changed nothing must not claim a version.
#
# What this can see is what the detector can name: component versions, the
# registry.local record, addresses that moved away from the spec. What it
# cannot see is a manifest that changed while its version stayed put — the
# only place that knows is the deploy step, and asking it means deploying.
# Printed as a caveat rather than left for the user to find out.
sub dry_run_report {
    my ($self, $config) = @_;

    print "  [..] Checking for drift (read-only)...\n";

    my $drift = OCP::Drift->new(
        config => $config,
        api    => $self->_k8s_api,
    )->detect;

    print "  [ok] No drift detected\n" unless @$drift;

    for my $entry (@$drift) {
        print "  [drift] $entry->{message}\n";
        print "          would run $entry->{remedy}{task}\n" if $entry->{remedy};
    }

    print "\n";
    print '  ', scalar @$drift, " difference(s) a real run would act on.\n";
    print "  It would also re-apply any component whose manifest changed at an\n";
    print "  unchanged version — the one difference a read-only pass cannot see.\n";
    print "\n";
    print "[Dry run - no changes made]\n";

    return;
}

# Run the step a drift entry asks for. Returns true when it ran, false when
# it could not (and says why). Dies only if the step itself fails.
#
# The key lookup is late on purpose. This is the one write on the reconcile
# path that goes over SSH, and on a secure-mode Hetzner cluster obtaining the
# key OCP put on those machines costs a PIN2 prompt (OCP::ClusterKey, ADR
# 0006). Asking for it up front would put a password prompt in front of every
# `ocp apply` against an existing cluster — including the overwhelmingly
# common case where nothing has drifted and no Rex task runs at all. Asking
# for it here means the prompt appears exactly when a task is about to run,
# and `ocp apply --dry-run` (which returns before this function) still never
# prompts.
#
# It used to read $config->ssh_private_key_path directly, which on a Hetzner
# control plane names a file that was never distributed to the machine and,
# in secure mode, is not even created — so this always took the "missing"
# branch and no drift with a Rex remedy could ever be repaired there. karr #87.
sub run_remedy {
    my ($self, $config, $entry) = @_;

    my $remedy = $entry->{remedy} or return 0;
    return 0 unless ($remedy->{type} // '') eq 'rex';

    my $host = $config->cluster_status->{public_ip};
    unless ($host) {
        print "  [!!] No control plane address known, cannot run $remedy->{task}.\n";
        return 0;
    }

    # Declining is a reported outcome, never an exception: one unrepairable
    # entry must not take the rest of the reconcile with it. Two things must
    # not happen either — declining quietly (reconcile_components counts what
    # this returns into its closing verdict) and blocking on a PIN2 prompt in
    # a run with no terminal, which OCP::ClusterKey turns into this same
    # decline rather than a hidden wait.
    my $key = eval { $self->cluster_ssh_key($config, reason => 'ocp apply') };
    unless ($key) {
        my $why = $@ || "no usable SSH key for the control plane\n";
        $why =~ s/\s+\z//;

        my $what = $entry->{label} // $entry->{component} // 'this component';
        print "  [!!] $remedy->{task} needs SSH access to the control plane and\n";
        print "       could not get a key for it. NOT run: $what stays as it is.\n";
        print "       $_\n" for split /\n/, $why;
        print "       Run 'ocp update --component $entry->{component}' instead.\n"
            if defined $entry->{component};
        return 0;
    }

    OCP::Rex->new(
        host     => $host,
        key_file => $key->path,
        verbose  => $self->ocp->verbose,
    )->run_task($remedy->{task}, %{ $remedy->{params} // {} });

    return 1;
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::ClusterKey>, L<OCP::Drift>, L<OCP::Rex>.

=cut
