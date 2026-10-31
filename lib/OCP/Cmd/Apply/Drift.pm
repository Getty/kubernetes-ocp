package OCP::Cmd::Apply::Drift;
# ABSTRACT: Reconcile existing clusters against the spec

use strict;
use warnings;

use OCP::Cmd::Apply::AMDGPU ();
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Deploy;
use OCP::Cmd::Apply::K8s ();
use OCP::Cmd::Apply::Network;
use OCP::Cmd::Apply::Workloads ();
use OCP::Drift;
use OCP::Rex;
use OCP::Secrets;
use OCP::Versions;

=head1 SYNOPSIS

    my $result = OCP::Cmd::Apply::Drift::reconcile_components($apply, $config);
    my $ran    = OCP::Cmd::Apply::Drift::run_remedy($apply, $config, $entry);
    OCP::Cmd::Apply::Drift::dry_run_report($apply, $config, $cp_ip, $secrets);   # --dry-run

=head1 DESCRIPTION

The "cluster already exists" branch of `ocp apply`: read the kubeconfig, run
OCP::Drift, then walk every component the deploy path owns and undo any
drift that has a remedy. Cluster-truth checks are unchanged from the deploy
path; the only structural difference is which steps we tolerate leaving
out (control-plane install and the other one-time bootstrap steps).

Workers are converged the way the OCPNode layer defines them: the OCPNode is
the reflection of desired state and goes hand in hand with the k8s Node. A
worker listed in F<ocp.yaml> that has no OCPNode is created on this path
too, through L<OCP::Cmd::Apply::Deploy/worker_step> — the same CR-driven
step the fresh deploy runs (Pending OCPNode, driven by robocop when it is
ready, from the CLI otherwise). Workers that already have an OCPNode are never
driven from here, whatever their phase: that would re-provision machines
and wait on each of them on every apply. When nothing is missing, the whole
worker check is one OCPNode list — no robocop wait, no SSH key, no PIN2
prompt. C<--only control-planes> skips it, as it skips the worker step of
the fresh deploy; C<--dry-run> names the workers it would create and
creates none.

robocop is made sure of on every reconcile when C<robocop.enabled> is set,
whether or not a worker is missing or listed (k173), through
L<OCP::Cmd::Apply::Deploy/robocop_step>: its credentials Secret is written
when missing or outdated, its Deployment re-applied. A current Secret costs no
SSH read and no PIN2. It sits behind the same C<--only> gate as the workers,
and C<--dry-run> names a missing or outdated Secret and a missing Deployment
without writing either. Disabling robocop does not remove it.

Under C<--dry-run> the walk is replaced by C<dry_run_report>: the detector
runs, its findings are printed, and not one write leaves the process.
NFD or the GPU Operator running another image than its pin is followed by
C<would re-apply the NFD manifest> (or the GPU Operator's, under
C<gpu.enabled>): their steps read the image as the probe does and re-apply
at an unchanged hash too (k351).
C<reconcile_components> then returns false, which is how the dispatcher
knows to stop without stamping a version.

On a secure-mode clone without F<.ocp/> the dry run writes no project key
(k349): PIN1 opens F<age.key.enc> into memory
(L<OCP::Secrets/unlock_age_key>) instead of F<.ocp/age.key>, and the
kubeconfig and the robo key for the robocop check are read with that key.
F<.ocp/age.pub> is not restored either, on a checkout that has the key on
disk too. The host probes read the robo key with it as well.

The host probes of a dry run record no host key (k374). They contact only a
machine whose key F<.ocp/known_hosts> holds already, and check it against
that key as a real run does; a key that no longer matches is said on STDERR.
A machine not recorded yet -- every one, on a fresh clone -- is skipped
without a connection, since its first contact would record the key, and the
C<[WARN] host probes skipped> line says so.

A drift probe that L<OCP::Drift> could not read (an RBAC denial, an
apiserver 5xx, anything but a 404) comes back as an entry with
C<< kind =E<gt> 'error' >>: no remedy, drift unknown, and a message that names
the object and the cause. The detector has already carped that cause to
STDERR. C<reconcile_components> prints the entry as
C<[drift] could not be checked: MESSAGE> and does not send anyone to
C<ocp update> over it. It counts the entry as unresolved
(C<LABEL drift check>), so the run ends incomplete and non-zero instead of
"All N component(s) up to date" (k267). C<dry_run_report> prints the same
line and counts these entries apart from the differences a real run would act
on and from the ones it only reports, as "could not be checked -- a real run
would not complete until it can be read".

C<gpu_dry_run> covers the GPU step the same way, read-only. It reads the GPU
Operator's Deployment, then compares its ClusterPolicy against the spec, and
outside quiet mode reads the ClusterPolicy again for the C<gpu.toolkit>
warning. It returns entries of the same shape: one C<< kind =E<gt> 'spec' >>
entry per ClusterPolicy path that differs, and one C<< kind =E<gt> 'error' >>
entry for each read that failed with anything but a 404 (k276). A 404 is an
answer: no operator finds nothing; no ClusterPolicy while the operator runs
is one C<spec> entry for the whole spec (k277). Any other failure
is neither a finding nor the absence of one: it is printed as "could not be
checked" with its cause, the cause goes to STDERR once, and both apply paths
count it the way they count an unreadable drift probe. When the ClusterPolicy
could not be read, it is not read a second time for the warning. The real run
asks C<gpu_dry_run> before it prints "No drift detected" (k234), so a GPU read
that failed holds that line back as well.

The AMD GPU stack is covered by L<OCP::Cmd::Apply::AMDGPU/dry_run>, from
the plan its step acts on (k261): per component, what a real run would
deploy, update or remove and on which nodes, with no call into
Rex::Rancher::K8s and no write to F<.ocp/deployed.yaml>. A component a drift
entry already names is not counted a second time.

C<run_remedy> is the only step here that leaves the process over SSH, and
therefore the only one that can cost a PIN2 prompt (see L<OCP::ClusterKey>).
It asks for the key at the point of use rather than up front, so a reconcile
that finds nothing to repair — the common case — never prompts, and neither
does the read-only dry run, which returns before this point. When no key can
be had, the remedy is declined out loud and counted as unresolved: the
closing summary then says the run did not bring the cluster back to spec
rather than "all components up to date".

The shape of reconcile is forced by t/38 in OCP::Cmd::Apply::Drift's
source: it regex-extracts reconcile_components and checks the body for
the steps it must run (_configure_registry_dns, _ensure_cp_ocpnode,
_setup_cilium_gateway, _setup_lb_ipam, ...) and the one it must NOT
(install_server). Moving the function but not the body would be a
regression. The worker behaviour — missing workers are created, existing
ones left alone, nothing at all when none is missing — is asserted by
running the path against a fake API in the same test (k26), not by the
source regex that used to forbid _drive_workers here.

L<OCP::Cmd::Apply> re-exports both helpers as thin forwarders so the
existing test surface (t/20, t/38) keeps working.

=cut

sub reconcile_components {
    my ($self, $config) = @_;

    # Read the kubeconfig from the encrypted store — never from a plaintext
    # copy lying around in the project directory.
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    # A dry run on a clone has no .ocp/age.key: PIN1 opens age.key.enc into
    # memory, and every read of this run takes the key from $secrets (k349).
    # With the key on disk already this asks nothing. A real run is unchanged.
    $secrets->unlock_age_key if $self->dry_run && $secrets->has_age_key_enc;
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
    return dry_run_report($self, $config, $cp_ip, $secrets) if $self->dry_run;

    my $updated = 0;
    my $checked = 0;

    # Drift entries this run named a repair for and did not carry out. Kept
    # apart from $updated because the closing summary has to be able to tell
    # "nothing was wrong" from "something was wrong and is still wrong" —
    # printing "All N component(s) up to date" over a Rex task that declined
    # to run is the same class of untruth as k43/k46, where a step that never
    # looked reported success.
    my @unresolved;

    # Drift: compare the running cluster against the version manifest and
    # ocp.yaml, then run whatever step brings it back.
    {
        $checked++;
        print "  [..] Checking for drift...\n";

        my $detector = OCP::Drift->new(
            config     => $config,
            api        => $self->_k8s_api,
            rex_prober => $self->rex_prober($config),
        );
        my $drift = $detector->detect;
        print $self->host_probe_warning($detector);

        # The ClusterPolicy is checked by the GPU step further down, but a
        # run that says "No drift detected" and then names a drift tells two
        # stories (k234): asked here, read-only, before the line is printed.
        # A read it could not make is no "no drift" either (k276): said and
        # counted like a probe OCP::Drift could not read, the cause on
        # STDERR -- the dry run tells the operator this run would not
        # complete over it.
        my @gpu = @$drift ? () : gpu_dry_run($self, $config, quiet => 1);
        for my $g (@gpu) {
            if ($g->{kind} eq 'error') {
                _say_unchecked($g);
                push @unresolved, "$g->{label} drift check";
                next;
            }
            print "  [drift] $g->{message}\n"
                . "          the GPU Operator check below re-applies the manifest\n";
        }
        print "  [ok] No drift detected\n" unless @$drift || @gpu;

        for my $entry (@$drift) {
            # A probe OCP::Drift could not read (k119, k256) found no drift:
            # nothing is known about what it names, so there is no step to
            # advise and no "up to date" to claim (k267). Said here on STDOUT
            # with its message, which carries the cause -- OCP::Drift has
            # already carped that to STDERR -- and counted for the exit.
            if (($entry->{kind} // '') eq 'error') {
                print "  [drift] could not be checked: $entry->{message}\n";
                push @unresolved, ($entry->{label} // $entry->{component}) . ' drift check';
                next;
            }

            print "  [drift] $entry->{message}\n";

            unless ($entry->{remedy}) {
                # Missing components are deployed by the checks below, and a
                # self-healing entry is one whose manifest this very run
                # re-applies — a GPU-stack version bump lands in the generated
                # manifest, so the hash changes and the component rolls out
                # two blocks further down. Only what neither covers
                # (distribution upgrades, moved IPs) needs a human.
                if ($entry->{manual_step}) {
                    print "        $entry->{manual_step}\n";
                }
                else {
                    print "        No automatic step for this — see 'ocp update'\n"
                        unless $entry->{kind} eq 'missing' || $entry->{self_healing};
                }
                next;
            }

            # An API remedy is no Rex task on a node (k198): naming its
            # handler as something "running" would tell the operator
            # otherwise. The wording matches ocp update's "via the cluster API".
            my $via_api = ($entry->{remedy}{type} // 'rex') eq 'api';
            print $via_api
                ? "  [..] Updating $entry->{label} via the cluster API...\n"
                : "  [..] Running $entry->{remedy}{task}...\n";
            my $done = eval { $self->_run_remedy($config, $entry) };
            if ($@) {
                # A repair that failed leaves the drift in place and the run
                # unfinished (k226): said on STDERR, in the [!!] style.
                print STDERR $via_api
                    ? "  [!!] $entry->{label} update via the cluster API failed: $@"
                    : "  [!!] $entry->{remedy}{task} failed: $@";
                push @unresolved, $entry->{label} // $entry->{component};
            } elsif ($done) {
                if (($entry->{kind} // '') eq 'rex_probe') {
                    # A host-side residue has no version to be "updated to"
                    # (it printed an empty target, k234): it was removed on a
                    # host, and the task said whether it restarted a service.
                    my ($svc) = map { /^Restarted (\S+?):/ ? $1 : () }
                        @{ $entry->{result}{steps} // [] };
                    print "  [ok] $entry->{label} removed on $entry->{host}"
                        . (defined $svc ? ", $svc restarted" : '') . "\n";
                }
                else {
                    print "  [ok] $entry->{label} updated to $entry->{expected}\n";
                }
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
            # The registry is required infrastructure ("MUST succeed" in the
            # deploy path: every image pull goes through it), so a failure is
            # an unfinished apply like cert-manager and the Gateway (k234).
            print STDERR "  [!!] Registry setup failed: $@";
            print STDERR "\n" unless $@ =~ /\n\z/;
            push @unresolved, 'Registry';
            push @{ $self->{_failed_components} }, 'Registry';
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
        } or do {
            # STDERR with its cause (k278); not counted -- registry.local
            # names the local registry, the pull-through cache works without.
            my $err = $@;
            $err .= "\n" unless $err =~ /\n\z/;
            print STDERR "  [WARN] registry.local DNS setup failed: $err";
        };
    }

    # NFD (Node Feature Discovery) — always deployed
    {
        $checked++;
        print "  [..] Checking NFD...\n";
        eval {
            $updated += $self->_report_component('NFD', $self->_setup_nfd($config));
        };
        if (my $err = $@) {
            # STDERR with its cause (k278).
            $err .= "\n" unless $err =~ /\n\z/;
            print STDERR "  [WARN] NFD setup failed: $err";
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
            # cluster this component is not part of. With it comes why an
            # update was made, when the image ran off its pin (k351).
            my ($outcome, $changed) = $self->_setup_gpu_operator($config);
            $updated += $self->_report_component('GPU Operator', $outcome, $changed);
            # Checked again after the worker join (k228 after skipped, k287
            # for an NVIDIA worker after a check that ran).
            $self->{_gpu_outcome} = $outcome;
        };
        if ($@) {
            print STDERR "  [!!] GPU Operator setup failed: $@";
            push @unresolved, 'GPU Operator';
            push @{ $self->{_failed_components} }, 'GPU Operator';
        }
    }

    # AMD GPU stack (only on nodes with the AMD marker, k251). The step
    # reports each component itself and never dies; what failed is
    # unresolved, which the summary below counts for the exit.
    {
        $checked++;
        print "  [..] Checking AMD GPU stack...\n";
        my $amd = OCP::Cmd::Apply::AMDGPU::step($self, $config);
        $updated += $amd->{changed};
        push @unresolved, @{ $amd->{failed} };
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

            # Equality, not presence: OCP::Drift catches a running image that
            # drifted from OCP::Versions, but this gate is the one that catches a
            # versions bump that has not reached the cluster yet. Mirrors the
            # shape registry, NFD and the GPU operator use — recorded version
            # compared against the live one, with the cluster asked to confirm.
            if ($cm_running
                && ($deployed->{certmanager} // '') eq OCP::Versions->get_component_version('cert_manager')) {
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
            # "MUST succeed" in the deploy path: said on STDERR and counted (k231).
            print STDERR "  [!!] cert-manager setup failed: $@";
            print STDERR "\n" unless $@ =~ /\n\z/;
            push @{ $self->{_failed_components} }, 'cert-manager';
        }
    }

    # Cilium Gateway — a plain server-side apply of one Gateway CR, and the
    # entry point for all HTTP(S) traffic. Deleting it is exactly the kind of
    # divergence from spec that reconcile exists to undo.
    {
        $checked++;
        print "  [..] Checking Cilium Gateway...\n";
        # The step says whether it created, updated or left the Gateway alone
        # (k300); the [ok] line and the update count follow it (k307). An
        # update is a spec change, in the step's own words (k318).
        eval {
            $updated += $self->_report_component('Cilium Gateway',
                $self->_setup_cilium_gateway($config), 'spec changed');
            1;
        } or do {
            # "MUST succeed" in the deploy path: STDERR and counted (k231).
            print STDERR "  [!!] Cilium Gateway setup failed: $@";
            print STDERR "\n" unless $@ =~ /\n\z/;
            push @{ $self->{_failed_components} }, 'Cilium Gateway';
        };
    }

    # LB-IPAM stays behind the same opt-in as in the deploy path.
    if ($config->lbipam && $cp_ip) {
        $checked++;
        print "  [..] Checking LB-IPAM (opt-in)...\n";
        if (eval { $self->_setup_lb_ipam($cp_ip, $config); 1 }) {
            print "  [ok] LB-IPAM up to date\n";
        } else {
            # An opt-in that is not there: STDERR, with its cause, and the
            # run is not complete (k278) -- a refused pool (k281) is the
            # user's to fix, not something a SUCCESSFULLY banner may hide.
            my $err = $@;
            $err .= "\n" unless $err =~ /\n\z/;
            print STDERR "  [!!] LB-IPAM setup failed: $err";
            push @unresolved, 'LB-IPAM';
        }
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
            # control_planes[0].node_ip as spec.nodeIP (k254): the ensure
            # replaces the spec, so a run that left it out took it off the
            # OCPNode the deploy wrote it to. Nothing installs here, so no
            # handed_node_ip -- status.nodeIP keeps what the bootstrap handed.
            $self->_ensure_cp_ocpnode($api, {
                name     => $cp_name,
                provider => $cp_id->{provider},
                host     => $cp_ip,
                node_ip  => OCP::Cmd::Apply::Bootstrap::cp_node_ip($config),
            });
            1;
        } or do {
            # STDERR with its cause, and not complete (k278): this block is
            # what puts a newer OCPNode/OCPNodeProvider CRD on the cluster
            # (k291), the update `ocp node add --node_ip` sends the user to
            # `ocp apply` for (k290).
            my $err = $@;
            $err .= "\n" unless $err =~ /\n\z/;
            print STDERR "  [!!] node CR reconcile failed: $err";
            push @unresolved, 'node CRs';
        };
    }

    # robocop (k173). `robocop.enabled` means robocop runs, so every reconcile
    # makes sure of it -- whether or not a worker is missing, whether or not
    # ocp.yaml lists one. That is what repairs a cluster left with the
    # Deployment but without its credentials Secret (k169), and what brings
    # robocop to a cluster that enabled it after bootstrap. A current Secret
    # is left alone, so this costs no SSH read and no PIN2; the Deployment is
    # re-applied like every other component here. After the CR block (it
    # needs the CRDs), before the workers (it may drive them), behind the
    # worker gate. Turning robocop off does not remove it -- nothing here
    # tears a component down.
    my $robocop;
    if ($config->robocop_enabled && worker_step_wanted($self)) {
        $checked++;
        print "  [..] Checking robocop...\n";
        $robocop = OCP::Cmd::Apply::Deploy::robocop_step($self, $self->_k8s_api, $config, {
            cp_ip   => $cp_ip,
            secrets => $secrets,
        });
        if ($robocop->{state} eq 'failed') {
            push @unresolved, 'robocop';
        } elsif ($robocop->{changed}) {
            $updated++;
        }
    }

    # Workers (k26). The OCPNode is the reflection of desired state: a worker
    # in ocp.yaml without one is created here, through the same CR-driven
    # step the fresh deploy runs. Workers that have one are left alone —
    # re-driving them would re-provision machines and wait on each. When none
    # is missing this costs one list and nothing else: no robocop wait, no
    # key (robocop itself is the block above). Runs after the CR block, which
    # put the CRDs and provider CRs the new OCPNodes need in place, and gated
    # by --only like Deploy.pm.
    if (@{ $config->workers } && worker_step_wanted($self)) {
        $checked++;
        print "  [..] Checking worker OCPNodes...\n";
        my $api = $self->_k8s_api;
        # A worker that matches an OCPNode only by host is not missing, but
        # it does not match either: missing_worker_ocpnodes says so on STDERR
        # and counts it into {_failed_components} (k211, k231) -- no [ok] over
        # it (k330).
        my $failed_before = @{ $self->{_failed_components} // [] };
        my @missing = eval {
            OCP::Cmd::Apply::CR::missing_worker_ocpnodes($self, $api, $config);
        };
        my $list_err = $@;
        if ($list_err) {
            print STDERR "  [!!] Could not list OCPNodes, workers were not checked: $list_err";
            push @unresolved, 'workers';
        } elsif (!@missing) {
            print "  [ok] Every worker in ocp.yaml has an OCPNode\n"
                if @{ $self->{_failed_components} // [] } == $failed_before;
        } else {
            my @names = map { $_->{metadata}{name} } @missing;
            print "  [..] Creating " . scalar(@names) . " worker(s) without an OCPNode: "
                . join(', ', @names) . "\n";
            my @results = OCP::Cmd::Apply::Deploy::worker_step($self, $api, $config, {
                names        => \@names,
                robocop      => $robocop,
                cp_ip        => $cp_ip,
                secrets      => $secrets,
                ssh_key_path => sub {
                    $self->cluster_ssh_key($config, reason => 'ocp apply')->path;
                },
            });
            for my $r (@results) {
                if ($r->{phase} eq 'Ready') {
                    $updated++;
                } else {
                    push @unresolved, "worker $r->{name}";
                }
            }
            unless (OCP::Cmd::Apply::Deploy::gpu_after_join($self, $config, \@results)) {
                push @unresolved, 'GPU Operator';
                push @{ $self->{_failed_components} }, 'GPU Operator';
            }
            push @unresolved, OCP::Cmd::Apply::AMDGPU::after_join($self, $config, \@results);
        }

        # A worker whose OCPNode exists but is not Ready is said, not waited
        # for, and not re-driven (k234). The ones just created are reported
        # by the worker step.
        unless ($list_err) {
            my %created = map { $_->{metadata}{name} => 1 } @missing;
            eval { OCP::Cmd::Apply::CR::check_worker_phases($self, $api, $config, \%created) };
            if (my $perr = $@) {
                print STDERR "  [!!] Could not check worker phases: $perr";
                push @unresolved, 'worker phases';
            }
        }

        # Pool labels/taints changed in ocp.yaml onto the workers that have an
        # OCPNode (k211): spec.labels/spec.taints only, no re-drive, no key.
        my $meta = eval { OCP::Cmd::Apply::CR::sync_worker_meta($self, $api, $config) };
        if (my $err = $@) {
            print STDERR "  [!!] Could not check worker labels/taints: $err";
            push @unresolved, 'worker labels/taints';
        } else {
            if (@{ $meta->{patched} }) {
                print "  [ok] Worker labels/taints updated: "
                    . join(', ', @{ $meta->{patched} }) . "\n";
                $updated++;
            }
            for my $f (@{ $meta->{failed} }) {
                print STDERR "  [!!] Worker labels/taints not updated: $f\n";
                push @unresolved, 'labels/taints of worker ' . (split /:/, $f, 2)[0];
            }
        }
    }

    # A Failed worker OCPNode that ocp.yaml does not list (made by `ocp node
    # add`, say) is not part of the spec this apply checks: named, not
    # counted for the exit (k231). Also with no workers in ocp.yaml at all.
    if (worker_step_wanted($self)) {
        eval { OCP::Cmd::Apply::CR::warn_unlisted_failed_ocpnodes($self, $self->_k8s_api, $config) };
    }

    # Summary. "All up to date" speaks for every step above, including those
    # that count a failure straight into {_failed_components} instead of
    # @unresolved: cert-manager, the Gateway, a Failed worker (k318).
    print "\n";
    if ($updated) {
        print "  $updated component(s) updated, $checked checked.\n";
    } elsif (@unresolved || @{ $self->{_failed_components} // [] }) {
        print "  $checked component(s) checked, none updated.\n";
    } else {
        print "  All $checked component(s) up to date.\n";
    }

    # What this run left short of spec is an apply that did not complete
    # (k226): it used to be said here on STDOUT -- "This run did NOT bring the
    # cluster back to spec." -- and `ocp apply` exited 0 all the same, a
    # Failed worker included. Every entry is a repair or a step this run tried
    # and that did not take; each has said why on STDERR where it happened.
    # Handed to OCP::Cmd::Apply::Health::finish, the single exit, which
    # names them on STDERR, takes the success banner away and ends non-zero.
    # The GPU Operator is already there (k203), so nothing is named twice.
    if (@unresolved) {
        my %named = map { $_ => 1 } @{ $self->{_failed_components} // [] };
        push @{ $self->{_failed_components} }, grep { !$named{$_}++ } @unresolved;
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
#
# $secrets is the run's OCP::Secrets, the project key unlocked into it on a
# clone (k349); the robocop check and the host probes read the robo key with
# it. The probes contact only a machine whose host key .ocp/known_hosts holds
# already (k374): the first contact with any other records its key there, a
# write. Such a machine is skipped, and the skip line says why.
sub dry_run_report {
    my ($self, $config, $cp_ip, $secrets) = @_;

    print "  [..] Checking for drift (read-only)...\n";

    my $detector = OCP::Drift->new(
        config     => $config,
        api        => $self->_k8s_api,
        rex_prober => $self->rex_prober($config,
            pinned_only => 1, age_key => $secrets && $secrets->age_key),
    );
    my $drift = $detector->detect;
    print $self->host_probe_warning($detector);

    # A probe that could not be read (k119, k256) is neither: nothing is known
    # about it, and a real run ends short of spec over it (k267). robocop's
    # findings are names, its unread Deployment an entry (k319).
    my $is_unknown = sub { ref $_[0] eq 'HASH' && ($_[0]{kind} // '') eq 'error' };
    # An entry with no remedy that the run does not re-apply either (not
    # self_healing, not missing) is report-only -- the pod CIDR (k182): a real
    # run names it and leaves it, so it is not counted as an action (k188).
    my $is_report_only = sub {
        my $e = shift;
        return !$e->{remedy} && !$e->{self_healing} && ($e->{kind} // '') ne 'missing'
            && !$is_unknown->($e);
    };
    # The GPU findings are asked first, silently: "No drift detected" is only
    # true when they find nothing either (k234). They are printed below.
    my @gpu_found = gpu_dry_run($self, $config, quiet => 1);
    print "  [ok] No drift detected\n" unless @$drift || @gpu_found;

    for my $entry (@$drift) {
        if ($is_unknown->($entry)) {
            print "  [drift] could not be checked: $entry->{message}\n";
            next;
        }
        print "  [drift] $entry->{message}\n";
        if ($entry->{remedy}) {
            print +($entry->{remedy}{type} // 'rex') eq 'api'
                ? "          would update $entry->{label} via the cluster API\n"
                : "          would run $entry->{remedy}{task}\n";
        }
        print "          report only, a real run leaves it as it is\n"
            if $is_report_only->($entry);
        # NFD or the GPU Operator off its pin: its step reads the image as the
        # probe does and re-applies the manifest, at an unchanged hash too
        # (k351).
        print "          would re-apply the $entry->{label} manifest\n"
            if OCP::Cmd::Apply::Workloads::reapplies($entry, $config);
    }

    # Workers without an OCPNode (k26): named, not created. The list is the
    # same read the real run makes; nothing past it is reached.
    my @missing;
    if (@{ $config->workers } && worker_step_wanted($self)) {
        @missing = eval {
            OCP::Cmd::Apply::CR::missing_worker_ocpnodes($self, $self->_k8s_api, $config);
        };
        print STDERR "  [!!] Could not list OCPNodes, workers were not checked: $@"
            if $@;
        print "  [workers] $_->{metadata}{name} has no OCPNode\n"
            . "          would create OCPNode/$_->{metadata}{name} and bring the worker up\n"
            for @missing;
    }

    # Pool labels/taints that differ on existing worker OCPNodes (k211).
    my @relabel;
    if (@{ $config->workers } && worker_step_wanted($self)) {
        my $meta = eval {
            OCP::Cmd::Apply::CR::sync_worker_meta($self, $self->_k8s_api, $config, dry_run => 1);
        };
        print STDERR "  [!!] Could not check worker labels/taints: $@" if $@;
        @relabel = @{ $meta ? $meta->{patched} : [] };
        print "  [workers] $_: labels/taints differ from ocp.yaml\n"
            . "          would update labels/taints of OCPNode/$_\n"
            for @relabel;
    }

    # robocop (k173): what the real run's robocop step would write. Reads
    # only -- the credentials check is the same one that keeps a real
    # reconcile PIN2-free.
    my @robocop = $config->robocop_enabled && worker_step_wanted($self)
        ? robocop_dry_run($self, $config, $cp_ip, $secrets)
        : ();

    # The GPU Operator's ClusterPolicy (lab notes 24, 27): its content against
    # the spec, and a gpu.toolkit switch -- both said by the real run's GPU
    # step, so the read-only pass says them too. Only where the operator runs.
    # A read it could not make is counted with the probes that could not be
    # checked (k276).
    my @gpu = gpu_dry_run($self, $config);

    # The AMD GPU stack (k261): what its step would deploy, update or remove,
    # and on which nodes. A component a drift entry already names -- the k250
    # probes read the same DaemonSets -- is that entry's difference, not a
    # second one.
    my %named = map { ($_->{label} // '') => 1 } @$drift;
    my @amd   = grep { !$named{ $_->{label} } } OCP::Cmd::Apply::AMDGPU::dry_run($self, $config);

    my $report_only = scalar grep { $is_report_only->($_) } @$drift;
    my $unknown     = scalar grep { $is_unknown->($_) } @$drift, @gpu, @robocop, @amd;
    my $actions     = scalar(@$drift) + scalar(@gpu) + scalar(@robocop) + scalar(@amd)
        - $report_only - $unknown + scalar(@missing) + scalar(@relabel);

    print "\n";
    print "  $actions difference(s) a real run would act on.\n";
    print "  $report_only more reported only -- a real run leaves "
        . ($report_only == 1 ? 'it as it is' : 'them as they are') . ".\n"
        if $report_only;
    print "  $unknown more could not be checked -- a real run would not complete until "
        . ($unknown == 1 ? "it" : "they") . " can be read.\n"
        if $unknown;
    print "  It would also re-apply any component whose manifest changed at an\n";
    print "  unchanged version — the one difference a read-only pass cannot see.\n";
    print "\n";
    print "[Dry run - no changes made]\n";

    return;
}

# The GPU half of the drift check, read-only: what the GPU step of a real run
# would act on, and only where the operator runs. One entry per ClusterPolicy
# path that differs from the spec, { kind => 'spec', path, message }. The
# gpu.toolkit warning is printed but is no entry of its own (the real run
# only warns as well).
#
# A read that fails with anything but a 404 is no answer (k276). The three
# here -- the operator's Deployment, the ClusterPolicy for its differences,
# the ClusterPolicy again for the warning -- each took one for a false
# answer: no operator, no differences, no ClusterPolicy. Each is now an
# { kind => 'error', label, cause, message } entry, drift unknown, the shape
# of a probe OCP::Drift could not read (k267); the real run's GPU step makes
# the same reads and fails on them. A ClusterPolicy that could not be read is
# not asked for again for the warning: one cause, said once.
#
# quiet: nothing printed, the caller says what was found. Otherwise every
# entry is said here, an error's cause on STDERR.
sub gpu_dry_run {
    my ($self, $config, %opt) = @_;
    return () unless $config->gpu_enabled;
    # No API at all is no cluster to ask; the reconcile has built it by now.
    my $api = eval { $self->_k8s_api } or return ();

    my $unread = sub {
        my ($label, $err) = @_;
        my $cause = "$err";
        chomp $cause;
        my $entry = { kind => 'error', label => $label, cause => $cause,
                      message => "$label: $cause" };
        _say_unchecked($entry) unless $opt{quiet};
        return $entry;
    };

    my $running = eval { $self->_resource_exists($api, 'Deployment', 'gpu-operator',
        namespace => 'gpu-operator') };
    return $unread->('GPU Operator', $@) if $@;
    return () unless $running;

    my @paths = eval {
        OCP::Cmd::Apply::Workloads::cluster_policy_differences($self, $config, $api)
    };
    return $unread->('GPU Operator ClusterPolicy', $@) if $@;
    my @found = map { +{ kind => 'spec', path => $_,
        message => 'GPU Operator ' . OCP::Cmd::Apply::Workloads::cluster_policy_difference($_) } } @paths;
    return @found if $opt{quiet};
    print "  [drift] $_->{message}\n"
        . "          would re-apply the GPU Operator manifest\n" for @found;

    my $cp = eval { $self->_crd_get($api, '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy') };
    return (@found, $unread->('gpu.toolkit switch', $@)) if $@;
    my $warning = OCP::Cmd::Apply::Workloads::toolkit_switch_warning($cp, $config->gpu_toolkit);
    print $warning if $warning;
    return @found;
}

# A GPU read gpu_dry_run could not make (k276), said the way an unreadable
# drift probe is (k267): "could not be checked" on STDOUT, the cause on STDERR.
sub _say_unchecked {
    my ($entry) = @_;
    print "  [drift] could not be checked: $entry->{message}\n";
    print STDERR "  [!!] $entry->{label} not checked: $entry->{cause}\n";
    return;
}

# The robocop half of the dry run: prints what robocop_step would write and
# returns one entry per difference. A Deployment that is there is not
# compared -- a real run re-applies it anyway, like every other manifest.
# Only a 404 is a Deployment missing; a read that fails otherwise is an
# { kind => 'error' } entry, "could not be checked" with its cause on STDERR
# (k319), the shape of a GPU read gpu_dry_run could not make (k276).
#
# $secrets (optional) is the run's, unlocked into memory on a clone (k349):
# the robo key is read with it, and read_only keeps the state from caching
# the project key or restoring .ocp/age.pub.
sub robocop_dry_run {
    my ($self, $config, $cp_ip, $secrets) = @_;
    my $api   = $self->_k8s_api;
    my $level = $config->robocop_security_level;
    my @found;

    # The Secret the same way (k329): a read that is no 404 dies in the
    # state, and is no "missing, would write it".
    my $secret = eval {
        $self->_robocop_credentials_state($api, $config, $secrets, $level,
            host => $cp_ip, read_only => 1);
    };
    if (my $err = $@) {
        chomp(my $cause = $err);
        print "  [robocop] Secret/robocop-credentials could not be checked\n";
        print STDERR "  [!!] Secret/robocop-credentials not checked: $cause\n";
        push @found, { kind => 'error', label => 'Secret/robocop-credentials', cause => $cause,
                       message => "Secret/robocop-credentials: $cause" };
    } elsif ($secret eq 'unreadable') {
        # k216: an operator's identity cannot read the robo key to compare,
        # and a real run leaves the Secret as it is (with a warning).
        print "  [robocop] Secret/robocop-credentials cannot be checked with this age\n"
            . "          identity (SOPS_AGE_KEY_FILE); a real run leaves it as it is\n";
    } elsif ($secret ne 'current') {
        print "  [robocop] Secret/robocop-credentials is $secret\n"
            . "          would " . ($secret eq 'missing' ? 'write' : 'rewrite')
            . " it ($level)\n";
        push @found, 'robocop-credentials';
    }

    my $deployment = eval { OCP::Cmd::Apply::K8s::read_or_absent('Deployment ocp-system/robocop',
        sub { $api->get('Deployment', 'robocop', namespace => 'ocp-system') }) };
    if (my $err = $@) {
        chomp(my $cause = $err);
        print "  [robocop] Deployment/robocop could not be checked\n";
        print STDERR "  [!!] Deployment/robocop not checked: $cause\n";
        push @found, { kind => 'error', label => 'Deployment/robocop', cause => $cause,
                       message => "Deployment/robocop: $cause" };
    } elsif (!$deployment) {
        print "  [robocop] Deployment/robocop is missing\n"
            . "          would roll it out ($level)\n";
        push @found, 'robocop';
    }

    return @found;
}

# Whether --only lets the worker side -- robocop and the worker step -- run:
# no --only, or --only workers. The gate OCP::Cmd::Apply::Deploy puts in front
# of the same steps.
sub worker_step_wanted {
    my ($self) = @_;
    return OCP::Cmd::Apply::Deploy::worker_gate($self);
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
# branch and no drift with a Rex remedy could ever be repaired there. k87.
sub run_remedy {
    my ($self, $config, $entry) = @_;

    my $remedy = $entry->{remedy} or return 0;

    # An API remedy runs from here, over the cluster API like the rest of the
    # reconcile: no SSH, no key, no PIN2 (k198).
    if (($remedy->{type} // '') eq 'api') {
        die "unknown API remedy $remedy->{task}\n"
            unless $remedy->{task} eq 'upgrade_cert_manager';
        OCP::Cmd::Apply::Network::upgrade_cert_manager(
            $self, $self->_k8s_api, $remedy->{params}{version});
        return 1;
    }

    return 0 unless ($remedy->{type} // '') eq 'rex';

    # A host-side probe (OCP::Drift's rex_probe mode) names the machine it
    # drifted on, so the fix runs there. Everything else keeps aiming at the
    # control plane, as before.
    my $host = $remedy->{host} // $config->cluster_status->{public_ip};
    unless ($host) {
        print STDERR "  [!!] No control plane address known, cannot run $remedy->{task}.\n";
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

        # A repair that did not run is a failure of this run (k226): STDERR.
        my $what = $entry->{label} // $entry->{component} // 'this component';
        print STDERR "  [!!] $remedy->{task} needs SSH access to the control plane and\n";
        print STDERR "       could not get a key for it. NOT run: $what stays as it is.\n";
        print STDERR "       $_\n" for split /\n/, $why;
        print STDERR "       Run 'ocp update --component $entry->{component}' instead.\n"
            if defined $entry->{component};
        return 0;
    }

    $entry->{result} = OCP::Rex->new(
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
