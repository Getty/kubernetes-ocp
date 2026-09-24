package OCP::Cmd::Apply::Deploy;
# ABSTRACT: Post-bootstrap component deployment + worker rollout

use strict;
use warnings;

use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Network;
use OCP::Cmd::Apply::Registry;
use OCP::Cmd::Apply::Workloads;
use OCP::Versions;

=head1 SYNOPSIS

    my $step = OCP::Cmd::Apply::Deploy::deploy($apply, {
        config         => $config,
        secrets        => $secrets,
        api            => $api,
        cp_name        => $cp_name,
        cp_ip          => $cp_ip,
        provider       => $provider,
        ssh_key_path   => $ssh_key_path,
        deploy_step    => $deploy_step,    # step counter so messages stay ordered
    });

    # robocop and the worker step, as the reconcile path runs them. robocop
    # comes first and on its own (k173); the worker step only uses its answer:
    my $robocop = OCP::Cmd::Apply::Deploy::robocop_step($apply, $api, $config, {
        cp_ip   => $cp_ip,
        secrets => $secrets,
    });
    my @results = OCP::Cmd::Apply::Deploy::worker_step($apply, $api, $config, {
        robocop      => $robocop,
        # k26:
        names        => \@missing,         # omit to cover every worker
        ssh_key_path => sub { ... },       # a path, or a code ref run lazily
        cp_ip        => $cp_ip,
        secrets      => $secrets,
    });

=head1 DESCRIPTION

The "the cluster is up, now put the stack on it" half of `ocp apply`.

Sits between OCP::Cmd::Apply::Bootstrap (which produced the working api
handle) and OCP::Cmd::Apply::Health::finish (which evaluates the result).
This module is the orchestrator: it owns the order in which registry,
CoreDNS/registry.local, NFD, GPU operator, cert-manager, Cilium Gateway
and LB-IPAM come up, and it owns the CR-first worker flow that follows.

The order is forced by the dependencies, not by convention:

=over

=item *

Registry FIRST — every other component pulls images through it.

=item *

NFD NEXT — GPU operator gating reads the pci-10de label NFD writes.

=item *

cert-manager manifests applied + Cilium Gateway established in
parallel (cert-manager takes time to start; Gateway needs no webhook).

=item *

LB-IPAM opt-in, only when the user asked for it.

=item *

cert-manager ready + issuers created (we let it start during Gateway
+ LB-IPAM setup so the wait is hidden).

=item *

CR layer (CRDs, providers, CP OCPNode) — observational, runs even
without workers.

=item *

robocop rollout (credentials Secret + Deployment) whenever
C<robocop.enabled> -- with or without workers (k173).

=item *

Worker OCPNodes, driven by robocop or the CLI reconcile fallback.

=back

The deploy function returns the final step counter so finish_apply
prints "Step N: Verify cluster health" with the right number.

=cut

sub deploy {
    my ($self, $args) = @_;

    my $config       = $args->{config};
    my $secrets      = $args->{secrets};
    my $api          = $args->{api};
    my $cp_name      = $args->{cp_name};
    my $cp_ip        = $args->{cp_ip};
    my $provider     = $args->{provider};
    my $ssh_key_path = $args->{ssh_key_path};
    my $deploy_step  = $args->{deploy_step} // 2;

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

    # Deploy GPU Operator if NFD detects NVIDIA GPU (pci-10de label).
    # The step's verdict is its return value (including 'skipped' for a
    # cluster with no NVIDIA card), so both apply paths close the block with
    # the same line instead of the deploy path having none at all.
    print "  [..] Checking GPU Operator...\n";
    my $gpu_outcome = eval { $self->_setup_gpu_operator($config) };
    if ($@) {
        print "  [WARN] GPU Operator setup failed: $@\n";
    } else {
        $self->_report_component('GPU Operator', $gpu_outcome);
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
            $self->_setup_lb_ipam($cp_ip, $config);
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
    #   4. If robocop_enabled: deploy robocop -- with or without workers.
    #   5. Write Pending OCPNode CR for each worker pool entry.
    #   6. Workers: let a ready robocop drive them (waiting briefly for one
    #      that is still starting), else drive them from the CLI via
    #      OCP::Node.
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

    # Additional control planes (police2+) join police1's embedded-etcd cluster
    # as RKE2 servers (k8). police1 was bootstrapped imperatively above and its
    # bootstrap is deliberately unchanged; these are provisioned and installed
    # through the same OCP::Node machinery workers use, which brings a
    # control-plane role up as a server-join. RKE2-only: for k3s, or a lone
    # control plane, ensure_control_plane_ocpnodes writes nothing and this is a
    # no-op. Runs before the worker step so the HA control plane exists first.
    # Gated by --only exactly like the worker step: `--only workers` neither
    # writes nor drives the join CRs, so it cannot provision a control plane.
    if (!$self->only || $self->only eq 'control-planes') {
        my @cp_crs = $self->_ensure_control_plane_ocpnodes($api, $config);
        if (@cp_crs) {
            my @cp_names = map { $_->{metadata}{name} } @cp_crs;
            print "  [..] Joining " . scalar(@cp_names)
                . " additional control plane(s) to the cluster...\n";
            my @cp_results = $self->_cli_reconcile_workers($api, $config, \@cp_names, {
                ssh_key_path => $ssh_key_path,
                cp_ip        => $cp_ip,
                secrets      => $secrets,
            });
            $self->_print_worker_status(\@cp_results, 'Control plane');
        }
    }

    # robocop is a component of its own (k173): `robocop.enabled` means robocop
    # runs, so it is rolled out whether or not ocp.yaml lists a worker -- it
    # also picks up the OCPNodes `ocp node add` writes later. After the
    # control-plane joins, which the CLI drives and robocop must not race,
    # and before the workers, which it may drive. Its gate is the worker gate:
    # robocop provisions workers and nothing else, so `--only control-planes`
    # leaves it alone and `--only workers` includes it.
    my $step = $deploy_step + 2;
    my $robocop;
    if ($config->robocop_enabled && worker_gate($self)) {
        print "\n";
        print "Step $step: Deploy robocop controller\n";
        $step++;
        $robocop = robocop_step($self, $api, $config, {
            cp_ip   => $cp_ip,
            secrets => $secrets,
        });
    }

    if (@$workers && worker_gate($self)) {
        print "\n";
        print "Step $step: Deploy workers (CR-driven)\n";
        $step++;
        worker_step($self, $api, $config, {
            ssh_key_path => $ssh_key_path,
            cp_ip        => $cp_ip,
            secrets      => $secrets,
            robocop      => $robocop,
        });
    }

    return $step;
}

# Whether --only lets the worker side run -- robocop and the worker step: no
# --only, or --only workers. Both apply paths put it in front of the same
# steps (OCP::Cmd::Apply::Drift).
sub worker_gate {
    my ($self) = @_;
    return !$self->only || $self->only eq 'workers';
}

# Make robocop run: its credentials Secret, then its Deployment, shaped for
# robocop.security_level. The one place `ocp apply` rolls robocop out, on the
# fresh deploy and on every reconcile alike (k173) -- so a cluster that got
# the Deployment without the Secret (k169) is repaired by the next apply.
#
# The Secret comes BEFORE the Deployment that mounts it: without it the pod
# sits in CreateContainerConfigError (k169). Same code as `ocp deploy-robocop`
# (OCP::Role::Cmd::RobocopCredentials); a Secret that is already current is
# left alone, so a reconcile costs no SSH read and no PIN2. When it cannot be
# written the Deployment is not rolled out either -- a pod that cannot start
# is no controller.
#
# Readiness is looked at once, not waited for: only a worker step that wants
# robocop to drive has a reason to wait, and worker_step does.
#
# Returns { state => 'ready' | 'pending' | 'failed', changed => 0|1 } --
# changed when the Secret was written or the Deployment was not there before.
# worker_step takes it as $deps->{robocop}.
sub robocop_step {
    my ($self, $api, $config, $deps) = @_;
    my $level = $config->robocop_security_level;

    print "  [..] Deploying robocop controller ($level)...\n";

    my $had_deployment = eval {
        $api->get('Deployment', 'robocop', namespace => 'ocp-system');
    } ? 1 : 0;

    my $secret;
    my $deployed = eval {
        $secret = $self->_ensure_robocop_credentials($api, $config, $deps->{secrets},
            $level, host => $deps->{cp_ip});
        $self->_ensure_robocop($api, $config);
        1;
    };
    # A failure, so STDERR -- mostly a credentials problem (refused PIN2,
    # unreadable join token) the operator has to act on.
    unless ($deployed) {
        my $err = $@ || "unknown error\n";
        $err .= "\n" unless $err =~ /\n\z/;
        print STDERR "  [!!] robocop deploy failed: $err";
        return { state => 'failed', changed => 0 };
    }

    my $changed = (($secret // '') eq 'written' || !$had_deployment) ? 1 : 0;

    if ($self->_wait_robocop_ready($api, 0)) {
        print "  [ok] robocop ready\n";
        return { state => 'ready', changed => $changed };
    }

    # inject: the pod turns Ready only once `ocp inject-key` handed it the
    # robo key, which nothing in this run does.
    print $level eq 'inject'
        ? "  [..] robocop waits for its SSH key (security_level inject):\n"
        . "       run 'ocp inject-key' once the pod is running.\n"
        : "  [..] robocop rolled out, not ready yet\n";
    return { state => 'pending', changed => $changed };
}

# The CR-driven worker step, shared by the fresh deploy (every worker) and
# the reconcile path of an existing cluster (only the workers that have no
# OCPNode yet, k26): write the Pending OCPNodes, then let robocop drive them
# or fall back to the CLI reconcile. Returns the per-worker results
# ({ name, phase, message }).
#
# robocop is not rolled out here (k173): the caller runs robocop_step first
# and hands its answer in as $deps->{robocop}. Left out -- robocop disabled,
# or not rolled out in this run -- the CLI drives the workers.
#
# $deps->{names} limits the step to those workers; left out, it covers all
# of ocp.yaml. $deps->{ssh_key_path} is a path, or a code ref returning one:
# the reconcile path has no key in hand and obtaining it can cost a PIN2
# prompt, so it is asked for only when the CLI fallback is actually taken --
# never when robocop does the work.
sub worker_step {
    my ($self, $api, $config, $deps) = @_;
    my $names   = $deps->{names};
    my $robocop = ($deps->{robocop} // {})->{state} // 'absent';

    $self->_ensure_worker_ocpnodes($api, $config, $names);

    my $robocop_ready = $robocop eq 'ready' ? 1 : 0;
    if ($robocop eq 'pending' && $config->robocop_security_level eq 'inject') {
        # A key that cannot arrive in this run is not waited for; a pod
        # injected on an earlier run was Ready in robocop_step already.
        print "  [..] robocop holds no SSH key yet: this run brings the\n"
            . "       workers up from the CLI.\n";
    } elsif ($robocop eq 'pending') {
        $robocop_ready = $self->_wait_robocop_ready($api, 60);
        if ($robocop_ready) {
            print "  [ok] robocop ready — grace period (5s)\n";
            $self->wait_seconds(5);
        } else {
            print "  [WARN] robocop not ready after 60s — falling back to CLI reconcile\n";
        }
    } elsif ($robocop eq 'failed') {
        print "  [..] robocop is not running: the CLI brings the workers up\n";
    }

    my $ssh_key_path = $deps->{ssh_key_path};
    if (!$robocop_ready && ref $ssh_key_path eq 'CODE') {
        $ssh_key_path = eval { $ssh_key_path->() };
        unless ($ssh_key_path) {
            my $why = $@ || "no usable SSH key for the cluster\n";
            my @which = $names ? @$names
                : map { $_->{metadata}{name} } OCP::Cmd::Apply::CR::worker_ocpnodes($config);
            print STDERR "  [!!] Bringing up worker(s) " . join(', ', @which)
                . " needs SSH access to the cluster and\n"
                . "       could not get a key for it. Their OCPNodes are written,\n"
                . "       the machines are NOT set up.\n";
            print STDERR "       $_\n" for split /\n/, $why;
            my @failed = map { {
                name    => $_,
                phase   => 'Failed',
                message => 'no SSH key for the CLI reconcile',
            } } @which;
            $self->_print_worker_status(\@failed);
            return @failed;
        }
    }

    my @results = $self->_drive_workers($api, $config, {
        robocop_ready => $robocop_ready,
        ssh_key_path  => $ssh_key_path,
        cp_ip         => $deps->{cp_ip},
        secrets       => $deps->{secrets},
        ($names ? (names => $names) : ()),
    });
    $self->_print_worker_status(\@results);
    return @results;
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::Cmd::Apply::Bootstrap>,
L<OCP::Cmd::Apply::Health>, L<OCP::Cmd::Apply::CR>,
L<OCP::Cmd::Apply::Registry>, L<OCP::Cmd::Apply::Workloads>,
L<OCP::Cmd::Apply::Network>.

=cut
