package OCP::Cmd::Apply::Deploy;
# ABSTRACT: Post-bootstrap component deployment + worker rollout

use strict;
use warnings;

use OCP::Cmd::Apply::CR;
use OCP::Cmd::Apply::Network;
use OCP::Cmd::Apply::Registry;
use OCP::Cmd::Apply::Workloads;
use OCP::Versions;

our $VERSION = '0.001';

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

Worker OCPNodes + robocop rollout + CLI reconcile fallback.

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

    return $deploy_step + 2 + ($worker_step ? 1 : 0);
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::Cmd::Apply::Bootstrap>,
L<OCP::Cmd::Apply::Health>, L<OCP::Cmd::Apply::CR>,
L<OCP::Cmd::Apply::Registry>, L<OCP::Cmd::Apply::Workloads>,
L<OCP::Cmd::Apply::Network>.

=cut
