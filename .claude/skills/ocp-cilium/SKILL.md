---
name: ocp-cilium
description: Use when configuring Cilium for an OCP cluster — the install flags OCP passes, LB-IPAM pools, the CRD wait pattern, pinned versions. Generic Cilium behaviour: skill kubernetes-cilium-concepts.
model: sonnet
---

# Cilium Configuration for OCP

## Why Cilium

Cilium replaces multiple components:
- CNI (Pod Networking)
- kube-proxy (eBPF replacement)
- Network Policies (L3/L4/L7)
- Encryption (WireGuard)
- Ingress (Gateway API)
- Service Mesh features
- Observability (Hubble)
- DNS Policies

No Istio, no Canal, no nginx ingress needed.

## eBPF kube-proxy Replacement

RKE2 config: `disable-kube-proxy: true`
Cilium install: `--set kubeProxyReplacement=true`

This means ALL service routing is handled by Cilium's eBPF programs, not iptables.

## Gateway API

OCP uses Cilium as Gateway API implementation (not Ingress):

```perl
my $gateway = {
    apiVersion => 'gateway.networking.k8s.io/v1',
    kind       => 'Gateway',
    metadata   => { name => 'cilium-gateway', namespace => 'kube-system' },
    spec       => {
        gatewayClassName => 'cilium',
        listeners => [
            { name => 'http',  port => 80,  protocol => 'HTTP', ... },
            { name => 'https', port => 443, protocol => 'HTTPS', ... },
        ],
    },
};
```

Gateway API CRDs are pinned in `OCP::Versions` (`gateway_api`, currently
v1.6.1 — version-locked to Cilium, bump both together) and applied BEFORE
Cilium by `Rex::Rancher::Cilium` (`install_cilium`/`upgrade_cilium` with
`gateway_api => 1, gateway_api_channel => 'standard'` — the library defaults to
experimental, so OCP always passes the channel; k155). **Standard channel only — never experimental on top of
it.** From Gateway API v1.5, both bundles ship the
`safe-upgrades.gateway.networking.k8s.io` ValidatingAdmissionPolicy, which
refuses experimental CRDs applied over standard ones (the reverse stays
allowed). OCP used to apply standard and then experimental with errors
swallowed; under the v1.6.1 pin the experimental apply was silently denied
and nobody noticed (k157). Standard alone is enough: from v1.5 it carries
TLSRoute v1 and BackendTLSPolicy v1, and from v1.6 also TCPRoute and
UDPRoute — everything Cilium 1.20 needs.

The library applies through Kubernetes::REST from the machine running `ocp`
(a kubeconfig the Rexfile fetches off the node, pointed at the Rex host) —
no last-applied annotation, so the 256 KiB limit a client-side apply hits is
moot; it skips the apply when the CRDs' bundle-version/channel annotations
already match (the same ones OCP::Drift reads, k164) and dies on failure.
The CRD-only drift remedy `update_gateway_api` keeps OCP's own server-side
kubectl apply (`_apply_gateway_api_crds`, `--force-conflicts
--field-manager=ocp`), because the library keeps that step private
(rex-rancher k43).

IPAM: Rex::Rancher's rke2 default is `ipam.mode: kubernetes`, and it only
refuses a mode change the release set explicitly. OCP therefore always passes
`helm_values => { ipam => ... }`: cluster-pool on `pod_cidr` for a fresh
Cilium, the live mode and pool (read from `kube-system/cilium-config`) for a
running one; an unreadable cilium-config aborts rather than guess
(rex-rancher k43). Readiness is OCP's `cilium status --wait` after the call.

Caveat: RKE2 >= v1.37 ships its own `rke2-gateway-api-crd` Helm chart, which
would fight this apply. Today's RKE2 pin is v1.36, so it's dormant; the
chart needs disabling (or OCP's apply needs dropping) when RKE2 is bumped
past that (k161, backlog).

## LB-IPAM (LoadBalancer IP Address Management)

For bare-metal/single-node clusters, Cilium provides LoadBalancer support:

```perl
# CiliumLoadBalancerIPPool — defines available IPs
{
    apiVersion => 'cilium.io/v2alpha1',
    kind       => 'CiliumLoadBalancerIPPool',
    metadata   => { name => 'default-pool' },
    spec       => { blocks => [{ cidr => "$node_ip/32" }] },
}

# CiliumL2AnnouncementPolicy — announces IPs via ARP
{
    apiVersion => 'cilium.io/v2alpha1',
    kind       => 'CiliumL2AnnouncementPolicy',
    metadata   => { name => 'default-l2' },
    spec       => {
        interfaces      => ['^eth[0-9]+', '^en[a-z0-9]+'],
        externalIPs     => true,
        loadBalancerIPs => true,
    },
}
```

This makes `type: LoadBalancer` services work on bare metal by assigning the node's IP and using L2 (ARP) announcements.

## CRD Wait Pattern

Cilium operator registers CRDs asynchronously. Wait before applying CiliumLoadBalancerIPPool:

```perl
for my $i (1..30) {
    last if $self->_resource_exists($api, 'CustomResourceDefinition',
        'ciliumloadbalancerippools.cilium.io');
    sleep 10;
}
```

## Cilium Versions

Single source of truth: `OCP::Versions` (`components`, current OCP version):
- Cilium: 1.20.0
- Cilium CLI: v0.19.7
- Gateway API CRDs: v1.6.1 (version-locked to Cilium — bump together)

The Rexfile carries no version constants of its own to drift out of sync.
`OCP::Rex` (`install_control_plane`) passes all three explicitly into the
`install_cilium` task params — the Rexfile's env var fallback
(`OCP_CILIUM_VERSION`, `OCP_CILIUM_CLI_VERSION`, `OCP_GATEWAY_API_VERSION`)
is only for hand-runs outside that path.

`upgrade_cilium` re-applies the Gateway API CRDs before the Helm upgrade
(k160), through the library like `install_cilium`.
