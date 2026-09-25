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
Since Rex::Rancher 0.003 the CRD-only drift remedy `update_gateway_api` goes
through the library too:
`Rex::Rancher::Cilium::ensure_gateway_api_crds` applies the same standard
bundle (skipped when version and channel already match, dying on failure)
and, only when it actually applied it, restarts a running `cilium-operator` —
unlike `upgrade_cilium` no new operator image follows, and controller-runtime
caches CRD schemas at startup. Cilium itself is not touched. There is no
kubectl apply and no `_apply_gateway_api_crds` left in the Rexfile any more
(rex-rancher k43).

IPAM: OCP always states `helm_values => { ipam => { mode => 'cluster-pool' }
}` — Rex::Rancher's rke2 default is `ipam.mode: kubernetes`, so a fresh RKE2
cluster would get that without it. Stated, it is also enforced: the library
dies before touching the host when a running Cilium is in a different mode
(Cilium cannot change IPAM under running pods; open: a running Cilium in a
mode other than cluster-pool blocks install/upgrade outright, rex-rancher
k64). The **pool** is not stated by OCP at all: `cluster_cidr` (passed next to
`helm_values`) is only the pool of a *fresh* install — a running cluster-pool
keeps its own, which the library reads off `kube-system/cilium-config`
through the API itself and warns about when it differs from `cluster_cidr`
(k182; an RKE2 cluster from before k182 runs `10.0.0.0/8`, which
`OCP::Drift` reports). On k3s, when OCP passes no `k8s_service_host` the
library takes the running Cilium's DaemonSet address instead of failing
outright, and only dies when neither is available, before the node is
touched.

Readiness is the library's own since 0.003: `wait => 1, wait_duration => ...`
(600s on `install_cilium`, 300s on `upgrade_cilium`) — it returns only once
the `cilium` DaemonSet and `cilium-operator` are rolled out and ready, and
dies naming their state otherwise (k178: a Cilium that never became ready
used to cost the full wait and then report success). There is no `cilium
status --wait` and no kubectl on the node for any of this any more.

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
