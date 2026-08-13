---
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

Gateway API CRDs (v1.1.0) are installed BEFORE Cilium in the Rexfile:
- standard-install.yaml (HTTPRoute, Gateway, GatewayClass)
- experimental-install.yaml (TCPRoute, UDPRoute, TLSRoute)

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

Managed in `OCP::Versions` and Rexfile constants:
- Cilium: 1.17.0
- Cilium CLI: v0.16.23

Rexfile has its own constants (`CILIUM_VERSION`, `CILIUM_CLI_VERSION`) — keep in sync with OCP::Versions.
