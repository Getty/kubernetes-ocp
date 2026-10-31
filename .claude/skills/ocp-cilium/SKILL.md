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

Gateway API CRDs are pinned in `OCP::Versions` (`gateway_api`, version-locked
to Cilium, bump both together; see "Cilium Versions") and applied BEFORE
Cilium by `Rex::Rancher::Cilium` (`install_cilium`/`upgrade_cilium` with
`gateway_api => 1, gateway_api_channel => 'standard'` — the library defaults to
experimental, so OCP always passes the channel; k155). **Standard channel only — never experimental on top of
it.** From Gateway API v1.5, both bundles ship the
`safe-upgrades.gateway.networking.k8s.io` ValidatingAdmissionPolicy, which
refuses experimental CRDs applied over standard ones (the reverse stays
allowed). OCP used to apply standard and then experimental with errors
swallowed; under the pin of the time, v1.6.1, the experimental apply was
silently denied and nobody noticed (k157). Standard alone is enough: from v1.5 it carries
TLSRoute v1 and BackendTLSPolicy v1, and from v1.6 also TCPRoute and
UDPRoute — everything Cilium 1.20 needs.

The library applies through Kubernetes::REST from the machine running `ocp`
(a kubeconfig `Rex::Rancher::Server::fetch_kubeconfig` fetches off the node,
pointed at the Rex host, with OCP's CA-less `insecure-skip-tls-verify` policy
as its filter; rex-rancher k73) —
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

IPAM: OCP passes `ipam_mode => 'cluster-pool'` (rex-rancher k64) —
Rex::Rancher's rke2 default is `ipam.mode: kubernetes`, so a fresh RKE2
cluster would get that without it. Like `cluster_cidr` for the pool, it is
only the mode of a *fresh* install: a running Cilium in another mode keeps
its mode (and pool), with a warning from the library, because Cilium cannot
change IPAM under running pods. **Never `helm_values => { ipam => { mode =>
... } }`**: that is a demand, and against a running Cilium in any other mode
the library dies before touching the host — every `ocp apply` would. The
**pool** is not stated by OCP at all: `cluster_cidr` (passed next to
`ipam_mode`) is only the pool of a *fresh* install — a running cluster-pool
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

RKE2 >= v1.37 ships its own `rke2-gateway-api-crd` chart, which would fight
this apply. The Rexfile puts that chart on every RKE2 server's `disable`
list, whatever the pin (k161). Skill `ocp-rke2` has the detail.

## LB-IPAM (opt-in: `lbipam: true`)

`type: LoadBalancer` on bare metal: a pool plus L2 (ARP) announcements, both
built by `OCP::Cmd::Apply::Network::lb_ipam_resources` (pure; `t/78`, `t/210`).

- `CiliumLoadBalancerIPPool` `default-pool`, **`cilium.io/v2`**. Its blocks
  come from `network.lb_pool` (`cidr`, or `start` + `stop`; k127). Without a
  pool, the blocks are the node IP as a `/32`, but only on a single-node
  cluster. On a multi-node cluster `lb_ipam_resources` dies rather than
  announce a node's own address; `ocp apply` reports it as a warning and
  continues without LB-IPAM, as it does with every LB-IPAM failure (the
  CRD wait below too).
- `CiliumL2AnnouncementPolicy` `default-l2`, `cilium.io/v2alpha1`, with
  `externalIPs` and `loadBalancerIPs`.
  - `interfaces` is `$config->l2_interfaces`: `network.l2.interfaces`, or
    `$OCP::Config::DEFAULT_L2_INTERFACES`. The default takes ethN and en*
    (VLANs ok) but no switchdev "np" ports like enp1s0f0np0 (k210).
  - `nodeSelector` comes from `network.l2.node_selector`, when that is set.

## Cilium Helm values from ocp.yaml (k210)

`cilium.devices` (short for Helm `devices`) and `cilium.helm_values` (deep-merged
over what Rex::Rancher::Cilium generates) come from `OCP::Config->cilium_helm_values`
and travel as `helm_values` to `install_cilium` (via `OCP::Rex::install_server`)
and to every `upgrade_cilium` (drift remedy and `ocp update`, via
`OCP::Drift->remedy_params`' `remedy_config`) — an upgrade without them would
drop what the install set. IPAM stays OCP's: see the IPAM paragraph above.

## CRD Wait Pattern

The Cilium operator registers its CRDs asynchronously. `setup_lb_ipam`
builds both objects first, so a refused pool fails before the wait. It then
polls `GET /apis/cilium.io/v2/ciliumloadbalancerippools` (30 × 10 s), dies
when the API is still not served after 300 s, and server-side-applies both.

## Cilium Versions

Single source of truth: `OCP::Versions`, the `components` of the current OCP
version: `cilium`, `cilium_cli`, `gateway_api`. This section copies no number
from there, so it cannot fall behind a bump. Read the current values:

- in the source, `lib/OCP/Versions.pm` (`$VERSIONS->{<OCP version>}{components}`);
- in code, `OCP::Versions->get_component_version('cilium')` (the current OCP
  version unless one is passed);
- from the CLI, `ocp version` for a project not deployed yet (the manifest it
  will install); on a deployed cluster a version drift in `ocp status` names
  the pin as `expected`.

Bump rules:

- `gateway_api` is version-locked to `cilium`: bump both together, to the
  Gateway API release Cilium's docs name for that Cilium release.
- A new `cilium` pin also ends `@OCP::Versions::CILIUM_STATIONS`, one station
  per minor with the pin itself last (`t/236-cilium-stations.t`): upgrades
  walk a cluster through the minors in between (k195).

The Rexfile carries no version constants of its own to drift out of sync.
`OCP::Rex` (`install_server`) passes all three explicitly into the
`install_cilium` task params — the Rexfile's env var fallback
(`OCP_CILIUM_VERSION`, `OCP_CILIUM_CLI_VERSION`, `OCP_GATEWAY_API_VERSION`)
is only for hand-runs outside that path.

`upgrade_cilium` re-applies the Gateway API CRDs before the Helm upgrade
(k160), through the library like `install_cilium`.
