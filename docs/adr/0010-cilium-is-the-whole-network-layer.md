# 0010. Let Cilium be the whole network layer

Date: 2026-08-12
Status: accepted

## Context

A cluster needs a CNI, network policy, ingress, and — on bare metal — some way
to answer for LoadBalancer addresses. The default assembly is a stack: a CNI,
plus an ingress controller, plus kube-proxy, plus a service mesh when L7 policy
or mTLS is wanted, plus something like MetalLB for L2.

Each layer is a separate upstream, a separate version to track, a separate
failure mode, and on small clusters a meaningful amount of RAM. OCP's target is
a handful of nodes, sometimes exactly one, sometimes an appliance whose memory
is spoken for.

Cilium covers the whole list in one component: CNI, L3/L4/L7 network policy,
kube-proxy replacement via eBPF, WireGuard encryption, Gateway API ingress,
service-mesh features, DNS policy and Hubble observability.

*Rationale partly reconstructed:* the code and commit history record the moves
(Traefik removed in favour of Cilium Gateway API, `a5a598d`, 2026-02-16; Cilium
1.17 → 1.19.2 with the Gateway API CRD bump, `9e410ae`). The rejection of Istio
and Canal is recorded only as a statement in the project's own documentation,
not in any commit or ticket.

## Decision

Cilium is the only network component OCP installs. Ingress is Cilium's Gateway
API implementation. There is no Istio, no Canal, and no separate ingress
controller — Traefik was removed rather than kept as an option.

Cilium's version and the Gateway API CRD bundle are version-locked to each
other in `OCP::Versions` and bumped together, because Cilium refuses to start
its Gateway controller unless the CRD bundle matches what its docs name for
that release. The CRDs are installed before Cilium.

LB-IPAM plus L2 announcements is **opt-in** (`lbipam: true`, default off). Its
natural default — a pool consisting of the host's public IP, announced over L2 —
makes Cilium hijack ARP for that address and takes down host-bound ports such as
sshd and the apiserver.

### Alternatives rejected

- **Istio (or any sidecar mesh)** for L7 policy and mTLS — overkill for the
  target cluster size and it costs memory per pod; Cilium answers the same
  questions in the datapath.
- **Canal / Flannel + Calico** — two components for what one does, and no
  Gateway API story.
- **A separate ingress controller (Traefik)** — was present and was removed; a
  second thing to version and a second place to configure ingress.
- **LB-IPAM on by default** — the default pool takes over the host IP, which
  breaks the machine OCP just installed.

## Consequences

- Cilium upgrades are cluster-wide events touching the datapath, and OCP owns
  them: `OCP::Drift` probes `cilium-operator` and carries `upgrade_cilium` as
  an automatic remedy.
- Gateway API CRD schema changes are OCP's problem, not an add-on's. The
  v1.1 → v1.2 bump required bouncing `cilium-operator` to refresh its schema
  cache.
- Anyone who wants an ingress controller OCP does not ship is on their own; the
  supported path is a `Gateway`.
- On bare metal without `lbipam`, LoadBalancer services have no address. That
  is the deliberate default, and NodePort plus the Gateway is the answer.
- The `cilium` CLI is downloaded per architecture, which is one of the places
  ADR 0020 has to hold.
