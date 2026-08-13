# 0011. Keep Helm off the runtime path

Date: 2026-08-12
Status: accepted

## Context

Helm is the default answer for installing anything into Kubernetes, so not
using it is the decision that needs recording.

Helm brings a release-state machine: a stored release record, a revision
history, and an upgrade path that OCP would neither own nor be able to
reconcile against. OCP already has a convergence model — Server-Side Apply plus
a manifest hash (ADR 0008) — and it is a different one. Running both means two
answers to "what is installed", and the Helm one is authoritative for the
resources Helm owns.

It also collides in practice. RKE2 and k3s ship their own `helm-controller` and
install their own add-ons through it; that is why the CoreDNS ConfigMap on RKE2
belongs to the `rke2-coredns` Helm release and is called
`rke2-coredns-rke2-coredns`, and why a `helm-install` job can CrashLoopBackOff
against a cluster whose CNI is already Cilium-owned. Every resource OCP shares
with a Helm release is a resource with two owners (ADR 0016).

*Rationale partly reconstructed:* the collisions above are documented in the
code and in karr #15 and #23. The original decision to avoid Helm is recorded
in the project's own documentation as a fact, with no commit or ticket stating
the reasoning.

## Decision

Helm is never the default path. OCP installs from plain manifests and Kustomize,
applied through the one Server-Side Apply helper. `helm template` is acceptable
as a build-time renderer — turning a chart into a manifest that OCP then owns —
but no Helm release is created at runtime.

Helm is not forbidden; it is simply never how OCP itself installs something.

### Alternatives rejected

- **Helm as the install mechanism** — a second convergence model beside the
  hash/SSA one, with its own state, and it collides with the distributions'
  own helm-controller.
- **Helm for third-party components only** — the split is exactly where
  ownership disputes live; the GPU operator's ClusterPolicy and Cilium's CRDs
  are precisely the objects OCP needs to own.

## Consequences

- Upstream chart values have to be translated into manifests by hand, and the
  translation goes stale. The GPU operator Deployment is hand-written and
  carries none of the `*_IMAGE` environment variables the chart sets — which is
  why an enabled ClusterPolicy component without an explicit image pin is an
  ImagePullBackOff rather than a sane default (ADR 0014), and why the
  `toolkit.env` block is still the recipe from an archived operator version
  (karr #30).
- Chart defaults have to be mirrored deliberately when they matter, with a
  comment saying that is what is happening.
- Where a distribution *does* own a resource through Helm, OCP has to find the
  Helm-mangled name rather than the obvious one — the CoreDNS ConfigMap is
  looked up under both names.
- Upgrading a third-party component means diffing its manifests, not bumping a
  chart version.
