# 0012. Support RKE2 and k3s as equals

Date: 2026-08-12
Status: accepted

## Context

RKE2 and k3s come from the same vendor and share a large part of their agent
code, which makes supporting both look nearly free. They serve different
targets: RKE2 is the hardened, FIPS-capable server distribution; k3s is the
small one that runs on a single appliance without ceremony.

OCP's users span both — a Hetzner control plane and a DGX Spark on someone's
desk are the same tool's job.

They are not, however, interchangeable in the places that matter:

- RKE2 registers agents on a supervisor port of its own (9345); k3s serves
  registration and the apiserver both from 6443. An agent pointed at the wrong
  one never joins.
- `kubectl` on the node is `/var/lib/rancher/rke2/bin/kubectl` on one and on
  `$PATH` on the other; state lives under `.../rancher/rke2/` or
  `.../rancher/k3s/`.
- k3s ships CoreDNS the stock way (`coredns` ConfigMap, with a `hosts` plugin
  for `NodeHosts`); RKE2 installs it from a Helm chart as
  `rke2-coredns-rke2-coredns`, with no `NodeHosts` block.
- `rke2-server.service` sets no `Environment=`, so it has no `PATH` for the
  containerd runtime scan; k3s does.

## Decision

Both are first-class, selected by `kubernetes.dist: rke2|k3s`. Every
distribution-dependent fact is derived from that key rather than assumed, and
the derivation lives in one place per fact:
`OCP::Config::supervisor_port`, `_dist_label` for user-facing text,
`OCP::Drift::@COREDNS_CONFIGMAPS` shared between the writer and the reader so
the two can never look in different places.

Neither distribution is the "real" one that the other is patched into.

### Alternatives rejected

- **RKE2 only** — excludes the single-appliance case that OCP is used for.
- **k3s only** — excludes the hardened server case.
- **k3s as "RKE2 with overrides"** — every override is then a special case
  layered on a wrong default; the CoreDNS and containerd bugs below are exactly
  what that shape produces.

## Consequences

- Every new node-touching feature has to be verified on both, and the cost is
  real. The week that produced these ADRs found three bugs that existed only
  because the smoke test ran RKE2 while the live machine ran k3s:
  a second `hosts` plugin killing CoreDNS on k3s (karr #15), a containerd
  template written to the RKE2 path on a k3s host (karr #23), and progress
  output hardcoded to "RKE2" during a k3s install (karr #18).
- A one-distribution smoke test is not coverage. `xt/smoke.sh` takes
  `SMOKE_DIST`, and a run on one of them says nothing about the other.
- Conversely, a fix verified on one distribution must say so. The RKE2 branch
  of `_configure_nvidia_runtime_path` is written and unverified, and is
  recorded that way rather than reported as done.
- Version pins come in pairs (`rke2` and `k3s` in `OCP::Versions`) and move
  together.
