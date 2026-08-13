# 0018. Admit only drift-capable, idempotent, cheap work into the reconcile path

Date: 2026-08-12
Status: accepted

## Context

`ocp apply` has two shapes. Against a project with no `kubeconfig.yaml` it
bootstraps: it creates or adopts machines, installs the distribution, and builds
the whole stack. Against an existing cluster it reconciles: it converges what is
already there. The reconcile path is the one people run repeatedly, often just
to check.

Which steps belong on it is not obvious, and getting it wrong is expensive in
both directions.

Too little, and the path is a liar. It used to check five components and never
touch `registry.local` DNS or the node CRs, which is why "the record is
self-healing on the next apply" was untrue for a cluster whose Corefile k3s had
reset (ADR 0016), and why an existing cluster showed `Pending` node CRs forever.

Too much, and the frequently-run command creates paid servers. Worker
provisioning waits up to 600s and calls a cloud provider's create API.

## Decision

A step may join the reconcile path when it is **drift-capable, idempotent and
cheap** — drift-capable meaning it can tell "already correct" from "needs
fixing", cheap meaning API calls rather than waiting loops.

On the path: the drift report and its remedies, the registry, `registry.local`
in CoreDNS, NFD, the GPU operator, cert-manager, the Cilium Gateway, LB-IPAM
(still opt-in), and the whole CR layer — `_ensure_crds`, `_ensure_providers`,
`_migrate_legacy_nodes`, `_ensure_cp_ocpnode`.

Off the path, deliberately: **worker provisioning and control-plane bootstrap**.
They are one-time steps, they create machines that cost money, and they wait.

Both paths end in the same `_finish_apply` and therefore in the same health
verdict (ADR 0017). Where the two paths need the same fact, they share one
derivation — `_cp_identity` exists so that reconcile cannot write the status of
a node it named differently from the way bootstrap named it.

### Alternatives rejected

- **Put everything on both paths** — makes the frequently-run command create
  paid infrastructure and wait ten minutes.
- **Keep the reconcile path minimal** — that was the previous state, and it made
  a self-healing claim untrue and left node CRs permanently wrong.
- **Provision workers on reconcile "because the rest converges"** — a real
  argument, and exactly why the gap is documented rather than closed by
  accident.

## Consequences

- Adding a worker to `ocp.yaml` and running `ocp apply` on an existing cluster
  does nothing: no CR, no server, no message (karr #26). The gap is named, not
  accidental. The shape of the eventual fix — write the CRs and let robocop
  drive, an explicit `--workers` flag, or `ocp node add` staying the only way —
  is undecided.
- Every candidate step now has to answer the three questions before it goes in,
  and the answer belongs in the comment beside it.
- The reconcile path got slower and noisier: more checks, more output lines.
  That is the price of it telling the truth.
- Because `_check_cluster_health` has exactly one caller, a new terminal path in
  `execute` would have to route through `_finish_apply` or it would silently
  reintroduce the original bug. A test holds that.
