# 0008. Write every resource with Server-Side Apply and converge components by manifest hash

Date: 2026-08-12
Status: accepted

## Context

`ocp apply` is run repeatedly against the same cluster and must converge rather
than accumulate. Two questions come with that: how a single resource is written,
and how OCP decides whether a whole component needs rewriting at all.

For the single resource, create-or-update means read, diff, and decide — with a
race between the read and the write, and a merge OCP would have to implement
itself. Client-side apply additionally stores its last-applied state in an
annotation and cannot express who owns which field.

For the component, "apply everything every time" is correct but not free: the
GPU operator, the registry and NFD are multi-document manifests, and applying
all of them on every run makes the frequently-used reconcile path expensive
(ADR 0018) and its output unreadable.

## Decision

**Every write is a Server-Side Apply**: `PATCH` with
`application/apply-patch+yaml`, `fieldManager: ocp`, `force: true`. One helper,
`_server_side_apply`, does it for every resource, and `_apply_yaml_string` /
`_apply_yaml_file` fan multi-document manifests through the same helper. The
API server owns the merge and the conflict detection; OCP owns nothing but the
desired state.

Because the raw transport does not inspect the response, the helper checks the
status itself and dies on `>= 400`. Without that check every failed apply was
silent — a 404 for a CRD the API server had not registered yet looked exactly
like success, and the run reported resources it had not created.

**Component convergence is hash-based**: the generated manifest (plus any CRD
files that are part of it) is MD5-hashed and the hash recorded in
`.ocp/deployed.yaml`. A component is redeployed when its hash is missing or has
changed. cert-manager is tracked by component version instead, because its
version is readable from the running Deployment (`OCP::Drift`).

### Alternatives rejected

- **Read-modify-write** — a race and a merge algorithm OCP would own.
- **Client-side apply** — no field ownership, and last-applied state carried in
  an annotation.
- **Unconditional re-apply of every component** — correct but expensive, and
  the reconcile path is the one that gets run often.
- **`force: false`** — a hand-edited field would then block convergence
  silently; OCP is the declared owner of what it applies and says so.

## Consequences

- `force: true` means OCP takes fields back from other field managers without
  asking. Anyone editing an OCP-managed resource by hand loses the edit on the
  next apply — deliberately.
- `fieldManager: ocp` is now part of the cluster's state. Renaming it would
  orphan every field OCP currently owns.
- The hash is over the *generated manifest*, not over the cluster. A resource
  someone deleted by hand is not noticed until the manifest itself changes;
  drift probes and the health gate (ADR 0017) cover different ground.
- `.ocp/deployed.yaml` is disposable (ADR 0004): losing it costs one full
  redeploy, not correctness.
- Resources whose Kind is not in the resource map fall back to a path built
  from the resource hash, so unregistered CRs (Gateway, ClusterPolicy) still go
  through the same single write path.
