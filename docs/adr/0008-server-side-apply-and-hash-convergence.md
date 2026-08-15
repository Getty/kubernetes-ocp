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

**The hash is never the only input** *(amended 2026-08-15, see below)*. It
answers one question — did the desired state change — and it is not evidence
that the component is still on the cluster. That is a second question, and it
is asked separately: before any component may report "up to date", it reads a
witness resource through `_resource_exists`. Hash match **and** witness present,
or the component is redeployed.

- **registry** — `Namespace/ocp-system`, plus `Deployment/ocp-cache` and
  `Deployment/ocp-registry`, but only the halves this configuration actually
  rolls out (`OCP::Cmd::Apply::Registry::running`). With an external cache or
  upstream OCP deploys nothing for that half and must not expect it, or the
  component redeploys on every run.
- **NFD** — `Namespace/node-feature-discovery` plus `Deployment/nfd-master`.
- **GPU operator** — `Namespace/gpu-operator` plus `Deployment/gpu-operator`.
- **cert-manager** — `Deployment/cert-manager` in namespace `cert-manager`;
  its version then comes off the running image, not out of the file.

What happened is judged once, inside the setup step — the only place that holds
both the record and the cluster's answer — and named:
`deployed` / `restored` / `updated` / `unchanged` / `skipped`. The caller does
not re-derive it; it prints the returned verdict through `_report_component`.
`restored` is the case the witness exists for — OCP had a record, the cluster
had nothing — and it counts as a change, so the reconcile summary cannot end in
"all components up to date" over a component it just had to put back.
`skipped` is the component that is not part of this cluster's spec at all (no
NVIDIA card, `gpu.enabled: false`) and counts as no change, so a GPU-free
cluster does not read as "1 component updated" on every run.

That holds by construction rather than by discipline: `reconcile_components`
reads `.ocp/deployed.yaml` exactly once, in the cert-manager block, and every
other component's verdict reaches it as a return value.

### Alternatives rejected

- **Read-modify-write** — a race and a merge algorithm OCP would own.
- **Client-side apply** — no field ownership, and last-applied state carried in
  an annotation.
- **Unconditional re-apply of every component** — correct but expensive, and
  the reconcile path is the one that gets run often.
- **`force: false`** — a hand-edited field would then block convergence
  silently; OCP is the declared owner of what it applies and says so.
- **Carrying the hash as an annotation on the object instead of in a local
  file** — the larger of the two directions weighed in karr #43, rejected
  2026-08-15. An annotation's whole value is that it dies with the object; but
  it dies only with *the* object it hangs on. A hash annotated on the
  `ocp-system` Namespace survives the deletion of a Deployment inside it
  exactly as well as the local file does — which is to say, wrongly. Noticing
  "someone deleted this by hand" needs the witness check either way, so the
  annotation would be the witness check *plus* API write access to every object
  OCP tracks. Took the check, left the write.

## Consequences

- `force: true` means OCP takes fields back from other field managers without
  asking. Anyone editing an OCP-managed resource by hand loses the edit on the
  next apply — deliberately.
- `fieldManager: ocp` is now part of the cluster's state. Renaming it would
  orphan every field OCP currently owns.
- The hash is over the *generated manifest*, not over the cluster, so on its
  own it can only say whether the desired state moved — never whether the
  component is still there. The witness resource carries that half, and the two
  are read together *(amended 2026-08-15, see below)*.
- The witness is a sample, not an inventory. A namespace and one Deployment
  say the component exists; they say nothing about a Service, ConfigMap or
  DaemonSet deleted out of the same manifest. Those are still only noticed when
  the manifest changes, or by the health gate (ADR 0017) if they break a pod.
- Every new hash-gated component owes a witness. `t/47-deployed-state.t` makes
  that structural rather than remembered — it reads the source and requires
  that whatever consults `_load_deployed_hashes` also asks the cluster — but it
  reads `OCP::Cmd::Apply` and `OCP::Cmd::Apply::Drift` only. The readers that
  moved into `Registry` and `Workloads` during the Phase 8 extraction satisfy
  the invariant and are not currently scanned for it (karr #68).
- A second reader of the hash file is a second judge with less evidence, and it
  is wrong in one specific direction. The reconcile path used to form the GPU
  operator's verdict itself, by diffing `.ocp/deployed.yaml` before and after
  the step; that comparison cannot see `restored` at all, so an operator gone
  from the cluster and put back at an unchanged hash reported as "up to date".
  Closed in karr #46 — the outcome vocabulary is now the whole interface
  between a setup step and whoever called it.
- `.ocp/deployed.yaml` is disposable (ADR 0004): losing it costs one full
  redeploy, not correctness. Keeping it past the cluster it describes costs
  more than that, which is why `ocp destroy` removes it.
- Resources whose Kind is not in the resource map fall back to a path built
  from the resource hash, so unregistered CRs (Gateway, ClusterPolicy) still go
  through the same single write path.

## Amendment 2026-08-15

Until this date the third Consequence read:

> The hash is over the *generated manifest*, not over the cluster. A resource
> someone deleted by hand is not noticed until the manifest itself changes;
> drift probes and the health gate (ADR 0017) cover different ground.

It was already only half true when it was written — NFD, the GPU operator and
cert-manager asked the cluster before skipping, the registry was the one that
did not — and karr #43 is what the other half cost. `ocp destroy` left
`.ocp/deployed.yaml` behind; the next `ocp apply`, against a cluster built from
scratch, matched the old hash, announced "Registry already deployed (up to
date)" over an empty `ocp-system`, and pointed CoreDNS at a registry that had
never been rolled out. Nothing on that path returned an error, and the health
gate (ADR 0017) found no broken pods because there were no pods: a component
that is never deployed produces none. That only the registry went missing was
luck — the other three carry distribution-dependent values whose hash changed
with the k3s → RKE2 switch. On the same distribution, destroy + apply would
have skipped everything.

karr #43 closed the gap in the registry, gave the hash file one definition
(`OCP::Config->deployed_file`, removed by `ocp destroy` together with
`status.yaml` — ADR 0004), and rejected the annotation variant recorded above.
`t/47-deployed-state.t` holds the general form.

The decision itself did not change. Convergence is still hash-gated, and the
hash is still the reason the frequently-run reconcile path stays cheap
(ADR 0018). What changed is its standing as evidence — which it never had on
its own. Recorded under karr #47.
