# 0009. Write CR status only through the /status subresource, and record who wrote it

Date: 2026-08-12
Status: accepted

## Context

`OCPNode` declares `subresources: {status: {}}`. Once a CRD does that, the API
server **silently discards** the `status` stanza of every write aimed at the
main resource endpoint — create, update, merge-patch and server-side apply
alike — and answers 2xx. Nothing looks wrong at the call site.

That is not a theory. On a real cluster (karr #16), `ocp apply` printed
`ensured OCPNode/cortex (control-plane, Ready)` while the stored CR had no
`status` key at all, and `ocp node ls` correctly reported `Pending` with an
empty IP. Three views of one node disagreed, and the one telling the truth
looked like the broken one. The same defect meant `OCP::Node::_patch_status`
had never persisted a single worker phase either.

There is a second question underneath: for a node that robocop does not own —
the control plane the CLI bootstrapped itself — who writes the status at all?
robocop reconciles workers only, and on a single-node cluster it may not run.

## Decision

Status goes through the `/status` endpoint, and through exactly one function:
`OCP::K8s->patch_status`. It is the only place in OCP allowed to reach for the
raw `_request` escape, because `Kubernetes::REST` cannot address a subresource
(ADR 0007 — the ticket lives on that distribution's board). It prefers a native
`patch_status` if the client ever grows one.

Spec and status are therefore written separately: `_ensure_cp_ocpnode` and
`_migrate_legacy_nodes` ensure the spec, then patch the status.

Ownership is explicit. `ocp apply` writes the status of the control plane it
bootstrapped, observationally, stamped `reconciler: cli`. robocop writes worker
statuses, stamped `reconciler: robocop`. The IP written is the one read off the
Kubernetes `Node` object, not the host from the configuration — the
configuration may hold a DNS name.

`ocp apply` no longer claims `Ready` when the status write fails.

### Alternatives rejected

- **Drop the status subresource from the CRD** — then any client could
  overwrite observed state with a spec edit, and the CR would lose its
  RBAC split between "who may ask for a node" and "who may report on one".
- **Let robocop own every status, including the control plane's** — robocop is
  opt-in and frequently absent (ADR 0001), so the control plane would stay
  `Pending` forever on exactly the simplest clusters.
- **Scatter `_request` escapes where needed** — one silent-failure class per
  call site, and nothing for a test fake to stub.

## Consequences

- Every status write costs a second round trip after the spec write.
- Test fakes stub `patch_status` rather than emulating a transport.
- `reconciler` is now the evidence for which side moved a node, and the
  CRD carries `lastReconcileTime` alongside it.
- The class of bug remains latent for any future CRD that enables the status
  subresource: a 2xx that dropped the payload. The single seam is the only
  defence, so a new writer must go through it.
