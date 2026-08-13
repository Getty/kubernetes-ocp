# 0003. Drive nodes from one trigger-neutral state machine, arbitrated by a lease

Date: 2026-08-12
Status: accepted

## Context

ADR 0001 gives two things the right to reconcile a node: robocop in its poll
loop, and `ocp apply` when robocop is absent or has not come up. ADR 0002 puts
the node's state in a CR both of them can write.

The obvious implementation — a reconcile loop inside the controller, and a
separate "just do it now" path inside the CLI — produces two codebases for one
lifecycle. They drift, and the divergence is invisible because the CLI path is
the one that gets exercised while the controller path is the one that runs in
production. Worse, if both ever run at once they race: two reconcilers can
provision two servers for one `OCPNode` and the second write silently wins.

## Decision

One class, `OCP::Node`, owns the whole lifecycle
`Pending → Provisioning → Installing → Joining → Ready` plus `Failed`. It is
constructed from a CR (`->from_cr`) with its dependencies injected — provider,
SSH key, join token, server URL, distribution — and knows nothing about who
called it. The caller identifies itself only through `reconciler_id`, which is
`cli` from `ocp apply` and `robocop` from the controller, and which is recorded
in the CR status so a human can see which side moved the node.

Concurrency is arbitrated by a lease held in the CR itself
(`holder@timestamp@ttl`, 300s) and taken with an ordinary update. Because the
update carries the `resourceVersion` that was read, a second reconciler racing
for the same lease gets a 409 from the API server rather than overwriting the
first. Releasing the lease is best-effort: a failed release must not push a node
that was provisioned perfectly well into the terminal `Failed` phase.

A read that fails for any reason other than 404 is fatal. Treating an
unreadable CR as an absent one would take the lease on the strength of a CR
nobody managed to read.

### Alternatives rejected

- **Separate CLI and controller implementations** — two lifecycles to keep in
  step, and the one that runs in production is the one that gets tested least.
- **A `Lease` object in `coordination.k8s.io`** — a second object to garbage
  collect and to keep in step with the CR it guards; the CR is already the
  thing being written, so it is the thing that should carry the guard.
- **No arbitration, "only one reconciler is ever active"** — the CLI fallback
  exists precisely because robocop's presence is not guaranteed, so the
  assumption is untrue by design.

## Consequences

- A bug in the state machine is a bug in both drivers at once. That is the
  point, and it cut both ways: karr #21 found seven broken `Kubernetes::REST`
  calls and a dead dispatch branch — `_provision` wrote `Installing`, but
  `Installing` dispatched to `_wait_ready`, so `_install_kubernetes` was
  reachable only from a phase nobody ever wrote. No agent would ever have been
  installed, in either driver.
- All Kubernetes access in the class funnels through three helpers
  (`_get_cr` / `_put_cr` / `_struct`), and the class no longer knows an
  API version at all — there is nothing left to pass as the wrong argument.
- The 409-collision behaviour has never been observed against a real API
  server; the optimistic concurrency is unverified (karr #29).
- `reconciler` in the status is load-bearing, not decoration: it is how
  "apply wrote the control plane's status, robocop owns workers" (ADR 0009) is
  visible after the fact.
