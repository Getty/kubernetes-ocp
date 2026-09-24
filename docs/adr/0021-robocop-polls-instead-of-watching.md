# 0021. Keep robocop polling, and hold the watch dependency as dated debt

Date: 2026-08-12
Status: superseded by [ADR 0029](0029-robocop-watches-ocpnode-through-net-async-kubernetes.md) (2026-09-24, k158)

## Context

robocop is a Kubernetes controller (ADR 0001), and controllers watch. OCP
declares `Net::Async::Kubernetes` in `cpanfile` and `IO::Async` alongside it,
which is what a watch loop would need.

Neither is used. `OCP::Robocop::Controller::run` is a `while (1)` that lists
`OCPNode` CRs, reconciles each one, and sleeps `poll_interval` (10s). The async
dependencies are declared and inert.

That is not, by itself, a problem worth solving. The reconcile unit is
`OCP::Node` (ADR 0003), which is a state machine over a CR, not an event
handler — it re-derives everything it needs from the CR on each pass and is
correct whether it was triggered by a watch event or by a timer. The workload is
a handful of nodes, so the poll costs one list call every ten seconds. A watch
adds reconnection, bookmark handling, resourceVersion-too-old recovery and
relist-on-desync, all of which have to be right before the loop is even as
reliable as the timer.

But the *declared and unused* dependency is a real cost. It reads as a
capability that exists, and something was built on that reading: `ocp inject-key`
needs a port-forward, was written against one, and is now disabled because the
client has none.

## Decision

Keep the poll loop. A ten-second timer over a state machine that is correct on
every pass is adequate for the cluster sizes OCP targets, and the reconcile code
does not change if a watch replaces the trigger later.

Record the dependency as debt with an expiry rather than as architecture: either
implement the watch loop and `port_forward` — redeeming `ocp inject-key` with it
— or drop `Net::Async::Kubernetes` from `cpanfile` (k1, k2). Do not
build anything further on the assumption that it is wired up.

### Alternatives rejected

- **Implement the watch now** — reconnect, bookmarks, `resourceVersion` expiry
  and relist are all required for it to match a timer's reliability, and the
  observed workload does not justify that yet.
- **Drop the dependency immediately** — the port-forward is still wanted for
  `ocp inject-key`, which is the mechanism that makes the two-tier key model
  (ADR 0006) real in-cluster.
- **Leave it undocumented** — the last time this was left implicit, a command
  was written against a capability that did not exist and had to be disabled.

## Consequences

- Reconcile latency is up to `poll_interval`. Nothing in OCP needs sub-second
  reaction.
- Every pass costs a full list of `OCPNode` CRs in the namespace. That scales
  with node count, and would not at watch-sized clusters.
- `ocp inject-key` stays disabled and dies with an explanation, so the robo-key
  is never actually delivered into the cluster (ADR 0006) *(amended 2026-09-24,
  see below)*.
- `cpanfile` claims a capability the code does not have. Anyone reading the
  dependency list to infer the architecture will infer wrongly, which is
  precisely why this is written down.
- The choice is reversible at low cost: only the trigger changes, not
  `OCP::Node`.

## Amendment 2026-09-24

This ADR said under `## Consequences`:

> `ocp inject-key` stays disabled and dies with an explanation, so the robo-key
> is never actually delivered into the cluster (ADR 0006).

That is no longer true. k129 delivers the robo key through the
`robocop-credentials` Secret (`robocop.security_level` `secret` /
`secret_approved`). k2 rebuilt `ocp inject-key` on `Net::Async::Kubernetes`
`port_forward` for the `inject` level. ADR 0028 records that design.
`port_forward` was the half of the dated debt that was wanted for
`ocp inject-key`, and it is now paid.

This amendment covers only that consequence. Whether this ADR's own decision,
to keep the poll loop, still stands after k1 wired up the watch driver is a
separate question and is not settled here.
