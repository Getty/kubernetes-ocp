# 0029. Trigger robocop's reconcile from an OCPNode watch through Net::Async::Kubernetes

Date: 2026-09-24
Status: accepted

Supersedes ADR 0021.

## Context

ADR 0021 kept robocop on a poll loop: `while (1)`, list every `OCPNode`,
reconcile each one, then sleep `poll_interval`. It listed two reasons not to
watch:

- **The watch would be fragile.** Reconnects, bookmarks, `resourceVersion`
  expiry and relisting would all have to be correct before a watch was as
  reliable as a timer.
- **The dependency was unproven.** The `Net::Async::Kubernetes` entry in
  `cpanfile` was declared but unused. ADR 0021 kept it as debt with a deadline:
  wire it up or drop it (k1, k2).

On 2026-08-12 the maintainer settled k1: `Net::Async::Kubernetes` would be
fixed, not dropped. He reworked the distribution himself. The agreed order was
to fix the distribution first and redesign robocop after that, with no
robocop architecture work in between. Several tickets were blocked on k1:

- k33: nothing constructed the controller.
- k26: `ocp apply` did not provision workers.
- k2: `ocp inject-key` needed `port_forward`.
- k29 and k31: further work on the worker path.

The poll loop was also not running anywhere. k33 found that `bin/robocop`
ignored its `controller` argument and ended in the CRIU/9999 stub (ADR 0026).
Nothing in the tree ever constructed `OCP::Robocop::Controller`. So the choice
was not between keeping a working poll and adding a watch. The controller had to
be connected for the first time, and the only question was which trigger it
should get.

`Net::Async::Kubernetes` 0.008 answered ADR 0021's reliability objection in the
sibling distribution, where it belongs. Its `Watcher` does the following:

- It reconnects when the server-side timeout expires.
- It resumes from the last `resourceVersion`.
- On `410 Gone` it clears the `resourceVersion` and starts again.

The costs ADR 0021 listed now sit in a library that has its own tests and its
own board. OCP does not have to write them again.

The other half of ADR 0021's reasoning still holds. `OCP::Node` (ADR 0003)
rebuilds everything it needs from the CR on every pass. So the trigger can
change without touching the reconcile code.

## Decision

robocop's reconcile is triggered by a watch on `OCPNode`, through
`Net::Async::Kubernetes` (k33 and k1, commit ce6dacd):

- **`bin/robocop controller` has one entry point.** It builds
  `OCP::Robocop::Controller->from_env`, and `run` hands control to an
  `IO::Async` loop.
- **The watch runs over the async client.** The controller calls
  `$kube->watcher('OCPNode', ...)` on a `Net::Async::Kubernetes` client. That
  client uses the same credentials as the sync client (`_kube_source`: in-cluster
  service account, or a kubeconfig for out-of-cluster tests). Both
  `on_added` and `on_modified` lead to `_reconcile_cr`, and from there to the
  existing `_on_node_event` / `_mark_failed` path.
- **Startup does not need its own pass.** A new watch without a
  `resourceVersion` replays an `ADDED` event for every existing `OCPNode`. So
  nodes that already exist are reconciled at startup, just as the first poll
  pass used to do.
- **Only the trigger changed.** Reconcile stays synchronous on the sync
  Kubernetes::REST client. It covers the lease check and the whole `OCP::Node`
  state machine. The async client is used only for the watch stream (and, since
  k2, for `port_forward`, ADR 0028).
- **The watch cycles every `watch_timeout` (300 s).** At the end of each cycle
  it reconnects and resumes from the last `resourceVersion`.
- **The dependency is pinned.** `cpanfile` requires `Net::Async::Kubernetes`
  `0.008`, and `cpanfile.snapshot` carries it (80f3b36).

### Alternatives rejected

- **Keep the poll loop.** ADR 0021 kept it because a correct watch was
  expensive to build. That cost now sits in the maintained sibling client.
  A poll would also have made `Net::Async::Kubernetes` a dependency that exists
  only for `port_forward`. The maintainer's decision was to use the dependency,
  not to keep it around unused.
- **Drop `Net::Async::Kubernetes`.** The maintainer rejected this on 2026-08-12
  in favour of fixing the distribution. It would also remove `port_forward`,
  and the `inject` key delivery (ADR 0028) depends on it.
- **Make reconcile async in the same step.** This would change the tested
  error handling and the lease path at the same time as the trigger. The watch
  was introduced with the reconcile unchanged. Making reconcile async is a
  separate step, still open.
- **Write reconnect and 410 handling in OCP.** That handling belongs in the
  client library. A decision owned by a sibling is a ticket on that sibling's
  board, not code in this repository.

## Consequences

- **Reconcile starts on events, not on a timer.** Reconcile latency is event
  latency, not up to `poll_interval`. There is no longer a full `OCPNode` list
  every ten seconds.
- **Nothing retries on a schedule.** *(amended 2026-09-24, see below)*
  Reconcile runs only when an event arrives,
  and a resumed watch does not replay unchanged objects. A CR whose problem is
  outside the cluster is not tried again until something writes to it. Examples
  are a provider that was unreachable or an SSH port that was not open yet.
  `Failed` is terminal in `OCP::Node`, so no retry was lost there. Any future
  "wait and try again" behaviour needs an explicit trigger. k2 shows the pattern:
  when a key is injected, it schedules `_reconcile_all`, because nodes that were
  held back get no new event.
- **A long reconcile blocks the whole loop.** *(amended 2026-09-24, see below)*
  The loop is shared, and reconcile
  is synchronous. While a reconcile runs, no other watch event is handled, and
  the `inject` key listener (ADR 0028) does not answer. An `ocp inject-key` sent
  during a long install can hit its timeout. Making reconcile async would fix
  this. Until then, this is the price of changing only the trigger.
- **Correctness depends on the sibling's watch semantics.** If the
  `Net::Async::Kubernetes` watcher has a bug in resuming or in its 410
  handling, robocop misses or replays events. `OCP::Node` tolerates replays.
  Missed events stay missed until the next write to that CR or a restart,
  because a restart replays everything. Such bugs are fixed on the sibling's
  board.
- **The `cpanfile` entry is now accurate.** `Net::Async::Kubernetes` is used,
  and reading the dependency list no longer gives a false picture of the
  architecture, which was the problem ADR 0021 was written about.
- **The CLI path still does not use the watch.** `ocp apply` without a Ready
  robocop still reconciles workers itself, one-shot, through `OCP::Node`
  (ADR 0003).

## Amendment 2026-09-24 (k159)

Two consequences above described the state right after the watch landed and
no longer hold. The decision itself -- the watch is the trigger, `OCP::Node`
stays synchronous and unchanged -- still stands.

- "**A long reconcile blocks the whole loop.** [...] Making reconcile async
  would fix this." It was fixed without making reconcile async. The loop now
  only enqueues; each reconcile runs in a child forked with
  `IO::Async::Loop->fork`, so watch events and the `inject` listener are
  handled while an install runs. A Future-based reconcile was rejected:
  `OCP::Node`, `OCP::SSH` and `OCP::Rex` are synchronous, Rex keeps
  per-process global state, and `OCP::Node` is shared with the CLI. A fork
  keeps all of that as it is, and the child inherits the robo key from memory
  -- the `inject` level gains no new place the key is written. The child
  leaves through `POSIX::_exit`, so it never shuts down the parent's sockets.
  The controller now also owns two rules the lease never covered, because
  every robocop reconcile holds the lease as `robocop`: never two reconciles
  of the same `OCPNode` at once (events meanwhile collapse into one rerun),
  and at most `ROBOCOP_MAX_RECONCILES` (default 2) children at a time. The
  child reads the CR again before it reconciles, so a stale event copy never
  reaches `OCP::Node`.
- "**Nothing retries on a schedule.**" A resync timer now enqueues every
  `ROBOCOP_RESYNC_INTERVAL` seconds (default 60) the `OCPNode`s in `Pending`,
  `Provisioning`, `Installing` or `Joining` that are not being reconciled.
  `Failed` stays terminal, as before; `Ready` and `Terminating` are left
  alone. This also covers a `Joining` node, which writes nothing while it
  waits for its kubelet and so used to wait for an unrelated write.
