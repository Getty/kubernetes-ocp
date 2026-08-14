# 0026. Robocop is a CRIU / TCP-9999 key-injection stub pending ticket #1

Date: 2026-08-14
Status: snapshot

> This is a snapshot, not a decision. The architecture this ADR names — CRIU
> checkpointing with a TCP-9999 key-injection listener, an in-memory only key,
> a 60-second sleep loop in place of reconciliation — is what `OCP::Robocop`
> ships today. The real reconciliation lives in `OCP::Robocop::Controller`,
> which is **not wired up**. The eventual replacement is ticket #1 (re-add
> `Net::Async::Kubernetes` and replace the stub with a watch loop and a
> `port_forward`-backed key injection). This ADR records the current state so
> the stub is not mistaken for the goal.

## Context

ADR 0001 puts the controller inside the cluster as a `Deployment`. ADR 0006
says the key it gets there is the robo-key, never the admin-key, and is
double-encrypted for the control plane that never sees it. ADR 0021 says
robocop's reconcile path is a poll, and that the `Net::Async::Kubernetes`
dependency it declares in `cpanfile` is **declared and unused** — held as
dated debt because either it gets wired up or it gets dropped, but not built
on.

`lib/OCP/Robocop.pm` is the version of that promise that actually ships today.
It is what `bin/robocop` would run if anyone ran it:

- It forks, dumps itself through CRIU into `/dev/shm/robocop/robocop.criu`,
  holds the SSH key in memory and tries to be restored from the checkpoint on
  the next boot.
- It listens on TCP `0.0.0.0:9999` for a key-injection payload that lives
  nowhere. `ocp inject-key` is the producer that sends it; the producer is
  `OCP::Cmd::InjectKey`, which dies with an explanation that the previous
  `kubectl port-forward` implementation was removed and the
  `Kubernetes::REST::port_forward` reimplementation is pending until robocop
  itself is in active use.
- Once it has a key — by either path — its `start_reconciliation_loop` prints
  "Reconciliation loop not yet implemented!" and `sleep(60)`s forever. There
  is no worker pool, no `OCPNode` CR loop, no provider dispatch.

The real reconciliation logic sits one directory over, in
`OCP::Robocop::Controller::run`, and the comments there now describe a client
the controller cannot build (`Kubernetes::REST 1.106` has no `kubeconfig`
argument and no in-cluster automatism) without first routing through
`OCP::Kubernetes`. The controller compiled once; nothing has called it since;
nothing in the build, the manifest, the deployment or the binary path is
hooked up to it. `bin/robocop`, if it were deployed, would start the CRIU
stub, sleep forever, and reconcile nothing.

Ticket #1 (`Adopt Net::Async::Kubernetes as the watch driver; implement
port_forward; re-enable ocp inject-key`) is the real architectural move. It
supersedes the design this ADR names: it deletes the CRIU/TCP-9999 path,
replaces the sleep with a watch loop, and routes key injection through the
typed Kubernetes client. Until it lands, this ADR is what is shipping, even
though none of it is what the controller should look like.

## Decision

For the moment, the robocop that ships is the CRIU/TCP-9999 sleep-loop stub
in `OCP::Robocop`, and this ADR records three things about it without making
it the goal:

- **The stub is what runs, not what we want.** Anything that depends on
  robocop actually reconciling an `OCPNode` from inside the cluster is, in
  the present state, a request to swap the stub for `OCP::Robocop::Controller`
  first. ADR 0001's promise of a watch-driven reconciliation is honoured
  by ticket #1, not by what is checked in.
- **`ocp inject-key` stays disabled** for the same reason. The producer side
  of TCP-9999 has no current path; the disabled `OCP::Cmd::InjectKey` is the
  explicit reminder of that.
- **No new code is built on top of the stub.** CRIU as the persistence story
  and TCP-9999 as the credential path are recorded here so that adding
  further receivers (CRIU restore on bootstrap, a network policy that depends
  on the listener, a way to provision the checkpoint without the listener)
  is recognised as building on sand, not as building on the architecture.

The rest of the controller — `OCP::Robocop::Controller` and the call graph
it relies on — is documented elsewhere (ADR 0003 for the state machine, ADR
0021 for the polling rationale, ADR 0007 for the Kubernetes API boundary).
This ADR is intentionally narrow: it covers only the stub that is currently
shipped and the ticket that will replace it.

### Alternatives rejected

- **Pull the stub and ship `OCP::Robocop::Controller` instead** — would
  require closing ticket #1 first (typed client, watch loop, port-forward
  key injection). Without those, removing the stub leaves the cluster with
  no robocop at all, which is also not the goal.
- **Promote the stub to "this is the design"** — would commit the project to
  CRIU as the only way to persist an in-cluster SSH key, to TCP-9999 as the
  only way to inject one, and to a sleep loop in place of reconciliation.
  None of those is the controller's eventual shape, and naming them
  authoritative would make the eventual rewrite look like a regression.
- **Rename and forget** — leaving the CRIU path undocumented means the next
  contributor hits `bin/robocop`, sees `sleep(60)`, has no pointer to ticket
  #1, and may either delete the listener (silently breaking key injection
  for any external producer that already exists) or extend it (silently
  building on what is meant to be discarded). The point of the ADR is the
  pointer.
- **Document the design AND the current state in two ADRs** — the design is
  ticket #1's payload and does not yet exist as a written decision. Recording
  it here would be writing a forward reference. When ticket #1 lands, the new
  ADR supersedes this one with a `Status: superseded` line and the
  transition is itself the audit trail.

## Consequences

- Reading `OCP::Robocop` or `bin/robocop` no longer leaves the impression
  that the implementation is a design choice. It is a placeholder; the path
  forward is named; the ticket pointer survives.
- Anyone who needs robocop actually reconciling `OCPNode` from inside the
  cluster has to land ticket #1 first. The dependency is recorded, not
  hidden.
- The CRIU binary dependency is not removed because the stub uses it; that
  change rides in with ticket #1, when the stub goes away. Until then, the
  image carries `criu` because `OCP::Robocop` shells out to it, even though
  no production path exercises the listener.
- The sleep loop is unreachable in practice (the listener never gets a
  producer today), but the image does not depend on any of it ending at a
  timestamp: there is no retry counter, no expiry, no health probe.
- This ADR is the source of truth for what is shipped now. When ticket #1
  is closed, the new ADR takes the same number's status to `superseded` and
  the audit trail of the swap is the diff between the two.
- The CRIU/TCP-9999 design will not be modified in place. If ticket #1 is
  deferred again, this stub stays as it is; the alternative — improving the
  stub toward a design we don't want — is the failure mode this ADR is
  written against.
