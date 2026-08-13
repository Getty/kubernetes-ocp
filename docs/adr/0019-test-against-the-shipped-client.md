# 0019. Test against the shipped client, never against a permissive double

Date: 2026-08-12
Status: accepted

## Context

`t/16-node.t` drove `OCP::Node` against a `FakeK8s` that accepted any call
signature and always returned the same CR. The suite was green for months.

Underneath it, `OCP::Node` was calling `Kubernetes::REST` with an
API-version-first signature that does not exist. The real client feeds argument
zero to `expand_class`, so `get('ocp.internal/v1', 'OCPNode', …)` does not
mis-address the request — it dies with *argument is not a module name*. Seven
call sites were broken this way, `update()` was being handed plain hashrefs it
cannot take, and the state machine had a dead dispatch branch that made agent
installation unreachable. Worker provisioning could never have worked on a real
cluster (karr #21).

There was even a regression test guarding this. It asserted that no call used
`path =>`, by checking that argument zero was a string without a reference —
and `'ocp.internal/v1'` is a string without a reference. It passed on the bug it
existed to prevent.

The lesson is not "the fake was too loose". It is that a double which answers
questions the real thing would refuse cannot be made strict by measuring the
recorded calls more carefully. The permissiveness is the defect.

## Decision

Test against the shipped client with a fake **transport**, not against a fake
client. `t/16-node.t` constructs a real `Kubernetes::REST` and mocks only the
HTTP call. Argument parsing, `expand_class`, path building and `/status`
addressing are done by the code that ships; assertions run against the resulting
verb and path.

`t/43-k8s-call-contract.t` holds the contract itself — API-version-first dies,
Kind-first hits the right paths, `update` refuses hashes — and scans `lib/`
repository-wide for the broken shape.

The same principle governs assertions generally: assert on the mechanism, not on
the text. The `.gitignore` test (ADR 0005) runs `ocp init` in a temp directory
and then runs `git check-ignore` over the four encrypted names, requiring no
match, and over `.ocp/age.key`, requiring one. A regex over the file's text
would pass an over-broad pattern of a shape nobody anticipated.

A fix is only believed when the test fails without it. Each of the seven call
sites was mutation-checked individually and fails in its own named subtest, and
the file goes red against the old `OCP::Node` with the exact production error.

The suite stays flat, numbered, network-free and cluster-free
(`t/NN-topic.t`), so it can run anywhere (ADR 0013). Real-machine verification
lives in `xt/smoke.sh` and is destructive and human-triggered.

### Alternatives rejected

- **Keep the fake, tighten its assertions** — the fake answers what the real
  client refuses; no amount of measuring the recorded calls recovers that.
- **Integration tests against a real API server** — needs a cluster, so the
  suite stops being runnable everywhere; and it would not have caught these
  errors any earlier than the live run did.
- **Type/signature linting instead** — the failure was semantic
  (`expand_class` on an API version), not syntactic.

## Consequences

- Test doubles are now bounded by what the real dependency accepts, so a
  client upgrade that changes a signature turns the suite red instead of
  leaving it green over broken code.
- Writing a test costs more: a mock transport has to answer plausibly, not
  merely record.
- Mocks still cannot show that an agent comes up, that a node registers under
  the expected name, that teardown really removes the machine, or that two
  reconcilers collide with a 409. Those remain unverified and are recorded as
  such (karr #29) rather than implied by a green suite.
- **A real client under the test does not make the fixtures real.** The
  `registry.local` drift probe (ADR 0022) derived the expected address itself
  while the writer put the same value through `Socket::inet_aton` first. Eight
  subtests were green, and `ocp status` reported drift permanently on a
  correctly configured cluster — a name compared against an address — because
  every fixture happened to use a host that *was* its own IP. Only the run
  against the real machine found it. The boundary this ADR does not cross is
  the one the fixtures draw.
- The repair generalises further than the bug: one fact, one derivation
  (`OCP::Drift::resolve_address`), used by writer and reader alike — the same
  discipline already applied to the CoreDNS ConfigMap names (ADR 0016). The
  regression test overrides that shared derivation, so if either side takes its
  own resolution back, only one side follows the override and the test fails.
  Its fixture host is deliberately a name that resolves nowhere: the real one
  resolves from the developer's machine, which would have left the counter-check
  green by accident.
- `xt/smoke.sh` was tightened for the same reason: its old assertion
  `smoke-$DIST|control-plane` was an ERE alternation matching any line
  containing `control-plane`. It now checks phase and IP.
