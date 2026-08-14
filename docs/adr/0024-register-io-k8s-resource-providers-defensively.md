# 0024. Register IO::K8s resource providers defensively, and live with raw YAML where they are absent

Date: 2026-08-14
Status: accepted

## Context

`OCP::Kubernetes` is the single typed Kubernetes helper the CLI shares
between code paths, and `_build_api` calls
`register_resource_providers($api)` after the client is built. The
registration loops over three providers:

```perl
for my $provider (qw(
    IO::K8s::Cilium
    IO::K8s::CertManager
    IO::K8s::GatewayAPI
)) {
    eval "require $provider; 1" or next;
    eval { $api->k8s->add($provider) };
}
```

Both the `require` and the `add()` are wrapped in `eval`. A failure on either
side is silently discarded: the loop continues with the next provider, and a
provider that never loads is not even mentioned in the log.

The asymmetry is what makes this odd. ADR 0010 declares Cilium the whole
network layer; ADR 0011 keeps Helm off the runtime path; ADR 0008 writes every
resource through Server-Side Apply with `fieldManager: ocp`. All three
presuppose that `IO::K8s::Cilium`, `IO::K8s::CertManager` and `IO::K8s::GatewayAPI`
load — the typed shape exists *for those kinds*. A missing provider means a
hand-written YAML fallback, which is precisely what the typed layer was added
to retire.

And yet a missing provider is not a fatal error. `OCP::Kubernetes` is also the
helper a single-node, SSH-only cluster uses to read its own node back and
nothing else, and a CI host that builds the snapshot does not need Cilium
typed objects at all.

## Decision

Registering typed resource providers is best-effort, with two failure modes
that are deliberate:

- **`require $provider` fails.** The provider is not installed in this Perl.
  The loop moves on. On a full cluster this would be wrong; on a CI host, a
  single-node cluster or a debugging checkout, this is the normal state. The
  failure is swallowed because no caller has the wrong expectation here: a
  caller that wants the typed shape must already have a reason to want it, and
  the absence falls back to the untyped YAML path that pre-existed.
- **`$api->k8s->add($provider)` fails.** The provider is installed but the
  client refuses to register it. Same handling: the loop moves on. The
  failure today happens with stale `IO::K8s` versions that lack a particular
  sub-namespace; an installation that is otherwise healthy would then
  silently fall back to raw YAML for that kind.

The cost of both is named: where a provider is absent, every write for that
Kind goes through the YAML string instead of the typed object, and the SSA
helper (ADR 0008) accepts either. Reads that produce typed objects return
untyped structures instead, and callers that branch on `object_to_struct`
have to accept `undef`. None of this is silently worse than the previous
behaviour — the untyped path is the previous behaviour — but the asymmetry
between "Cilium is mandatory" (ADR 0010) and "Cilium provider is optional"
(now) is recorded here so it does not have to be rediscovered.

### Alternatives rejected

- **Fail-loud on a missing provider.** Forces every shared-path caller —
  including the single-node, SSH-only case that does not have Cilium — to
  declare its intent up front. The shared helper then cannot be shared; every
  caller ends up carrying its own bootstrap, and one of them will be a copy
  of the same defensive code that the loop already runs.
- **Fail-loud on `add()` but not on `require`.** The easier half to justify
  is the wrong half: a `require` failure is exactly the CI/test case where
  loud is wasteful, and an `add()` failure is exactly the case where the
  install is otherwise complete and the user wants to see why. Splitting the
  two adds a policy that does not match what callers actually do.
- **Always install the three sub-modules transitively.** Costs a CPAN edge
  for users who never need typed Cilium, and forces the cpanfile to carry a
  guarantee about a sub-package layout that is not `OCP`'s to make. The
  `require` already does the right thing: it succeeds exactly when the
  package is on disk.
- **Remove the loop entirely and require typed calls to declare their
  provider.** That is a different architecture — every typed call site names
  what it needs — and there is no demand for it yet. Today every typed call
  site *would* name the same three.

## Consequences

- A full cluster is expected to ship with all three providers installed, and
  is checked at `make snapshot` time (the snapshot is generated in
  `perl:5.42`, and `IO::K8s` declares its sub-modules). A cluster that
  somehow boots without them still works on the YAML path; the resource map
  carries the Kinds (CiliumNetworkPolicy, Certificate, Gateway, HTTPRoute,
  …) without the dispatch tables. Drift detection (ADR 0022's
  `OCP::Drift::registry_dns_drift`-style probes) is unaffected.
- The defensive loop hides two distinct bugs behind one silence. A future
  diagnostic logging at `-v` would help, but it deliberately sits below the
  current logging surface because the same loop runs on every API handle.
- `Kubernetes::REST` does not currently distinguish "provider not installed"
  from "provider refused" in its event channel; if that ever changes, the
  finer signal is reason enough to revisit this ADR.
- ADR 0010's "Cilium is mandatory" and this ADR's "Cilium provider is
  optional" coexist on purpose. Mandatory in the cluster, optional at the
  Perl boundary. The price of that split is one silent fallback, and the
  test suite exercises the typed path every time `OCP::Kubernetes` is mocked
  (the mocks ship typed objects because that is what a real cluster hands
  back).
