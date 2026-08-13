# 0022. Report the gap instead of building a second mechanism to close it

Date: 2026-08-12
Status: accepted

## Context

ADR 0016 left one thing open. OCP merges the `registry.local` record into the
Corefile the distribution generates, and the distribution owns that ConfigMap:
a k3s addon re-apply or an RKE2 chart upgrade restores its own default and takes
the record with it. Between that moment and the next `ocp apply`, the name does
not resolve.

The obvious answer is an upgrade-durable record — write it somewhere the
distribution will not reclaim. Before building it, three things were measured.

**The k3s lever exists, and works better than expected.** `coredns-custom` is
mounted at `/etc/coredns/custom` with `optional=true` on the live CoreDNS
deployment, and the stock Corefile imports `*.server` outside the root block, so
a `registry.local:53 { hosts { IP registry.local } }` snippet is legal there
(unlike in `*.override`, which is imported *into* the server block where a
second `hosts` is forbidden). The assumption that a snippet would need a CoreDNS
restart was **refuted**: 1.14.6 hashes the Corefile *after* import expansion, so
the reload plugin picked the snippet up live, in about two seconds.

**The RKE2 lever does not exist.** The `rke2-coredns` chart's ConfigMap template
renders `extraConfig` as a name plus parameters and nothing more — there is no
`configBlock`, so a `hosts { … }` block cannot be expressed through it;
`extraConfig` carries one-liners such as `import`. The only remaining lever is
replacing the whole `servers:` list through a `HelmChartConfig`, and lists do not
merge (rancher/rke2#4940). That means carrying a copy of the chart's default
Corefile inside OCP and re-syncing it for every chart version.

**Running both at once is measurably worse than either alone.** With an inline
record of `10.9.9.9` and a snippet of `10.230.30.155`, CoreDNS answers
`10.230.30.155`: the more specific `registry.local:53` block shadows the inline
record completely. A stale snippet would therefore win silently over the record
OCP keeps correct, and `ocp apply` would report an address the cluster does not
answer with.

And the size of the harm: **no OCP component resolves `registry.local` over
DNS.** Image pulls go through the containerd mirror on `localhost:30501`, and no
pod image on the live cluster references the name at all. The window is quiet.

## Decision

Do not build the second mechanism. The inline merge from ADR 0016 stays the only
writer of this record, on both distributions. Add a probe instead.

`OCP::Drift::registry_dns_drift` reads the CoreDNS ConfigMap and compares the
address the Corefile actually maps `registry.local` to against the address the
writer would use. It reports a missing record and a stale one. It carries
`remedy => undef` and says *"ocp apply restores it"* as a statement rather than
an instruction, because the reconcile path prints it in the middle of the very
apply that is about to fix it — pointing at `ocp update` there would be wrong.

`corefile_host_address` reads the mapping regardless of which block the line
sits in. An operator who adds their own `coredns-custom` snippet therefore
counts as solved and is not nagged about drift. The decision is not that the
snippet is wrong; it is that OCP will not maintain it.

Generalised: when a gap cannot be closed the same way on every supported target
(ADR 0012), and the measured harm is a quiet, self-healing window, report the
gap. A mechanism is earned by a demonstrated failure, not by the existence of a
theoretical one.

### Alternatives rejected

- **`coredns-custom` on k3s plus `HelmChartConfig` on RKE2** — two
  distribution-specific mechanisms where one common one exists, and the RKE2
  half means carrying a copy of a third party's Corefile and re-syncing it per
  chart version. It replaces one verified common path with one verified path
  plus one brittle path.
- **`coredns-custom` on k3s only** — closes the window on one distribution and
  leaves the other exactly as it is, while adding a second mechanism to
  maintain. That is ADR 0012's failure mode: one distribution becoming the real
  one.
- **Both writers side by side, belt and braces** — measured to be actively
  worse. The more specific block shadows the inline record, so the second
  writer silently overrides the one OCP keeps correct. This is ADR 0014's
  two-pins-that-must-agree trap, in mechanism form, and here it was measured
  rather than deduced.
- **Say nothing and rely on self-healing** — the window would remain and be
  invisible, which is the failure mode ADR 0017 exists against.

## Consequences

- The window survives on purpose: after a distribution upgrade, `registry.local`
  does not resolve until the next `ocp apply`. It is now visible in
  `ocp status` and on the reconcile path, and healed by that same apply.
- **The decision rests on a measurement that can go stale.** "Nothing resolves
  `registry.local` over DNS" is true of today's components; the day one does,
  the calculus changes and this ADR has to be revisited. The load-bearing fact
  is that pulls go through the containerd mirror, not through DNS.
- No migration is needed for existing clusters, because no second writer is
  introduced.
- The RKE2 half of the reasoning is derived from the chart template, not
  measured against a running RKE2 cluster.
- The probe's verdict was checked against reality rather than asserted: four
  Corefile states run through real CoreDNS 1.14.6 with the live cluster's own
  Corefile — pristine (probe reports missing / CoreDNS NXDOMAIN), patched
  (clean / answers the right address), stale (reports the stale address /
  CoreDNS answers exactly that), and a hand-built custom block (clean / answers
  correctly). The probe says what CoreDNS actually does in all four.
- OCP now reports a condition it deliberately does not fix outside of `apply`.
  That is a category the drift report did not have before, and it needs to stay
  distinguishable from drift that wants `ocp update`.
