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
sits in *(amended 2026-11-07, see below)*. An operator who adds their own
`coredns-custom` snippet therefore counts as solved and is not nagged about
drift *(amended 2026-11-07, see below)*. The decision is not that the snippet
is wrong; it is that OCP will not maintain it.

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

## Amendment 2026-11-07 (k392)

Until this date the third paragraph under `## Decision` read:

> `corefile_host_address` reads the mapping regardless of which block the line
> sits in. An operator who adds their own `coredns-custom` snippet therefore
> counts as solved and is not nagged about drift. The decision is not that the
> snippet is wrong; it is that OCP will not maintain it.

The first sentence described the code exactly. `corefile_host_address` took
the first line anywhere in the Corefile that mapped the name (60aa766). That
is not how CoreDNS reads a Corefile, and this ADR's own Context had measured
why: a `registry.local:53` block shadows the inline record. With the right
inline record and a stale block of its own for the name, the probe met the
inline record first and reported nothing, while CoreDNS answered with the
stale address. That is the silent win this ADR rejected two writers for, and
it sat in the probe. None of the four states under Consequences had both.

The second sentence was not true on the day it was written. A
`coredns-custom` snippet lives in a ConfigMap of its own, and
`registry_dns_drift` read only the `Corefile` key of the CoreDNS ConfigMap
(60aa766, unchanged until k338). Neither the probe nor the writer saw a
snippet there. A k3s cluster whose inline record had been reset, and whose
snippet answered correctly, was reported as missing the record. What did count
as solved was a server block written into the Corefile itself. k19's offline
table has a row in which the probe answers correctly for a snippet. The
function was right about the text it was given, but on a cluster the probe
never gave it that text.

k338 (5ea2861) and k348 (79e24e3) made the paragraph's intent true. The writer
(`OCP::Cmd::Apply::Network::configure_registry_dns`) and the probe now read
the Corefile through one parser, `OCP::Corefile`:

- **The answering block.** `registry.local` is read from the server block
  CoreDNS answers it from: of the blocks whose zone covers the name, the most
  specific one, the root zone covering every name (`block_for`). A record
  anywhere else does not count. Only blocks for plain DNS on port 53 answer
  (`on_cluster_port`). A block on another port or transport neither answers
  nor shadows.
- **`coredns-custom`.** Where the Corefile has a top-level `import` from
  `/etc/coredns/custom/`, both sides read `kube-system/coredns-custom` and take
  the `*.server` snippets the import names as server blocks of the Corefile
  (`OCP::Drift::corefile_imports_custom`). k3s's stock Corefile has that
  import. The RKE2 chart's has none, so on RKE2 nothing changes.
- **A snippet that maps the name to the control plane counts as solved.** There
  is no drift, and the writer does nothing. One that maps it elsewhere, or has
  no record for it, is a `spec` entry with a `manual_step` and no remedy, named
  with the ConfigMap key it is in. That is drift `ocp apply` does not close.
  The writer does not write a root-block record the snippet would shadow. It
  says why, as a `[WARN]` on STDERR.
- **OCP still does not write or maintain the snippet.** It writes only the
  inline record in the Corefile's root block. `coredns-custom` is only read.
- **`*.override` files are not read.** k3s imports them inside the root block,
  as plugin lines rather than as server blocks, and `OCP::Corefile` expands
  only top-level imports (`t/338-registry-dns-one-reading.t` holds that). A
  second `hosts` there is what this ADR's Context already ruled out.

The decision did not move. OCP writes the record in one place, and the snippet
is still the operator's to maintain. What moved is what the probe sees, and
with it the case this ADR held against running two writers: a stale snippet
that shadows the correct inline record is now reported, not silent. It is
reported as a third kind of entry next to the two the last Consequence keeps
apart, a condition that neither `ocp apply` nor `ocp update` closes. The
Consequence that the probe says what CoreDNS does "in all four" states stays
as written, because it is true of those four. `t/338-registry-dns-one-reading.t`
drives the writer and the probe over the shadowing state and the k348 cases,
and asserts that they agree. Neither k338 nor k348 records a run against a
live cluster. Recorded under k392.
