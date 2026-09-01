# 0025. Pin the same Perl patch release in image, snapshot and runtime

Date: 2026-08-14
Status: accepted

## Context

OCP's toolchain runs inside Docker (ADR 0013). The exact Perl that builds the
image and the exact Perl that resolves the snapshot have to be the same one,
because the dependencies they install are bound to that Perl's ABI.

Three places currently name a Perl:

- `Dockerfile:21` — `FROM perl:5.42.3-slim-trixie AS ocp-base`.
- `Makefile:snapshot` — runs `carton install` inside `perl:5.42` (a major.minor
  tag, no patch).
- `cpanfile` — declares no Perl version floor; the only constraints are on
  Getty-authored CPAN modules (`WWW::Hetzner 0.100`, `IO::K8s 1.105`,
  `Kubernetes::REST 1.106`, `CryptX 0.091`, …).

The base image was changed for exactly this reason: the `Dockerfile` used to
build Perl 5.42.0 from source against a snapshot that resolved in `perl:5.42`.
The source-built Perl and the snapshot's Perl differed in `useshrplib` and in
maintenance release, so XS modules compiled against the image's ABI refused to
load against the snapshot's Perl, and vice versa. The `perl:5.42.3-slim-trixie`
swap closes that — the snapshot Perl and the image Perl are now the same
binary, non-threaded, shared-libperl, 5.42.3.

The remaining gap is the other side of the same coupling. If a CPAN
dependency is released and its `cpanfile` snippet is bumped to require a Perl
the image does not carry, `cpm install --cpanfile=…./cpanfile.snapshot` breaks
silently in CI: the snapshot is regenerated against a Perl the shipped image
does not run. The current pinning is downward (Getty modules must be at least
the version we picked), and there is no upward pin on the host Perl.

The `Makefile:snapshot` form (`perl:5.42`) is coarser than the Dockerfile's
(`perl:5.42.3-slim-trixie`). On a quiet day they resolve to the same
maintenance release. The day 5.42.4 ships, the snapshot will move and the
image will not.

## Decision

The Perl that builds the image, the Perl that resolves the snapshot, and the
Perl the image runs are versionally one release, and they are pinned on every
side where the chain can drift. *(amended 2026-08-17, see below)*

Concretely:

- **`Dockerfile:21`** carries the exact tag — the patch level is in the tag
  itself (`perl:5.42.3-slim-trixie`). ADR 0014's "pin every artifact exactly
  once" applies to this Perl the same way it applies to cilium or nfd: the
  base image is an artifact, and the artifact's identity is the digest behind
  that tag.
- **`Makefile:snapshot`** names the same tag literal. A future change to
  5.42.x or to 5.44 changes both files together. The snapshot image being a
  different repository (`perl:5.42`) is a documented follow-up, not an
  oversight.
- **`cpanfile`** declares `perl 5.042003` (Carton form) as a runtime floor.
  *(amended 2026-08-17, see below)*
  Below the floor the floor is meaningless — `carton install` checks it, the
  snapshot records it, and an upgrade that lands a `perl 5.044` requirement
  fails the snapshot regenerator visibly instead of silently producing a
  snapshot that ships a Perl the image lacks.
- A change to the floor is a coordinated change to the three artefacts: the
  Dockerfile tag, the Makefile tag, the cpanfile floor, and the version
  readme note. The change is communicated in `Changes` because it is a binary-
  ABI event that affects every XS module in the image.

### Alternatives rejected

- **No floor in `cpanfile`.** The current state, and the source of the risk
  this ADR names. The image and the snapshot defend each other through
  matching tags, but a CPAN upgrade that wants a newer Perl breaks the
  pairing invisibly — `cpm install` either errors against the snapshot's Perl
  or succeeds against a re-resolved snapshot and lands a `cpanfile.snapshot`
  that describes a Perl the image does not have.
- **Floor at `5.42` (major.minor) instead of `5.42.3` (patch).**
  *(amended 2026-08-17, see below)* Matches `Makefile:snapshot`'s current
  wording. Loses the guarantee that a same-day
  maintenance release (5.42.4, 5.42.5, …) is in lockstep with the snapshot.
  The Dockerfile already names the patch; matching it in `cpanfile` is free.
- **Floor at `5.44` to leave headroom for `Rex`'s Perl requirements.** Rex's
  current `cpanfile` does not require 5.44. Speculative headroom is just
  over-pinning: when a real dependency requires 5.44, the floor moves with it
  and `Changes` records the move, and the image and snapshot move with it.
- **A wrapper CI job that re-resolves the snapshot whenever a CPAN
  dependency wants a new Perl.** A daily-script approach that does not
  distinguish "CPAN got noisier" from "CPAN actually raised the floor" is the
  same silent break, just dressed in automation. The floor is the floor.

## Consequences

- A CPAN release that asks for `perl 5.044` will fail the snapshot
  regenerator in CI, not in production. The visible failure is what this ADR
  is for. *(amended 2026-08-17, see below)*
- `carton install --deployment` (used in CI) is allowed to disagree with the
  snapshot's Perl because the snapshot pins Perl, not the other way around.
- The floor is in the same file as the dependency declarations, which means
  a contributor who adds a CPAN dep with a Perl bump sees the floor change
  in the same diff. That is the point: a Perl bump is a coordinated event.
- The base image tag is now load-bearing across three files. A drive-by
  change to any one of them is a breaking change to the others.
- ADR 0013 already forbids running `carton install` on the host; this ADR
  adds that the Perl the snapshot is regenerated against must also be the
  Perl the image runs, and the floor in `cpanfile` is the contract.
- The Dockerfile comment block that explains the base-image choice (lines
  5–20) was written against an earlier version of this decision; it is the
  in-code companion to this ADR and is not duplicated here.

## Amendment 2026-08-17 (karr #125)

Two things here did not survive review: what the `cpanfile` floor mechanically
does, and the value it was set to. The decision — one Perl for the image and the
snapshot, pinned where the chain can drift — stands.

### The floor does not do what this ADR credits it with

The Decision said, and the Consequences repeated:

> **`cpanfile`** declares `perl 5.042003` (Carton form) as a runtime floor.
> Below the floor the floor is meaningless — `carton install` checks it, the
> snapshot records it, and an upgrade that lands a `perl 5.044` requirement
> fails the snapshot regenerator visibly instead of silently producing a
> snapshot that ships a Perl the image lacks.

> A CPAN release that asks for `perl 5.044` will fail the snapshot regenerator
> in CI, not in production. The visible failure is what this ADR is for.

A `requires 'perl', …` line is a lower bound on *this* distribution. It says
nothing about what a dependency requires, and it cannot fail on a dependency
asking for more. What actually catches the `perl 5.044` case is the other half
of this ADR: `Makefile:snapshot` resolving inside `perl:5.42.3-slim-trixie`.
Regenerate there and the dependency's own requirement is unsatisfiable in that
container — visibly, in CI, which is the outcome this ADR wanted. The floor was
credited with work the image tag was already doing.

What the floor does buy is real, just smaller: the snapshot cannot be resolved
and the distribution cannot be installed on a Perl *older* than the baseline,
and the baseline is written down next to the dependencies bound to it. That is
the claim it can carry. (The sentence "Below the floor the floor is meaningless"
was garbled on the way in; the intended reading is that below the floor nothing
installs at all.)

### The floor was set from a machine that is no longer the development machine

`5.042003` matched the Perl of the machine this ADR was written on (pikachu, a
custom Perl build). Development has since moved to reuben, whose system Perl is
5.40.1 — below the declared floor. That is not cosmetic: `@Author::GETTY` loads
`Prereqs::FromCPANfile`, so the floor is not a note to the reader, it lands in
`META` as `MIN_PERL_VERSION`. `make test-host` and `dzil build` on the
development machine then run below the distribution's own baseline.

Maintainer decision 2026-08-17: the floor drops to `5.040001`, the system Perl
of the current machine. With it falls the reasoning of the rejected alternative
"Floor at `5.42` (major.minor)" — the argument there was that matching the
Dockerfile's patch level is free. The floor no longer tracks the image tag at
all; it tracks the oldest Perl OCP is expected to run on, which is the
development machine's.

The lockstep this ADR is about is untouched: it holds between `Dockerfile:21`
and `Makefile:snapshot`, the two places naming the Perl the artifact is built
and shipped with. The floor was never part of that pair and could not have
been — `cpanfile` has no upper bound to give.

Stated plainly, so the next reader does not take it for drift: image (5.42.3)
and floor (5.40.1) differ on purpose. A green `make test-host` says "runs on
the baseline", a green `make test` says "runs on what ships", and only the
second one binds (ADR 0013).
