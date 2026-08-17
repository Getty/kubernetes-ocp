# 0013. Run the toolchain inside Docker

Date: 2026-08-12
Status: accepted

## Context

OCP is a CPAN distribution with real system dependencies — LibSSH, OpenSSL,
expat, zlib — and a `cpanfile.snapshot` that is supposed to describe one exact
dependency set. It is also shipped and run as a Docker image; that is the
primary way users install it.

Resolving dependencies on the developer's host produces a snapshot that
describes the host: its Perl, its already-installed modules, its system library
versions. Two developers regenerate it and get two different files. Worse, the
snapshot then no longer describes the image that ships, so "works here" and
"works in the image" diverge silently.

Running `ocp` itself from a host checkout has the same problem one level up: the
module versions it loads are whatever the host CPAN happens to hold, not what
the pinned snapshot says.

## Decision

The dependency toolchain runs inside Docker, never on the host. `make snapshot`
regenerates `cpanfile.snapshot` in a `perl:5.42` container with the project
mounted, installing the system packages first and running `carton install`
there, so the refreshed snapshot lands on the host having been resolved in the
image's world. `carton install` and `cpm` are not run on the host.

Running `ocp` for real happens in the image.

A missing Docker-ised Make target gets added; it does not get worked around
with a host command.

`cpanfile` is the source of truth for dependencies, and Getty-authored
distributions are pinned to exact released versions there.

The test suite is binding inside Docker and available as a host run that does
not bind. `make test` runs `prove -l t/` *in the pinned image*; the suite is
mock-based, network-free and cluster-free (ADR 0019), and running it in the
image is what makes its result describe what the release will actually run
against. `make test-host` runs the same suite against whatever CPAN happens to
be installed on the developer's machine — it stays because the fast iteration
loop matters, but its result does not bind and it has been wrong (karr #79).
`make docker-test` checks that the image itself starts. *Amended 2026-08-17 —
see below.*

### Alternatives rejected

- **Host toolchain with a documented "recommended" Perl** — the snapshot still
  describes a host, and the recommendation is unenforceable.
- **No snapshot, resolve at build time** — the image stops being reproducible,
  and a broken upstream release becomes a broken build with no way back.
- **Everything including tests only in Docker** — argued, when this ADR was
  written, to make the fast inner loop slow. The 2026-08-16 measurement
  (karr #79, replicated 2026-08-17): `make test` (pinned image) 159 s wall,
  53.51 CPU; `make test-host` (host CPAN) 160 s wall, 53.77 CPU — delta
  0.5 %. The container is not the slow lane; the argument did not survive
  measurement and so is rejected in form but not in fact. *Amended
  2026-08-17 — see below.*

## Consequences

- Contributing requires Docker. There is no supported host-only path.
- `make snapshot` is slow: it installs build dependencies from scratch each
  time.
- `make smoke` and `ocp apply`/`ocp destroy` against a real project directory
  touch real, paid infrastructure, and are human-triggered only. Neither belongs
  in `t/`.
- Publishing (`make docker-push`, `make docker-release`, `dzil release`) is
  deliberately separate from building and never runs without explicit
  permission.
- The image must exist for the architecture being targeted, which is where this
  meets ADR 0020: the published images are amd64-only today, so robocop cannot
  be deployed on an arm64 cluster (karr #10).

## Amendment 2026-08-17 (karr #107)

This ADR was written assuming a binding `make test` outside the image and a
non-binding image run, with a rejected alternative of "everything including
tests only in Docker" because "it makes the fast inner loop slow". All three
of those sentences need to be re-read against the post-#79 state of the
Makefile: binding is now `make test` *in* the image, `make test-host` is the
non-binding escape hatch, and the rejected alternative is what `make test`
actually does. The decision (Docker-first for everything else, image for the
host tools, install, snapshot) is unchanged; what changed is which side of
the test boundary is binding and the rationale for that choice.

The "slow loop" claim did not survive a stopwatch. Two side-by-side runs on
the same tree, same wall-clock window, against the post-#79 targets:

  make test (pinned image)        159 s wall   53.51 CPU   Files=65  Tests=1123
  make test-host (host CPAN)      160 s wall   53.77 CPU   Files=65  Tests=1123

Per-file results identical, zero skips, identical exit code. The 0.5 % delta
is well inside measurement noise and well below the run-to-run variance
that motivated karr #79 in the first place. What `make test` buys is not
slowdown; it is the interpreter and module graph the release will actually
execute under. On 2026-08-15 the host ran Perl 5.36.000 against module
versions that had drifted past the snapshot's pins, and produced a green
result that did not bind; the binding run is the image's 5.42.003 against
the pin (the pin ADR 0025 puts in `cpanfile`). That is the criterion the
ADR was implicitly relying on; the prose just did not say so.

Two intentional non-changes. Consequences bullet 1 ("Contributing requires
Docker. There is no supported host-only path.") was already too strong given
the existence of `make test-host`; the amendment reflects that
`test-host` is the supported escape hatch (not a path — the result does
not bind). The ADR does not retract the consequences list; it treats the
host side as documented fast-iteration tooling rather than a second
binding lane. `.github/workflows/` no longer exists at all (see ADR 0020
amendment), and that is unrelated to test binding — the measure above is
the relevant number now.
