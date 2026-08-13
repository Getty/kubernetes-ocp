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

The test suite is the one thing that runs either way: `make test` is plain
`prove -l t/` because the suite is mock-based, network-free and cluster-free
(ADR 0019), and `make docker-test` checks the image itself.

### Alternatives rejected

- **Host toolchain with a documented "recommended" Perl** — the snapshot still
  describes a host, and the recommendation is unenforceable.
- **No snapshot, resolve at build time** — the image stops being reproducible,
  and a broken upstream release becomes a broken build with no way back.
- **Everything including tests only in Docker** — makes the fast inner loop slow
  for a suite that touches nothing outside its temp directories.

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
