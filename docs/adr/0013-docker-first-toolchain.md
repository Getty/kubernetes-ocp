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
loop matters, but its result does not bind and it has been wrong (k79).
`make docker-test` checks that the image itself starts. *Amended 2026-08-17 —
see below.*

### Alternatives rejected

- **Host toolchain with a documented "recommended" Perl** — the snapshot still
  describes a host, and the recommendation is unenforceable.
- **No snapshot, resolve at build time** — the image stops being reproducible,
  and a broken upstream release becomes a broken build with no way back.
- **Everything including tests only in Docker** — argued, when this ADR was
  written, to make the fast inner loop slow. The 2026-08-16 measurement
  (k79, replicated 2026-08-17): `make test` (pinned image) 159 s wall,
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
  permission *(amended 2026-11-06, see below)*.
- The image must exist for the architecture being targeted, which is where this
  meets ADR 0020: the published images are amd64-only today, so robocop cannot
  be deployed on an arm64 cluster (k10).

## Amendment 2026-08-17 (k107)

This ADR was written assuming a binding `make test` outside the image and a
non-binding image run, with a rejected alternative of "everything including
tests only in Docker" because "it makes the fast inner loop slow". All three
of those sentences need to be re-read against the post-k79 state of the
Makefile: binding is now `make test` *in* the image, `make test-host` is the
non-binding escape hatch, and the rejected alternative is what `make test`
actually does. The decision (Docker-first for everything else, image for the
host tools, install, snapshot) is unchanged; what changed is which side of
the test boundary is binding and the rationale for that choice.

The "slow loop" claim did not survive a stopwatch. Two side-by-side runs on
the same tree, same wall-clock window, against the post-k79 targets (on the
development machine of the time — see "Where the numbers come from" below):

  make test (pinned image)        159 s wall   53.51 CPU   Files=65  Tests=1123
  make test-host (host CPAN)      160 s wall   53.77 CPU   Files=65  Tests=1123

Per-file results identical, zero skips, identical exit code. The 0.5 % delta
is well inside measurement noise and well below the run-to-run variance
that motivated k79 in the first place. What `make test` buys is not
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
amendment) *(amended 2026-11-06, see below)*, and that is unrelated to test
binding — the measure above is the relevant number now.

### Where the numbers come from (added 2026-08-17, k107)

The two runs above were measured on the development machine of the time:
pikachu, whose host Perl was a custom build — the 5.36.000 named above. Since
then development moved to reuben, whose system Perl is 5.40.1, and the pair does
not reproduce there: `make test-host` aborts within seconds because the host
CPAN has no MooX::Singleton and no WWW::Hetzner::Cloud, so there is no 160 s
host run to hold the image run against.

This does not weaken the conclusion — a host lane that cannot even load the
distribution is the strongest form of "the host run does not bind" this ADR
could have asked for. It does mean the figures are bound to the machine that
produced them and have to be read with it. Whoever re-checks the 0.5 % delta
measures on their own box; the number is evidence for "the container is not the
slow lane", not a constant of the repository.

The Perl gap the amendment leans on moved with the machine and is smaller now:
reuben's 5.40.1 against the image's 5.42.3, not 5.36 against 5.42. The argument
is unchanged — the host interpreter is still not the one that ships — and the
floor in `cpanfile` follows the development machine rather than the image
(ADR 0025, amended 2026-08-17).

## Amendment 2026-11-06 (k405)

The fourth Consequence reads:

> - Publishing (`make docker-push`, `make docker-release`, `dzil release`) is
>   deliberately separate from building and never runs without explicit
>   permission.

It names the Make targets and the release, and says nothing about CI. For
CI it has not always been true.

When this ADR was written, `.github/workflows/docker-publish.yml` was set up
to publish the image on every push to `main`. On 2026-08-14, df5b0cf deleted
it, because the maintainer wanted publishing to be a manual, controlled step
and not something every push to `main` does. From then on the bullet held,
and the 2026-08-17 amendment could say that `.github/workflows/` no longer
existed.

k134 brought CI back. Its `.cicd/` scripts run through SimpiCI from
`.github/workflows/ci.yml`, one job per registry. `docker+29+build.image.sh`
builds the image and pushes nothing. `docker+29+publish.image.sh` pushes it,
and states its own policy: `main` and tags publish, nothing else does. The
k134 card said that an automatic push from CI would be a policy decision, to
be taken there explicitly. It records the policy the scripts implement, not a
decision by the maintainer to publish from `main`. The scripts were written on
2026-09-04 and reached `main` on 2026-09-18. The maintainer had put the Docker
Hub credentials into the GitHub repository on 2026-09-04, as the secret
`DOCKERHUB_TOKEN` and the variable `DOCKERHUB_USER`. GHCR needs nothing beyond
the run's own `GITHUB_TOKEN`.

From 2026-09-18 on, the publish policy therefore covered every push to
`main`. A publish needs a green build first, and `main` was red until at least
2026-09-23 (run 35692604890, the missing `vendor/` from k133). Once `main`
built, a push to `main` published `raudssus/ocp:latest` and `:<short sha>` to
Docker Hub, and the same pair to `ghcr.io/getty/kubernetes-ocp`. The earliest
run checked does this, 36813555940 (2026-10-01, ac075c6), and so does the
latest, 41741299801 (2026-11-03, 44a9db0). The runs before 2026-10-01 were not
checked.

Pushing `main` already waits for the maintainer's go. In effect, that go now
also covered publishing an image, and nobody had decided that in so many
words. For CI the bullet was false again: publishing ran on the permission for
a push, not on a permission of its own.

The maintainer decided on 2026-11-06 that only release tags publish. Pushes to
`main`, feature branches and pull requests build the image, because the build
is the test, and push nothing. The gate stays where the policy already lived,
in `.cicd/docker+29+publish.image.sh`. Any revision that is not a release tag
exits 78 there, which SimpiCI counts as a skip.

What counts as a release tag is the main agent's call, not the maintainer's.
It is the bare-version tag that `dzil release` writes under `[@Author::GETTY]`
(`tag_format` `%v`, for example `0.001`). Any other tag builds and pushes
nothing, `k138-debug` (which exists on the remote) included, so a debug tag
cannot move `latest`. The bare version is also the image tag that robocop of a
released CLI asks for: `OCP::Robocop::Manifest` `_default_image` names
`raudssus/ocp:<version>`. The tag a release writes and the image tag its
robocop pulls are the same string.

Consequences:

- A release tag reaches the remote through `dzil release`, whose bundle tags
  and pushes, or through a tag pushed by hand. Both wait for the maintainer's
  go. So the bullet holds for CI again: CI publishes an image only as part of
  a release that someone explicitly permitted.
- `latest` is now the newest release, not `main`. A development checkout's
  robocop falls back to `raudssus/ocp:latest` (`docs/robocop.md`), so it can
  run older code than the checkout it was deployed from. Until the first
  release tag is pushed, `latest` stays where the last push to `main` left it,
  at 44a9db0. `make docker-push` and `make docker-release` push `latest` as
  well, so a manual push the maintainer permits still moves it.
- New commits on `main` no longer get a published image. To run one in a
  cluster, build its image first (`make build`). k405 does not remove the
  images already published from `main`.
- The scope is CI only. `make docker-push` and `make docker-release` are
  unchanged, and they still need the maintainer's go.
- The architecture bound is unchanged. CI builds on amd64 runners
  (`ubuntu-latest`), so the images it publishes are amd64. The last
  Consequence still holds, and so does ADR 0020's "the published
  `raudssus/ocp:latest` is amd64". The push that 0020 dates to 2026-08-15 is
  no longer the latest one, though. That was CI's, from 44a9db0 on 2026-11-03.

The 2026-08-17 amendment's remark that `.github/workflows/` no longer exists
was true when it was written. k134 brought the directory back, and it has been
on `main` since 2026-09-18.

The decision did not move. The toolchain still runs inside Docker, and
publishing is still separate from building. What this amendment corrects is
the account of that consequence. It did not hold for CI on the day this ADR
was written, nor from 2026-09-18 until k405. Recorded under k405.
