# Developing OCP

This is for hacking on OCP itself. If you only want to run a cluster, the
[README](../README.md) is the whole story.

## Getting a checkout running

```bash
git clone git@github.com:Getty/kubernetes-ocp.git
cd kubernetes-ocp
cpanm --installdeps .
perl -Ilib bin/ocp --help
```

That is enough to poke at the CLI. It is **not** the toolchain the test suite
uses — see below.

## The toolchain is Docker-first

Not "Docker-recommended". The binding test suite, dependency installation and
snapshot regeneration all run **inside the Docker image**, against
`cpanfile.snapshot`. Running `carton install` or `cpm` on the host pollutes
host CPAN state and produces results that do not match what ships.

```bash
make test          # binding suite, in Docker, against cpanfile.snapshot
make test-v        # same, verbose
make test TESTS=t/33-registry-manifests.t   # a single file
make test-host     # fast, NOT binding — host CPAN, may drift from the image
make build         # build the Docker image
make snapshot      # regenerate cpanfile.snapshot (in Docker; never on host)
make docker-test   # confirm the built image starts and its entrypoint answers
```

If a target you need is missing, it gets added to the Makefile — it does not
get worked around on the host.

## `make smoke` is not a test

```bash
SMOKE_HOST=... make smoke
```

This bootstraps a full cluster against a **real machine** and wipes whatever is
on it. Human-triggered only. It is never part of normal development, and its
concerns deliberately never move into `t/` — everything in `t/` is
network-free and cluster-free, running against inline mock packages
(`FakeK8s`, `FakeProvider`, `FakeRex`) and `File::Temp` fixtures.

## Output channels: STDOUT vs STDERR

Every `ocp` command has two output channels with separate jobs, and mixing them
breaks the pipe:

- **STDOUT is the payload** (the result) or the **progress narrative** (rollout,
  apply) that a human reads or a machine consumes.
- **STDERR is everything that went wrong**, with its diagnosis. An error
  without diagnosis is as much a violation as diagnosis noise on STDOUT.
- **Machine-readable commands** (`ocp keys show`, `ocp kubeconfig`) put
  *only* the requested material on STDOUT. That is what makes this work:

```bash
ocp keys show --purpose admin >> ~/.ssh/authorized_keys
```

## CI

`.github/workflows/ci.yml` runs this repository's own `.cicd/` jobs through
[SimpiCI](https://github.com/Getty/simpici)'s action. What gets built, which
registries exist, and that only `main` and tags publish at all is decided in
those scripts — in this repository, under review. Not in workflow YAML.

### How SimpiCI picks the jobs

SimpiCI reads the plan off the **file names** in `.cicd/`. There is no config
file and no step graph:

```
.cicd/<image-expression>+<phase>[.<job>].sh
```

Ours:

| Script | Runs in | Phase | Job |
|---|---|---|---|
| `docker+29+build.image.sh` | `docker.io/library/docker:29` | `build` | `image` |
| `docker+29+publish.image.sh` | `docker.io/library/docker:29` | `publish` | `image` |

The phase order is fixed: `prepare build test package publish deploy`. Jobs in
one phase run concurrently; the next phase starts only once every job in the
current one has finished, so nothing publishes an image that failed to build.
Aliases (`linux`, `perl`, `node`, `python`) resolve to the official latest
images; anything else splits on `+` with the last field as the tag.

Rename a script and you have changed the plan. A name SimpiCI cannot parse
fails the whole run with exit 64 before anything executes — worth knowing
before renaming one. You can check a change without pushing:

```bash
SIMPICI_PLAN_ONLY=true GITHUB_WORKSPACE=$PWD ~/dev/simpici/action/run.sh
```

### What the container gets

Each job runs in its own container with the workspace mounted **read-only** at
`/workspace`, plus writable `/output` and `/artifacts`. Only a fixed set of
`CICD_*` variables crosses into it — an arbitrary environment variable from the
workflow does **not**, which is why nothing here reads an `OCP_*` secret.

Two things are handed out by phase rather than to everyone:

- the host's **Docker socket**, in `build` and `publish` only;
- the **registry credentials** (`CICD_REGISTRY`, `_USER`, `_PASSWORD`,
  `CICD_PUBLISH_IMAGE`), in `publish` and `deploy` only.

Because the socket is the host's, the image the build phase produces is still
in the daemon when the publish phase looks for it.

### One job per registry

SimpiCI passes exactly **one** registry triple into a container, so one run
publishes to one registry. We want the image in two places, so `ci.yml` defines
two independent jobs:

| Job | Registry | Image | Credentials |
|---|---|---|---|
| `dockerhub` | `docker.io` | `raudssus/ocp` | repo variable `DOCKERHUB_USER` + secret `DOCKERHUB_TOKEN` |
| `ghcr` | `ghcr.io` | `ghcr.io/getty/kubernetes-ocp` | the run's own `GITHUB_TOKEN`, no secret needed |

Docker Hub is primary because `raudssus/ocp` is the name the rest of the
project already agrees on — the Makefile's `IMAGE`, `OCP::Cmd::DeployImage`'s
`$DEFAULT_REPO`, the robocop manifests and `xt/smoke.sh`.
`t/66-image-registry-consistency.t` guards that agreement; it deliberately
excludes `README.md`, which gets a manual pass whenever the image moves.

The two jobs are independent: Docker Hub being down, or its secrets missing,
does not stop the GHCR publish. The cost is that the image is built twice, once
per runner.

### Publish policy

`main` and tags publish. Everything else — pull requests, feature branches —
builds the image and pushes nothing, because the build is the test. The publish
job reports that with **exit 78**, which SimpiCI counts as a skip rather than a
failure. Missing credentials on a revision that would otherwise publish are
also a skip, on stderr: runner configuration must never turn a green build red.

### Two Alpine details

The official `docker` image is Alpine, and both scripts have to work around it:

- it ships **no bash**, and `share/bin/ocp-build-image` is a bash script, so
  each job does `apk add --no-cache bash` first. Cheaper and more honest than
  rewriting a tested tool in POSIX sh or maintaining a CI image just for this;
- `/workspace` is bind-mounted and owned by another uid, which git refuses to
  read as "dubious ownership" — and `ocp-build-image` asks git for the version
  and the short sha. Without `git config --global --add safe.directory`, the
  image would quietly be tagged `develop`/`unknown`.

The same script also runs from the standalone `simpicid` daemon, which invokes
the very same `action/run.sh`. There is one contract, not two.

## Releasing

`make test`, `make build` and `dzil build` are fine at any time.

`dzil release`, `make docker-push` and `make docker-release` require the
maintainer's explicit go-ahead, every time, even when a plan lists "release" as
the obvious next step.

Note that this distribution builds with `no_cpan = 1`: it is deliberately not
published to CPAN, and `cpanm OCP` will never find it.

## Architecture

Decisions and their reasoning are recorded as ADRs in [`adr/`](adr/) — start
with [0001, splitting the CLI from the in-cluster controller](adr/0001-split-cli-from-in-cluster-controller.md)
and [0004, spec in git, status out of it](adr/0004-spec-in-git-status-out-of-it.md).

One rule worth repeating here because it constrains every code path:
**no `kubectl`, anywhere in OCP.** All Kubernetes access goes through
`Kubernetes::REST`/`IO::K8s`. The `kubectl` binary in the Docker image is for
humans to debug with ([ADR 0007](adr/0007-no-kubectl-in-any-code-path.md)).
