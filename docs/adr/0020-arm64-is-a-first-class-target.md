# 0020. Treat arm64 as a first-class target

Date: 2026-08-12
Status: accepted

## Context

OCP was written on and for x86, and the assumption was invisible because it was
never written down — it was spelled into artifact names. A deployment against
an NVIDIA DGX Spark (GB10, aarch64, Ubuntu 24.04) found them:

- `install_rke2_server` downloaded `rke2.linux-amd64.tar.gz` and
  `sha256sum-amd64.txt` literally: a 404 on aarch64.
- The Debian NVIDIA driver branch asked for `linux-headers-amd64`.
- The Dockerfile fetched `kubectl` from `bin/linux/amd64`.
- The Hetzner server-type picker filtered to x86 types.

Meanwhile the Cilium tasks already did arch detection correctly — the pattern
existed in the repository, twice, inlined, and RKE2 did not use it.

An architecture assumption fails late and confusingly. It does not fail at
`ocp apply`; it fails halfway through a bootstrap with an HTTP error on a URL
nobody reads carefully.

## Decision

arm64/aarch64 is a supported target, not an exception. Concretely:

- **No literal architecture in any artifact name.** One helper, `_node_arch()`,
  maps `uname -m` onto Go's `GOARCH` naming, which is what the download URLs
  use. Machines it does not know pass through unmapped, so the failing URL names
  the architecture rather than hiding it. The two inlined Cilium ternaries now
  call it too.
- **Ask the host, do not translate.** Package architecture comes from
  `dpkg --print-architecture`, not from a mapping OCP maintains.
- **Every pinned image must have a real `linux/arm64` entry under the same
  tag** (ADR 0014). That was verified for all of them: NFD, gpu-operator,
  container-toolkit, k8s-device-plugin, dcgm-exporter, dcgm, cilium,
  operator-generic, registry:2, cert-manager, debian:trixie, perl:5.40-slim. No
  `sbsa`/`aarch64` tag switching is needed anywhere.
- **A verified non-problem is recorded as such.** The k3s and RKE2-agent install
  scripts self-detect; `registries.yaml`, the containerd config and the
  distribution config generation are architecture-neutral; there are no
  architecture `nodeSelector`s; `OCP::Versions` holds no architecture-bound
  artifact name. That list is part of the decision, so the audit does not have
  to be redone from scratch.

### Alternatives rejected

- **amd64 with arm64 special cases** — special cases are added when someone
  notices, which is at bootstrap time on a customer machine.
- **A separate arm64 code path** — doubles every download site; the difference
  is one string.
- **Guessing an arm64 package name where the archive differs** — see ADR 0015;
  the driver case is exactly where a guess breaks a machine.

## Consequences

The decision is honoured where OCP actually generates the artifact, and lapses
where OCP ships the artifact. The split is the load-bearing fact; it has to be
read as two columns, not one.

### Where arm64 IS first-class today

- **Component downloads** — `share/Rexfile:_node_arch` maps `uname -m` onto Go's
  `GOARCH` for every artifact OCP downloads by hand: the RKE2 tarball and its
  sha256 file (the original 404), the Cilium CLI, the Cilium Gateway API CRD
  bundle. The mapping falls through unmapped on machines it does not know, so
  the failing URL names the architecture rather than hiding it. Same call site
  for every download, no inline ternary.
- **`dpkg --print-architecture`** for package names — `linux-headers-arm64` on
  Ubuntu, `nvidia-driver` on Debian (which dpkg resolves to the right branch).
  Gone is the hardcoded `linux-headers-generic` that pinned to the wrong kernel
  flavour (ADR 0015).
- **`kubectl` download in the Dockerfile** — `dpkg --print-architecture` is the
  architecture the image is being built for, with no dependency on
  `buildx` passing `TARGETARCH`; an amd64-only literal would have shipped an
  unrunnable binary into every arm64 image.
- **Hetzner picker** — `OCP::Hetzner::server_type_options` lists CAX* and CPX*
  side by side, with the architecture in the label; the picker cannot silently
  pick x86 over arm64 unless `architecture => 'arm' | 'x86'` narrows it on
  purpose.
- **Multi-arch base image** — `perl:5.42.3-slim-trixie` carries `linux/arm64`
  under the same tag as `linux/amd64`, and `make build-multiarch` runs both
  arms locally (under QEMU on an amd64 host) without source changes.
- **External image pins** — every image OCP pulls from outside (NFD,
  gpu-operator, container-toolkit, k8s-device-plugin, dcgm-exporter, dcgm,
  cilium, operator-generic, registry:2, cert-manager, debian:trixie) was
  verified to publish a real `linux/arm64` entry under the same tag. A version
  bump is not complete until the new tag does too.
- **k3s / RKE2-agent installs** self-detect; `registries.yaml`, the containerd
  config and the distribution-generated config are architecture-neutral; there
  are no architecture `nodeSelector`s; `OCP::Versions` holds no architecture-
  bound artifact name. Recorded as part of the decision so the audit does not
  have to be redone.

### Where arm64 is NOT yet first-class

- **OCP's own published images are amd64-only.** `raudssus/ocp:latest` does not
  carry `linux/arm64`, so robocop cannot run on an arm64 cluster — the CLI is
  unaffected because it runs outside the cluster (ADR 0013). This is the
  largest open hole. Multi-arch publish is built and locally verified
  (`Makefile:docker-push`, `Makefile:build-multiarch`); the actual publish step
  is maintainer-gated (karr #10).
- **`Dockerfile.robocop` is amd64-only.** Carries its own `perl:5.40-slim` base
  rather than the main image's `5.42.3-slim-trixie` and breaks the build
  outright on missing `libexpat1-dev` (karr #39). It is not referenced by any
  workflow or Makefile target; deletion is straightforward (karr #58). Once it
  is gone, the "one image, multi-arch" claim stops having an exception written
  in `Dockerfile.robocop`.
- **No cross-architecture CI for the full reconcile path.** The arm64
  verification was a single k3s end-to-end run; the RKE2 arm64 fix that started
  the work has never been re-verified against a running RKE2 cluster
  (karr #9). Static checks replaced the live run because the live run would
  have re-bootstrapped a real machine.
- **No `xt/smoke.sh` on aarch64.** `make smoke` is amd64-only (`xt/smoke.sh`
  needs `SMOKE_HOST`); an aarch64 smoke would need an aarch64 runner with the
  same `SMOKE_HOST` target. Until it exists, "first-class on arm64" is asserted
  by a single historical run plus the static checks the run substituted for.

### What this means for further work

- The "Where first-class" column is load-bearing — a new component pin must
  carry an arm64 entry, and a new download URL must go through `_node_arch`. No
  new literal arch strings anywhere.
- The "Where not yet" column is the audit obligation. After karr #10 lands
  (multi-arch publish) and karr #58 lands (`Dockerfile.robocop` removed), this
  ADR becomes eligible for a third pass where the split collapses: the only
  remaining gaps would be CI coverage and an aarch64 smoke, and those belong in
  the verification path, not in the artifact claim.
- 0008 (Server-Side Apply), 0009 (status subresource) and 0013 (docker-first
  toolchain) reference arm64 only as a publication target. They themselves are
  architecture-clean and do not need a parallel revision; the publication gap
  this ADR names is also theirs.

### Verified end-to-end (the historical run)

A full k3s cluster was deployed on arm64: k3s v1.36.3+k3s1, node Ready,
Cilium 1.20.0 (the CLI resolved `linux-arm64` correctly), registry, NFD,
cert-manager, Cilium Gateway, and the GPU stack reporting `nvidia.com/gpu: 1`
with a successful CUDA workload validation. The run went over k3s, whose
install script self-detects, which is why the RKE2 arm64 path is still only
statically checked (karr #9).
