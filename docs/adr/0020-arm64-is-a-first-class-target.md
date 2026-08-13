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

- Verified in part, and only in part. A full k3s cluster was deployed on arm64:
  k3s v1.36.3+k3s1, node Ready, Cilium 1.20.0 (the CLI resolved `linux-arm64`
  correctly), registry, NFD, cert-manager, Cilium Gateway, and the GPU stack
  reporting `nvidia.com/gpu: 1` with a successful CUDA workload validation.
  **The RKE2 arm64 fix — the reason the work started — is still only statically
  checked**, because that run went over k3s, whose install script self-detects
  (karr #9).
- **The published images are amd64-only**, so robocop cannot be deployed on an
  arm64 cluster at all (karr #10). The CLI works because it runs outside; the
  controller does not. This is the largest open hole in the decision.
- Every new download URL, package list and image pin now carries an audit
  obligation, and a version bump is not complete until the new tag has been
  checked for an arm64 entry.
- Hetzner's server-type picker remains x86-filtered (karr #14) — latent, since
  Hetzner offers arm64.
