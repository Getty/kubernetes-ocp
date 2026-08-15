---
model: sonnet
---

# GPU Stack for OCP

## Version Pinning — `OCP::Versions` is the only source

Never carry component versions in this file: a stale number here is how a wrong
pin gets argued back into the code. Read them:

```perl
OCP::Versions->get_component_version('gpu_operator')
```

Components pinned there: `gpu_operator`, `nvidia_toolkit`, `nvidia_driver`,
`nvidia_device_plugin`, `dcgm_exporter`, `nvidia_dcgm`, `nfd`.

Constraints that outlive any single pin:

- **Every enabled ClusterPolicy component needs repository + image + version.**
  OCP hand-rolls the operator Deployment instead of using the Helm chart, so it
  sets none of the `*_IMAGE` env the chart sets. `imagePath()` then errors out
  and the DaemonSet never starts. `t/40-gpu-clusterpolicy.t` enforces this.
- **No separate validator pin.** The standalone
  `nvcr.io/nvidia/cloud-native/gpu-operator-validator` image stops at v25.3.4;
  from v25.10 the operator image itself carries `/usr/bin/nvidia-validator`, and
  upstream tags it with the operator's own version. Pinning it separately
  produces five DaemonSets in `Init:ImagePullBackOff` — the validator is their
  init container.
- **Device plugin floor for GB10/Grace-Blackwell: v0.17.4.** Older plugins
  mishandle the unified memory those parts expose (NVIDIA/gpu-operator#1794).
- **`nvidia_driver` only matters when `gpu.driver: operator`.** Keep it equal to
  `driver.version` in the operator chart's bundled `values.yaml` for the pinned
  operator version.
- **`OCP::Drift` probes the GPU operator and NFD, and nothing else in the
  stack.** Both read the image off a Deployment OCP writes itself, so the
  version is honestly measurable; both are report-only (`remedy => undef`,
  `self_healing`) because a plain `ocp apply` re-applies the manifest that
  carries the version. The GPU operator probe is `optional` — absence is not
  drift, since the operator only exists where a card and `gpu.enabled` are. The
  rest (`nvidia_toolkit`, `nvidia_device_plugin`, `dcgm_exporter`,
  `nvidia_dcgm`, `nvidia_driver`) is deliberately unprobed: OCP puts those
  versions into the ClusterPolicy, and the operator turns them into DaemonSets
  whose names and layouts it owns and changes between releases. Measuring them
  honestly means reading the ClusterPolicy spec, not guessing a DaemonSet name.

## Detection Chain

Two detections, at two times, asking two different questions.

**1. Before the cluster — Rex `detect_gpu` (`share/Rexfile`).** Question: does
this host need an NVIDIA driver?

- `_pci_display_devices` reads **sysfs**, not `lspci`:
  `/sys/bus/pci/devices/*/{vendor,device,class}`. Vendor `0x10de`, class
  `0x0300xx` (VGA) or `0x0302xx` (3D controller).
- There is **no model whitelist**, and it must not come back. `lspci` prints
  the name from the host's `pci.ids` database, which is always older than the
  newest card: a DGX Spark prints `Device [10de:2e12]` for its GB10, and no list
  of marketing names can match that. Vendor and class come from the hardware.
- `_gpu_action` decides: `nvidia` / `virtual` / `amd` / `none`. NVIDIA wins over
  the virtual-adapter list, because a VM with a passed-through card has both.
- The virtual blacklist (`1af4` virtio, `1b36` QEMU, `15ad` VMware, `80ee`
  VirtualBox) stays: a short list of "definitely not" keeps working as hardware
  moves on.
- `_nvidia_driver_present` (nvidia-smi enumerates GPUs **and** `libcuda.so` is
  in the linker cache) skips the driver install. Package state is the wrong
  question — vendor appliances install outside the distro's package namespace.
- Compute capability is **not** asked here. Whether a card is worth scheduling
  on is answered later, by the device plugin.

**2. After the cluster — NFD labels.** `_setup_gpu_operator` looks for
`feature.node.kubernetes.io/pci-0300_10de.present` or `pci-0302_10de.present`.
Same evidence as sysfs, from the other side.

**3. Authoritative — `nvidia.com/gpu` in the node capacity.** Published by the
device plugin. This, plus a CUDA smoke pod, is the only proof the stack works;
everything before it is a prediction.

## Host Driver Install (`install_nvidia`)

- **Debian**: `linux-headers-$(uname -r)`, `linux-headers-$(dpkg
  --print-architecture)`, `nvidia-driver`, `nvidia-smi`, `libcuda1`.
- **Ubuntu**: `linux-headers-$(uname -r)` plus `ubuntu-drivers install`. No
  branch number is hardcoded, on purpose — the branch, the open-vs-proprietary
  flavour and the architecture are three separate questions and all three are
  part of the package *name*:
  - R535 reached end of life in June 2026; on Ubuntu 24.04 `nvidia-driver-535`
    is a transitional package that pulls 580, so the old pin pinned nothing.
  - Grace Hopper and Blackwell run **only** the open kernel modules; Maxwell,
    Pascal and Volta run only the proprietary ones.
  - amd64 and arm64 do not carry the same names (arm64 comes from ports).
  `ubuntu-drivers` resolves all three from the card's PCI modalias. If it fails,
  the task **dies** — OCP does not fall back to a guessed package name.
- `linux-headers-generic` is never installed: on a vendor kernel (a DGX Spark
  runs `6.17.0-1029-nvidia`) it pulls headers for a different kernel and DKMS
  builds against the wrong tree.
- The container toolkit comes from NVIDIA's `libnvidia-container` apt repo —
  unless `_nvidia_toolkit_present` finds `nvidia-container-runtime` and
  `nvidia-ctk` already installed, in which case neither the apt source nor the
  package is touched. A DGX has both from its vendor image, and OCP has no
  business deciding where such a host gets its packages from afterwards.

## containerd — OCP writes nothing

k3s and RKE2 share the same agent code. At **startup** it scans `PATH` for
`nvidia-container-runtime` (with `/usr/local/nvidia/toolkit` and
`/opt/kwasm/bin` prepended, which is where the operator's toolkit DaemonSet
installs), writes what it finds into its own containerd config, and k3s also
ships the matching RuntimeClass objects. Verified on a DGX Spark: runtime and
`nvidia` RuntimeClass both present, OCP having done nothing.

- The scan runs **only at service start**. Install the runtime before the
  service, or restart it.
- Neither distribution makes nvidia the **default** runtime. Workloads use
  `runtimeClassName: nvidia`, or the cluster opts in with `--default-runtime`.
- **Never write a `config.toml.tmpl` / `config-v3.toml.tmpl` without
  `{{ template "base" . }}`.** Both render the template *instead of* their
  generated config, so a partial template silently drops the registry mirrors,
  the sandbox image and the CNI settings. OCP used to ship exactly that.
- RKE2's unit sets no `PATH` at all, so `_configure_nvidia_runtime_path` writes
  one into `/etc/default/rke2-{server,agent}` (docs.rke2.io/add-ons/gpu_operators).
  k3s needs nothing.

## ocp.yaml switches

```yaml
gpu:
  enabled: true      # false: no detection on any node, no operator deployed
  driver: host       # host = Rex installs it; operator = the driver DaemonSet does
  toolkit: true      # false on hosts that already ship the toolkit (DGX OS)
```

`OCP::Config` normalises `enabled`/`toolkit` to 0/1 and rejects an unknown
`driver` value rather than falling back to `host` in silence. `driver: operator`
turns the Rex-side install off *and* `ClusterPolicy.driver.enabled` on — the two
halves must never both be active.

On DGX-class hosts NVIDIA's guidance is `driver.enabled=false` **and**
`toolkit.enabled=false`: the vendor image already has both, and the toolkit
DaemonSet would rewrite a containerd config that already works.

## GPU Operator ClusterPolicy (`_generate_gpu_operator_manifest`)

| Component | State | Why |
|---|---|---|
| `driver` | follows `gpu.driver` | never both sides at once |
| `toolkit` | follows `gpu.toolkit` | off where the host already has one |
| `devicePlugin` | on | publishes `nvidia.com/gpu` |
| `dcgm` + `dcgmExporter` | on | the operator runs its own hostengine on :5555 in the `nvidia-dcgm` container; the exporter connects there, not to a host engine. Expect a few exporter restarts racing the starting hostengine |
| `gfd` | off | NFD does feature discovery |
| `nfd` | off | OCP deploys NFD itself |
| `migManager` | off | MIG does not exist on GB10 |
| `validator` | on, operator image | see the pinning rules |
| `nodeStatusExporter` | off | |

### `toolkit.env` — two variables, and two that are left out on purpose

OCP sets `CONTAINERD_SOCKET` and `CONTAINERD_CONFIG`, both node paths. The
socket is `/run/k3s/containerd/containerd.sock` on **both** distributions (RKE2
runs k3s' agent code and inherits its containerd invocation; the RKE2 GPU docs
name that path explicitly). Only the config path follows the distribution:
`/var/lib/rancher/{k3s,rke2}/agent/etc/containerd/config.toml`.

They stay because they are the operator's **input**, not decoration: it reads
both, derives `RUNTIME_SOCKET` / `RUNTIME_CONFIG` from them, and mounts the
*directory* of each into the toolkit DaemonSet. Leave them out and it falls back
to `/etc/containerd/...` and `/run/containerd/...`, right on neither
distribution. Because it is the directory that gets mounted, a wrong path that
happens to exist is the worst case: the hostPath mounts cleanly and the failure
only surfaces when the toolkit tries to reach containerd through it.
`RUNTIME_CONFIG_SOURCE` and `RUNTIME_DROP_IN_CONFIG` need no help — the operator
sets those itself.

`CONTAINERD_SET_AS_DEFAULT` and `CONTAINERD_RUNTIME_CLASS` are deliberately
**not** set. The runtime class only ever restated the default: the operator
overwrites whatever the ClusterPolicy says with `operator.runtimeClass`
(`nvidia`). Set-as-default is the one with teeth. OCP does not make the nvidia
runtime the node's default — management pods reach it through RuntimeClass,
everything else keeps runc — and sending `1` here is exactly that decision taken
sideways. It is not obsolete upstream either: the toolkit still accepts it as a
source for `--set-as-default`, behind `NVIDIA_RUNTIME_SET_AS_DEFAULT` in the
same first-set-wins chain. It loses today only because `cdi.enabled` defaults to
true, which makes the operator hand the toolkit
`NVIDIA_RUNTIME_SET_AS_DEFAULT=false` ahead of it — measured on the DGX Spark,
where `crictl` reported `defaultRuntimeName runc` while OCP was still sending
`1`. So the variable was never dead, only outvoted.

Leaving it out is **not** a guard, though: the toolkit's own default for
`--set-as-default` is true. What keeps runc the default is CDI being on, and OCP
takes that from the CRD default without writing `cdi.enabled: true` into the
spec. `t/40-gpu-clusterpolicy.t` asserts the absence of both variables, so
neither can come back unnoticed.

## NFD (Node Feature Discovery)

Deployed by OCP itself, not by the operator (`nfd.enabled: false` in the
ClusterPolicy), into the `node-feature-discovery` namespace from
`registry.k8s.io/nfd/node-feature-discovery`. nfd-master (Deployment) labels,
nfd-worker (DaemonSet) detects. The RBAC in `_generate_nfd_manifest` mirrors
upstream exactly — every rule is load-bearing.

## GPU Status

`ocp status` shows a GPU section when GPU nodes exist: nodes carrying
`nvidia.com/gpu` in capacity, GPU Operator status, device plugin pod count.
