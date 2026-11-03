---
name: ocp-gpu
description: Use when working on OCP's GPU stack, NVIDIA or AMD — detect_gpu, install_nvidia or install_amd in the Rexfile, the ocp.yaml gpu block (gpu.amd included), the ClusterPolicy OCP generates, NFD, the AMD device plugin, DRA driver, labeller or metrics exporter, GPU pins in OCP::Versions, GPU drift probes. Generic GPU setup: skills kubernetes-gpu and rocm-engineering.
model: sonnet
---

# GPU Stack for OCP

One `gpu:` block covers two vendors.

- **NVIDIA:** Rex::GPU installs the host driver. In the cluster the GPU Operator
  runs under OCP's ClusterPolicy, beside OCP's own NFD.
- **AMD:** Rex::GPU::AMD installs the host driver. In the cluster a few
  DaemonSets go into `kube-system`, from Rex::Rancher::K8s. There is no operator.

Read the reference for the side you change **before** you change it.

| Reference | Holds |
|---|---|
| `references/nvidia-host.md` | `detect_gpu`, `_gpu_actions`/`_driver_gpus`, `install_nvidia` (Ubuntu vs. the rest), toolkit, CDI, containerd/PATH, the `gpu.toolkit` CR channel |
| `references/nvidia-cluster.md` | NVIDIA pins and their coupling rules, the CRD bundle, the ClusterPolicy table, `toolkit.env`, NFD, drift, status |
| `references/amd.md` | `install_amd`, the integrated gate, all AMD labels, the component/object table, the affinity matrix, reconcile, readiness, removal, drift, pins, status, live traps |

## ocp.yaml switches

```yaml
gpu:
  enabled: true        # false: no detection, no operator; the AMD stack is removed
  driver: host         # both vendors: who installs the kernel driver (host | operator)
  toolkit: true        # NVIDIA only; false where the host ships one (DGX OS)
  amd:
    allocation: device-plugin   # device-plugin | dra | none: default per AMD node
    resource_naming: single     # single | mixed, handed to the device plugin
    labeller: true
    metrics: false              # Instinct / Radeon AI only, not APUs
    integrated: false           # iGPU/APU on every node (provider CR, k253)
```

`OCP::Config` normalises booleans to 0/1. It croaks on an unknown `driver`,
`amd.allocation` or `amd.resource_naming`, and never falls back in silence.

- **The switches take true/false only** (k320): `enabled`, `toolkit`,
  `amd.labeller`, `amd.metrics` and `amd.integrated` accept true, false, 1 or
  0. A string like `no` is refused (`gpu.enabled: must be true or false, not
  'no'; write enabled: false`), by `validate` and by the accessor alike. It
  used to read as true, so `enabled: no` left the GPU stack on.
- **Unknown keys are refused** (k331): `gpu:` takes `enabled`, `driver`,
  `toolkit`, `amd`; `gpu.amd:` takes the five shown above. `gpu: false` is
  refused with the hint `gpu: { enabled: false }`.

## Rules for every GPU change

- **Pins live only in `OCP::Versions`**, read with `get_component_version`.
  - NVIDIA: `gpu_operator`, `nvidia_toolkit`, `nvidia_driver`,
    `nvidia_device_plugin`, `dcgm_exporter`, `nvidia_dcgm`, `nfd`.
  - AMD: `amd_device_plugin` (its labeller is tag `labeller-<pin>`),
    `amd_dra_driver`, `amd_metrics_exporter`.
  - Never copy a pinned number into skills or comments.
- **Detect from sysfs** (`Rex::GPU::Detect::Sysfs`), by vendor + class. Never
  use a model list or `lspci`.
- **Never call `install_driver` with an empty list.** NVIDIA's would install a
  GPU-agnostic driver. Filter with `_driver_gpus` first.
- **OCP writes no containerd config and no `config.toml.tmpl`.** The only CDI
  OCP writes is NVIDIA's under `gpu.toolkit: false`.
- **Host and operator never both install the driver.** With NVIDIA under
  `operator`, Rex installs nothing and `ClusterPolicy.driver.enabled` is on.
  AMD has no operator: under `operator` OCP installs no AMD driver, but it
  still detects and labels the GPU.
- **`t/40-gpu-clusterpolicy.t` guards the ClusterPolicy.**
  - Every enabled component needs repository + image + version.
  - `share/gpu-operator/crds/` holds NVIDIA's files from the pinned tag. Never
    stub them.
  - `CONTAINERD_SET_AS_DEFAULT` and `CONTAINERD_RUNTIME_CLASS` stay unset.
- **Drift probes read only workloads OCP writes, and every GPU probe is
  self-healing.**
  - Probed: `nfd` (two probes: `nfd-master`, `nfd-worker`), `gpu_operator`
    (optional) and the four AMD DaemonSets (optional). All seven carry
    `self_healing` in `@OCP::Drift::COMPONENT_PROBES` and no `remedy`:
    `ocp apply` closes the drift, no Rex task does.
  - The four AMD DaemonSets since k350, NFD (`nfd-master`) and the GPU Operator
    (`gpu-operator`) since k351, the `nfd-worker` DaemonSet since k369. Their
    apply step re-deploys (AMD) or re-applies the manifest (NFD, GPU Operator)
    when the image tag is off its pin, even at an unchanged hash.
  - What counts: the first container's image tag against the pin, read by
    `OCP::Drift->version_against_pin`, the one helper probe and step share.
    A pin bump and an image changed in the cluster both count.
  - What does not: args and any other field, on either side. An untagged image
    is not compared either.
  - Nothing GPU-related is report-only.
  - Never guess an operator-owned DaemonSet name for the other NVIDIA pins.
- **A GPU is ready when it shows in `status.allocatable`, never in capacity.**
  The kubelet keeps capacity after a device plugin unregisters. The final
  proof is a smoke pod.

## AMD in short

- **Host.** `install_amd` takes the AMD GPUs that Rex::GPU does not mark
  `compute => 0`. An integrated GPU needs `gpu_amd_integrated`, which comes
  from `ocp node add --gpu` or from `gpu.amd.integrated` (k253). OCP never
  reboots and installs no ROCm.
- **Labels.** At registration, an accepted GPU puts
  `ocp.internal/amd-gpu.present=true` and `ocp.internal/amd-gpu.gfx-target=<gfx>`
  on the node. Use the `$OCP::Config::AMD_GPU_*_LABEL` constants for both.
- **Cluster stack.** `OCP::Cmd::Apply::AMDGPU` selects on that marker, never on
  NFD's `pci-*_1002`. Node label `ocp.internal/amd-gpu.allocation` overrides
  `gpu.amd.allocation` through affinity terms, so each node gets either the
  device plugin or the DRA driver (experimental). A component that no node
  selects is removed again.
- **Unreleased libraries.**
  - Rex::GPU::AMD is on rex-gpu branch `worktree-k1-amd-driver`. Without it,
    the released detection marks AMD GPUs `compute => 0`, so no driver and no
    labels.
  - The `deploy_amd_*`/`remove_amd_*` functions are on rex-rancher branch
    `worktree-k95-amd-gpu`. Without them, apply prints one `[WARN]` and
    deploys nothing.
  - Neither case ever fails a run.
