# NVIDIA — the cluster side

The GPU Operator's ClusterPolicy, OCP's own NFD, the pins and the drift probes.
The host side (detection, driver, toolkit, CDI) is in `nvidia-host.md`.

## Pins (`OCP::Versions`) and the rules that outlive any pin

```perl
OCP::Versions->get_component_version('gpu_operator')
```

The NVIDIA keys are `gpu_operator`, `nvidia_toolkit`, `nvidia_driver`,
`nvidia_device_plugin`, `dcgm_exporter`, `nvidia_dcgm` and `nfd`. Never copy a
pinned number into a skill or a doc. A stale number is how a wrong pin gets
argued back in.

- **Every enabled ClusterPolicy component needs repository + image + version.**
  OCP hand-rolls the operator Deployment instead of using the Helm chart, so
  none of the chart's `*_IMAGE` env is set. Without them `imagePath()` errors
  out and the DaemonSet never starts. `t/40-gpu-clusterpolicy.t` enforces this.
- **No separate validator pin.** The standalone
  `nvcr.io/nvidia/cloud-native/gpu-operator-validator` stops at v25.3.4. From
  v25.10 the operator image carries `/usr/bin/nvidia-validator` under the
  operator's own tag. A separate pin produces five DaemonSets in
  `Init:ImagePullBackOff`, because the validator is their init container.
- **Device plugin floor for GB10/Grace-Blackwell: v0.17.4.** Older plugins
  mishandle unified memory (NVIDIA/gpu-operator#1794) and the node silently
  shows 0 GPUs. See `t/65-gpu-device-plugin-floor.t`.
- **`nvidia_driver` only matters under `gpu.driver: operator`.** Keep it equal
  to `driver.version` in the operator chart's bundled `values.yaml` for the
  pinned operator.
- **The CRD bundle moves with `gpu_operator`.**
  - `share/gpu-operator/crds/` holds NVIDIA's `nvidia.com_clusterpolicies.yaml`
    and `nvidia.com_nvidiadrivers.yaml` as `clusterpolicy-crd.yaml` and
    `nvidiadriver-crd.yaml`. They are unchanged from
    `deployments/gpu-operator/crds/` at the pinned tag, under a `# Source:`
    header that names it.
  - A pin bump means fetching both again from the new tag.
    `t/40-gpu-clusterpolicy.t` stays red until the header's tag equals the pin.
  - The test checks every field the generated ClusterPolicy sets against the
    CRD `setup_gpu_operator` sends: declared, required, type, enum, pattern.
    `preserve-unknown-fields` does not count as declared.
  - **Never stub or hand-edit the CRD.** The stub OCP shipped until 2026-09-27
    had no `cdi`, and the live apply died with `.spec.cdi: field not declared
    in schema`. The real CRD requires `spec.daemonsets`, which OCP sends empty.

## How the cluster knows a node has a card

1. **NFD labels**: `_setup_gpu_operator` looks for
   `feature.node.kubernetes.io/pci-0300_10de.present` or `pci-0302_10de.present`.
   That is the same evidence as sysfs, seen from the other side.
   - When the run joined workers, `setup_gpu_operator_after_join` (in
     `OCP::Cmd::Apply::Workloads`) checks again, unless the first check
     failed or `gpu.enabled` is false.
   - First it waits up to 600 s (`gpu_label_timeout`) for *any*
     `feature.node.kubernetes.io/` label on each new node. NFD's worker pod
     gets no network sandbox until Cilium's first BPF compile on the fresh
     node is done (4-5 min on brain, ~5.5 min on synapse), so it labels late.
     A node NFD never labels in time is a `[WARN]` on STDERR, and the check
     goes on with what is there.
   - Then it decides by what the first check did:
     - It skipped: the check runs again, and decides on the labels it sees.
     - It ran (k287): the check runs again only when a joined worker carries
       an NFD NVIDIA label; otherwise it says "No NVIDIA GPU on the new
       worker(s)" and stops. An up-to-date operator still waits (300 s,
       `gpu_ready_timeout`) for `nvidia.com/gpu` in `status.allocatable` on
       the new node (k273).
2. **Authoritative**: `nvidia.com/gpu` in the node's `status.allocatable`,
   published by the device plugin, plus a CUDA smoke pod.
   - Not capacity: the kubelet leaves capacity standing after a plugin
     unregisters (see `amd.md`). `OCP::Kubernetes` `node_gpu_count` and
     `ocp status` count allocatable (k270).
   - A node without it after the 300 s wait fails the GPU Operator step, as
     on AMD (k285): `[!!]`, counted, APPLY INCOMPLETE, exit 1, the check
     after the worker join included. `ocp node add --gpu` says it with
     `ocp apply` and keeps exit 0.
   - OCP's ClusterPolicy sets neither time-slicing nor MIG mixed, so the
     plugin publishes `nvidia.com/gpu` (live check on an RTX 3090 node,
     2026-11-03).
     `nvidia.com/gpu.shared` and `nvidia.com/mig-*` come only from a
     ClusterPolicy OCP does not write.
   - Everything before this is a prediction.

## ClusterPolicy (`_generate_gpu_operator_manifest`)

The generator lives in `OCP::Cmd::Apply::Workloads`, behind a delegator in
`OCP::Cmd::Apply`.

| Component | State | Why |
|---|---|---|
| `driver` | follows `gpu.driver` | never both sides at once |
| `toolkit` | follows `gpu.toolkit` | off where the host already has one |
| `devicePlugin` | on | publishes `nvidia.com/gpu` |
| `dcgm` + `dcgmExporter` | on | the operator runs its own hostengine on :5555 in the `nvidia-dcgm` container, and the exporter connects there. Expect a few exporter restarts while the hostengine starts |
| `gfd` | off | NFD does feature discovery |
| `nfd` | not sent | not a ClusterPolicy field (the CRD rejects it); OCP deploys NFD itself |
| `migManager` | off | MIG does not exist on GB10 |
| `validator` | always runs, operator image | no `enabled` field exists |
| `nodeStatusExporter` | off | |
| `daemonsets` | `{}` | required by the CRD; empty is the operator's zero value |

On DGX-class hosts NVIDIA's guidance is `driver.enabled=false` **and**
`toolkit.enabled=false`. The vendor image has both, and the toolkit DaemonSet
would rewrite a containerd config that already works.

### `toolkit.env`: two variables set, two left out on purpose

- **Set:** `CONTAINERD_SOCKET` and `CONTAINERD_CONFIG`, both node paths.
  - The socket is `/run/k3s/containerd/containerd.sock` on **both**
    distributions, because RKE2 runs k3s' agent code.
  - The config path follows the distribution:
    `/var/lib/rancher/{k3s,rke2}/agent/etc/containerd/config.toml`.
- **They are the operator's input.** It derives `RUNTIME_SOCKET` and
  `RUNTIME_CONFIG` from them and mounts the *directory* of each into the
  toolkit DaemonSet. Without them it falls back to `/etc/containerd/...` and
  `/run/containerd/...`, which are wrong on both distributions.
- **A wrong path that exists is the worst case.** The hostPath mounts cleanly,
  and the failure only surfaces when the toolkit tries to reach containerd.
- `RUNTIME_CONFIG_SOURCE` and `RUNTIME_DROP_IN_CONFIG` need nothing from OCP.
  The operator sets them itself.
- **Never set `CONTAINERD_SET_AS_DEFAULT` or `CONTAINERD_RUNTIME_CLASS`.**
  `t/40-gpu-clusterpolicy.t` asserts that both are absent.
  - The runtime class only restated the default. The operator overwrites it
    with `operator.runtimeClass` (`nvidia`).
  - Set-as-default would make nvidia the node's default runtime, a decision
    taken sideways. OCP keeps runc as the default: management pods reach
    nvidia through the RuntimeClass.
  - Upstream the variable is still live. It loses today only because
    `cdi.enabled` defaults to true, and that makes the operator hand the
    toolkit `NVIDIA_RUNTIME_SET_AS_DEFAULT=false` first. This was measured on
    the DGX Spark: `crictl` showed `defaultRuntimeName runc` while OCP still
    sent `1`.
  - Leaving it out is **not** a guard. The toolkit's own default for
    `--set-as-default` is true. What keeps runc the default is CDI being on,
    and OCP takes that from the CRD default without writing
    `cdi.enabled: true`.

## NFD (Node Feature Discovery)

OCP deploys NFD itself on every cluster; the operator never does. It goes into
the `node-feature-discovery` namespace, from
`registry.k8s.io/nfd/node-feature-discovery`. nfd-master (a Deployment)
labels, and nfd-worker (a DaemonSet) detects. The RBAC in
`_generate_nfd_manifest` mirrors upstream exactly, and every rule is
load-bearing. AMD's stack does not gate on NFD (see `amd.md`).

## Drift (`OCP::Drift`)

- Probed: `nfd` (the `nfd-master` Deployment and, since k369, the
  `nfd-worker` DaemonSet: two probes of one pin) and `gpu_operator` (the
  `gpu-operator` Deployment, `optional`, since absence is not drift). All are
  workloads OCP writes itself, so the image is honestly readable.
- Both are report-only (`remedy => undef`) and `self_healing`: a plain
  `ocp apply` re-applies the manifest that carries the version. `ocp update`
  leaves them to apply (`%APPLIED_BY_APPLY`).
- **Deliberately unprobed:** `nvidia_toolkit`, `nvidia_device_plugin`,
  `dcgm_exporter`, `nvidia_dcgm` and `nvidia_driver`. OCP puts those into the
  ClusterPolicy, and the operator turns them into DaemonSets whose names and
  layouts it owns and changes between releases. An honest probe reads the
  ClusterPolicy spec. It never guesses a DaemonSet name.

## Status

`ocp status` shows a GPU section when a node has `nvidia.com/gpu` in
allocatable or capacity (`OCP::Kubernetes::gpu_nodes`). A node whose plugin
is gone stays listed, so the reader sees it.

- Per node it shows one line with the `nvidia.com/gpu` **allocatable** (k270).
- Capacity appears beside it only where the two differ, marked as stale.
- There is no GPU Operator status and no device-plugin pod count.
- `--json`: `nodes[].gpu` is the allocatable count (0 when the node has
  none). `nodes[].gpu_capacity` is the capacity (`null` when the node has
  none).

The AMD block follows (see `amd.md`).
