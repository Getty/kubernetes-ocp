# AMD GPU workers — design

Date: 2026-10-31 · Card: k248 · Depends on: rex-gpu k1 (Rex::GPU::AMD), rex-rancher k95

## Intent

An AMD GPU node joins an OCP cluster as an ordinary GPU worker, the same way an NVIDIA
node does today. Which workload gets which GPU is decided later by the maintainer's GPU
management system (GPM). OCP therefore offers every allocation path that works and picks
none of them as policy. The maintainer gave this go on 2026-10-31 and skipped the design
questions ("hau rein"). Every choice below that is not quoted from upstream or from the
maintainer is the design author's call. Those choices are marked *(call)*.

## Goals

- **Host preparation on join.** `detect_gpu` finds the AMD GPU and Rex::GPU::AMD makes the
  kernel driver ready. If the driver is already working, it is left alone.
- **Allocation paths.** A cluster can offer both:
  - the classic device plugin (`amd.com/gpu`);
  - DRA (`ResourceClaim` against DeviceClass `gpu.amd.com`).
  It picks a default for the cluster, and a single node can override it.
- **Node labels for selection.** These are AMD's labeller labels plus a gfx-target label that
  OCP sets itself, because nothing upstream publishes one.
- **Pinning and drift.** Every image is pinned in `OCP::Versions`. Drift probes cover the
  objects OCP writes, and `ocp apply` redeploys a DaemonSet whose image is off its pin (k350). `ocp status` shows the AMD GPUs a node can hand out
  (`status.allocatable`, with capacity beside it).
- **Mixed clusters work.** The test cluster is an NVIDIA control plane (otho, RTX 3090) with an
  AMD worker (synapse).

## Non-goals

- **AMD GPU Operator mode.** It is deferred; see "Deferred".
- **Partitioning.** This covers Instinct CPX/NPS and the DCM. Synapse cannot exercise it, so it
  is not built now. The device plugin's `mixed` naming still passes through; on an
  unpartitioned GPU it registers the plain `amd.com/gpu` (verified on synapse).
- **Host ROCm userspace.** Containers bring their own ROCm. Kubernetes needs only the kernel
  driver plus `/dev/kfd` and `/dev/dri`. `Rex::GPU::AMD::install_rocm` exists, but OCP does
  not call it.
- **Scheduling policy.** There are no quotas, taints or priorities per GPU type. That is GPM's
  job.

## Anti-goals

- No moving image tags. The upstream manifests use `latest`, and the charts disagree with
  their own releases.
- No `kubectl` in any code path.
- No `--privileged` as a blanket fix. A DaemonSet runs privileged only where upstream or the
  live spike shows it is needed.
- No `HSA_OVERRIDE_GFX_VERSION` set by OCP. That is a workload decision.

## Facts this rests on

Sources: the upstream research report from 2026-10-31 (scratchpad, summarized on k248), the
live session on synapse, and the API that rex-gpu k1 announced.

### Hardware (synapse)

- Ryzen AI Max+ PRO 495 / Radeon 8065S, PCI `1002:1586`, gfx1151 APU, class `0380`.
- Ubuntu 24.04.5, HWE kernel 7.0, inbox amdgpu, ROCm 7.2.4 on the host.
- PyTorch and ComfyUI run on the host GPU.

### Detection

- Detection works today: `_gpu_action` returns `amd`, then stops.
- NFD's default config labels AMD GPUs `feature.node.kubernetes.io/pci-<class>_1002.present`.
  The class is `0300` (VGA), `0302` (3D), `0380` (APUs and Instinct MI100–MI300) or `1200`
  (MI355X).
- The device plugin dies if amdgpu is not loaded. It must run only on AMD nodes.

### Device plugin and labeller

- Source: `rocm/k8s-device-plugin` 1.31.0.11, labeller `labeller-1.31.0.11`.
- This is the only path with AMD's word on gfx1151 ("can be used in our AI MAX 395 clusters").
- **The plugin** returns kubelet DeviceSpecs only. That means no CDI, no RuntimeClass and no
  containerd change.
- **The labeller** sets `amd.com/gpu.{family,device-id,product-name,vram,cu-count,simd-count,driver-version}`.
  It sets no gfx target, and on an APU its vram is the carve-out.

### DRA driver

- Source: `rocm/k8s-gpu-dra-driver` v1.0.1.
- It runs on Kubernetes 1.36 (`resource.k8s.io/v1`).
- It writes its own CDI specs. containerd 2.x in our RKE2/k3s pins has CDI on by default.
- APU memory accounting is unproven (upstream #84). It publishes no gfx target.

### Metrics exporter

- Source: `rocm/device-metrics-exporter` v1.5.3.
- Instinct and Radeon AI only. AMD explicitly declines Ryzen APUs.

### Rex::GPU::AMD API (rex-gpu k1)

- Nothing is exported. Call it fully qualified.
- `install_driver(gpus => \@amd, method => 'auto'|'inbox'|'dkms', reboot => 0|1)`
  - Returns `'present'`, `'inbox'` or `'dkms'`.
  - Dies before any host change on bad arguments or an unsupported OS/kernel.
- `verify_amd([gpus => …])`
  - Warns and never dies.
  - Returns `{ ok, gpus => [{ slot, device_id, gfx_target, vram_bytes, gtt_bytes, kfd_node }] }`.
- Detect gives AMD entries `device_id`, `gfx_target` and `compute` 1/0/undef, with the same
  meaning as for NVIDIA.
- Feature flag: `Rex::GPU->can('amd_class')`.

## Design

### 1. Host — `share/Rexfile` (ocp-infra-worker)

- `detect_gpu` handles NVIDIA and AMD on the same host. If both are present, NVIDIA goes first,
  then AMD *(call; today's `_gpu_action` returns only one answer)*.
- New task `install_amd`:
  - It takes the AMD GPUs Rex::GPU does not mark `compute => 0`. Undef is handed on, the same
    as for NVIDIA.
  - **Integrated GPUs are opt-in** *(call)*. An AMD GPU that Rex::GPU marks `integrated => 1`
    (the iGPU of a Ryzen CPU or APU, synapse included) is handed on only when the Rexfile
    parameter `gpu_amd_integrated` is true:
    - The parameter is true when the node was joined explicitly as a GPU node
      (`ocp node add --gpu`, `spec.gpu: true`).
    - It is also true when `gpu.amd.integrated: true` is set cluster-wide.
    - Otherwise the GPU is skipped with one log line and gets no label.
    - `integrated` 0, undef or absent is handed on as before.
    - If nothing is left after the filter, `install_driver` is not called at all.
  - Why: detection runs on every node, control planes included. A Hetzner AX42 has a Phoenix
    iGPU (gfx1103, officially supported since ROCm Core SDK 10.1.0). OCP must not touch its
    driver or offer it as `amd.com/gpu` unless someone asked for it. Rex::GPU's own
    `gpu_setup` gates the same way (`amd_integrated => 1`). OCP calls `install_driver`
    directly and so has to apply the gate itself.
  - It calls `Rex::GPU::AMD::install_driver(gpus => …, method => 'auto')`, then `verify_amd()`.
  - It never reboots (`reboot => 0`). A DKMS install that needs a reboot says so and leaves it
    to the operator.
  - It installs no ROCm, no container toolkit, no CDI, and writes no containerd config.
- `gpu.driver: operator` keeps its meaning: who installs the kernel driver.
  - OCP has no AMD operator, so under `operator` OCP installs no AMD driver.
  - The log line says the driver must already be on the host *(call)*.
  - AMD GPUs are still detected and labelled under `operator` (marker label and gfx-target,
    with the integrated gate applied) *(call)*. Without the marker, an operator-mode cluster
    could never use an AMD node. The NVIDIA path under `operator` does not change.
- **Marker label** *(call)*. Every node on which the host step accepted at least one AMD GPU
  registers with `ocp.internal/amd-gpu.present=true`. The cluster stack selects on this
  marker (§3), because NFD cannot tell a skipped iGPU from an accepted one. The constant is
  `$OCP::Config::AMD_GPU_PRESENT_LABEL`.
- **gfx-target label.** For each AMD GPU `verify_amd` reports, the node registers with
  `ocp.internal/amd-gpu.gfx-target=<gfx>`.
  - If the node has more than one gfx target, it gets one label per target instead:
    `ocp.internal/amd-gpu.gfx-target.<gfx>=<count>`, AMD's labeller convention *(call)*.
  - Preferred path: the agent's `node-label` at registration, so no API write is needed.
  - The builder may instead patch the Node after the join, if the Rexfile cannot hand the value
    to the install step cleanly. Either way, the label must exist before GPM looks at the
    node, and a plain re-apply must not remove it.
- Guard: if `Rex::GPU->can('amd_class')` is false (Rex::GPU < next release), `install_amd`
  says so and skips. It does not die.

### 2. Config — `OCP::Config` (ocp-state-worker; validation helpers per ocp-choices-worker conventions)

```yaml
gpu:
  enabled: true
  driver: host            # unchanged, vendor-neutral: who installs the kernel driver
  toolkit: true           # unchanged, NVIDIA only
  amd:
    allocation: device-plugin   # device-plugin | dra | none — default for every AMD node
    resource_naming: single     # single | mixed — passed to the device plugin
    labeller: true              # AMD node labeller on every AMD node
    metrics: false              # device-metrics-exporter; Instinct / Radeon AI only
    integrated: false           # set up integrated AMD GPUs (iGPU/APU) on every node
```

- Accessors: `gpu_amd_allocation`, `gpu_amd_resource_naming`, `gpu_amd_labeller`,
  `gpu_amd_metrics` and `gpu_amd_integrated`.
- `integrated` reaches the Rexfile through the same OCPNodeProvider CR channel that
  `gpu.toolkit` uses (k223: CR.pm, Provider `gpu_flags_from_cr`, Node attribute, Bootstrap,
  Add, CRD). That channel is its own card. Until it exists, only the per-node route works:
  `ocp node add --gpu`. OCP::Node ORs the two together.
- Booleans are normalised to 0/1, as `gpu_toolkit` is.
- An unknown value croaks, as `gpu_driver` does.
- An absent `gpu.amd` means the defaults above.
- **Per-node override:** a node label `ocp.internal/amd-gpu.allocation` with the same values
  wins over the cluster default. It is set with `ocp node add --label` or by GPM *(call)*.
  This is how one cluster offers both paths at once.

### 3. Cluster stack — `OCP::Cmd::Apply::Workloads` + wiring in `Deploy`/`Drift` (ocp-apply-worker)

**Trigger, namespace and reconcile**

- The stack is deployed when any Node carries the marker `ocp.internal/amd-gpu.present=true`
  (§1) *(call; replaces the earlier NFD trigger)*.
  - The NFD labels `feature.node.kubernetes.io/pci-{0300,0302,0380,1200}_1002.present` are
    not a gate. An AX42 control plane carries `pci-0300_1002` for its iGPU too.
  - The marker is set at registration, so the after-join step does not wait for NFD.
- `gpu.enabled: false` deploys nothing.
- **The objects come from Rex::Rancher::K8s, not from OCP** *(call, following the maintainer's
  principle: generic code goes in the lib, OCP keeps only policy)*.
  - OCP decides when (trigger), where (affinity), which version (OCP::Versions) and what gets
    removed again, plus drift and status.
  - Namespace: `kube-system`, the lib's choice. The `amd-gpu` namespace from the first version
    of this spec is dropped.
  - Lib functions:
    - `deploy_amd_device_plugin(kubeconfig, version, affinity, resource_naming, wait,
      node_labeller)`: OCP passes `wait => 0` and `node_labeller => 0`, and deploys the
      labeller as its own component
    - `deploy_amd_node_labeller(kubeconfig, version, affinity)`
    - `deploy_amd_dra_driver(…)`
    - `deploy_amd_metrics_exporter(…)`
    - a `remove_amd_*` counterpart for each.
  - Source: rex-rancher k95 (commit 9dceb03), k101 (labeller on its own, resource_naming,
    wait, remove), k102 (DRA) and k103 (metrics), all on branch `worktree-k95-amd-gpu`,
    unmerged.
  - OCP needs a released Rex::Rancher with these functions, so the cpanfile pin waits for a
    release (maintainer).
  - OCP passes `wait => 0` and checks Ready itself. The lib's wait read `status.capacity`,
    which the kubelet leaves stale after a plugin unregisters, so it reported success on a
    redeploy before the pod was up (rex-rancher k106, fixed in cf10698 to read allocatable,
    unreleased). Ready means pod Ready plus `status.allocatable`, never capacity.
- Reconcile works like the NVIDIA operator: a manifest hash in deployed hashes, plus a running
  check. A second look runs after a worker join (`setup_gpu_operator_after_join` pattern):
  it checks the marker on the workers that came up Ready, once, without waiting, because the
  marker comes with the node's registration (no NFD label to wait for). Only
  `ocp node add --gpu` waits, for the marker or NFD's NVIDIA label (k251).

**AMD node match** (used by every DaemonSet below)

- `nodeAffinity` on the marker `ocp.internal/amd-gpu.present=true`, combined with the
  allocation terms below.

**Components**

| Object (kube-system, from the lib) | Image (Versions key) | Runs on |
|---|---|---|
| DaemonSet `amdgpu-device-plugin-daemonset` | `rocm/k8s-device-plugin:<amd_device_plugin>` | AMD nodes whose effective allocation is `device-plugin` |
| DaemonSet `amdgpu-labeller-daemonset` + SA `node-labeller-sa`/ClusterRole `cr-node-labeller`/Binding `labeller` | `rocm/k8s-device-plugin:labeller-<amd_device_plugin>` | all AMD nodes, if `labeller` |
| DaemonSet `k8s-gpu-dra-driver-kubeletplugin` + SA `k8s-gpu-dra-driver-service-account`/ClusterRole `k8s-gpu-dra-driver-role`/Binding `k8s-gpu-dra-driver-role-binding` + DeviceClass `gpu.amd.com` (`resource.k8s.io/v1`) + VAP/VAPB `resourceslices-policy-k8s-gpu-dra-driver`; upstream Helm-default names, rex-rancher k102 (not committed yet) | `rocm/k8s-gpu-dra-driver:<amd_dra_driver>` | AMD nodes whose effective allocation is `dra` |
| DaemonSet, SA, ClusterRole, ClusterRoleBinding and Service (ClusterIP :5000 `http`, internalTrafficPolicy Local), all `amdgpu-metrics-exporter`, + ConfigMap `amdgpu-metrics-exporter-config`; upstream GPU-branch names, rex-rancher k103 (4f2f3ca) | `rocm/device-metrics-exporter:<amd_metrics_exporter>` | AMD nodes, if `metrics` |

**Effective allocation per node**

- The override label wins. Otherwise `gpu.amd.allocation` applies.
- Express it as affinity terms, so that no controller is needed. For example, with default
  `device-plugin`, the plugin selects "AMD AND (label absent OR label=device-plugin)", and DRA
  selects "AMD AND label=dra".
- When the default is `dra`, the terms swap. When it is `none`, only explicit labels select.

**Component details**

- **Device plugin** *(verified live 2026-10-31 on synapse)*
  - Unprivileged (`allowPrivilegeEscalation: false`, drop ALL). It registers `amd.com/gpu: 1`.
  - Trap: the image has no ENTRYPOINT, only Cmd `./k8s-device-plugin …`. Setting `args`
    alone kills the container. With `-resource_naming_strategy`, set the command as well
    (reported to rex-rancher for k101).
- **Labeller** *(verified live)*
  - Needs **privileged**. Unprivileged, the device cgroup refuses `/dev/dri/card0` ("operation
    not permitted"), and only `device-id` comes through.
  - Privileged, it delivers `cu-count=40`, `device-id=1586`, `family=GC_11_5_0`,
    `product-name=AMD_Radeon_8065S`, `simd-count=80` and `vram=128G`.
  - `driver-version` stays empty under the inbox driver: there is no module version file.
- **DRA**
  - Mark it experimental in docs and status output.
  - The init container keeps upstream's `busybox:1.36`, in the DRA driver and in the metrics
    exporter alike (rex-rancher k102/k103, `Rex::Rancher::K8s`). It is a tag, not a digest,
    and the caller cannot override it: the one image of the stack that OCP's pins do not cover
    (open on the rex-rancher board).
  - The lib installs upstream's ValidatingAdmissionPolicy + Binding, which restricts the
    plugin's ResourceSlice writes to its own node. It needs `ServiceAccountTokenPodNodeInfo`
    (GA from 1.32), and the lib checks for `resource.k8s.io/v1` before deploying *(call,
    accepted for rex-rancher k102)*. Its resourceRules also name `v1` since rex-rancher k107;
    before that it blocked nothing on 1.36 (see "Lib run"). The webhook stays out: it needs cert-manager
    wiring.
- **Metrics:** off by default. Document that it is Instinct / Radeon AI only. Upstream does
  not support the exporter on APUs (upstream issues 281 and 353); on synapse many fields read
  0, so a run there proves the deployment, not the metrics.

### 4. Versions — `OCP::Versions` (ocp-infra-worker)

| Key | Pin |
|---|---|
| `amd_device_plugin` | `1.31.0.11` (labeller tag derived: `labeller-` prefix, same release) |
| `amd_dra_driver` | `v1.0.1` |
| `amd_metrics_exporter` | `v1.5.3` |

- No init-image pin: the lib writes `busybox:1.36` into the DRA and metrics init containers
  itself (see §3). OCP gets a pin once the lib takes one.
- Each pin gets a comment with its source and any floor.
- All images are amd64-only upstream; say so next to the pin.
- `ocp update` knows these components.

### 5. Drift — `OCP::Drift` (ocp-state-worker)

- Self-healing probes with no remedy task (`remedy => undef`). They read the image off the four
  DaemonSets that OCP has the lib write (kube-system, names as in §3). The AMD GPU step of
  `ocp apply` closes what they find:
  - a pin bump, through its options hash;
  - an image changed in the cluster, by reading the DaemonSet as the probe does
    (`OCP::Drift->version_against_pin`, k350).

  Args and other fields are not compared, by either side. The names live in one
  table. Device plugin and labeller are confirmed by the k101 live run; DRA and metrics
  follow the upstream Helm defaults that k102/k103 adopt and are confirmed once those land.
- All are `optional`. Absence is not drift, because the stack only exists where AMD hardware
  and `gpu.enabled` are.
- This mirrors the NFD and `gpu_operator` probes.

### 6. Status — `OCP::Cmd::Status` (ocp-status-worker)

The GPU section also shows:
- each AMD node (the marker, or any `amd.com/gpu` quantity) with its `amd.com/gpu`
  allocatable, capacity beside it;
- its `ocp.internal/amd-gpu.gfx-target` label(s);
- its effective allocation;
- the ResourceSlices of driver `gpu.amd.com` (count of devices);
- the AMD DaemonSets' ready/desired.

## Deferred

**AMD GPU Operator mode.** v1.5.1 is lab-validated only on Instinct. Its NFD rule lacks APU
IDs (needs our own NodeFeatureRule). Bug #665 strips labeller labels exactly when NFD is
external, as it is in OCP. Its metrics exporter does not serve APUs. Synapse cannot exercise
it meaningfully. Revisit with an Instinct host.

**Not yet offerable upstream:**
- the device plugin's `product` naming strategy;
- DRA `extendedResourceName` mapping (`amd.com/gpu` served by DRA);
- DRA auto-partitioning and VFIO.

**Non-root GPU pods.** AMD device nodes keep the host groups `render`/`video`. Non-root pods
need `supplementalGroups`, or the agent option `nonroot-devices`
(`device_ownership_from_security_context`). Offering that switch is a Rex::Rancher option
(k95 note), and OCP may expose it later *(call: not in this round)*.

## Live acceptance (otho CP + synapse worker)

1. Synapse joins via `ocp node add synapse --role worker --provider ssh-default --host 10.230.30.50 --gpu`.
   It is Ready, and the NVIDIA stack on otho keeps working.
2. `install_amd` reports `present` on synapse and changes nothing on the host.
3. The node carries `ocp.internal/amd-gpu.present=true` and
   `ocp.internal/amd-gpu.gfx-target=gfx1151` (integrated gate opened by `--gpu`), plus the
   labeller's `amd.com/gpu.*`.
   - A node without `--gpu` and without `gpu.amd.integrated` gets neither label, and no AMD
     component lands on it.
4. **device-plugin mode**
   - Node capacity `amd.com/gpu: 1`.
   - A pod with a ROCm PyTorch image and `amd.com/gpu: 1` runs a matmul and SDPA on the GPU.
   - Both are checked against CPU. Enumeration alone is not a pass.
5. **dra mode** (node label override)
   - A ResourceSlice for synapse is published.
   - A pod with a ResourceClaim for DeviceClass `gpu.amd.com` runs the same smoke.
   - The device plugin no longer advertises on that node.
6. `ocp status` shows all of the above. Drift is clean.
7. Re-apply is idempotent: the manifest hash is unchanged and nothing is redeployed.

## Left to the builder

- Exact Perl structure, sub names and test layout, within the lanes above.
- How the Rexfile hands the gfx target to the registration step.
- Whether the device-plugin/DRA affinity is generated or templated.

## Spike result (2026-10-31, otho CP + synapse worker, RKE2 v1.36.4+rke2r1, containerd 2.3.4)

Hand-written manifests in place of the later lib functions. The host step was simulated by
setting the marker and gfx-target labels by hand. The smoke test is
`rocm/pytorch:rocm7.2.4_ubuntu24.04_py3.12_pytorch_release_2.9.1` with `torch_smoke.py
--size 512 --sdpa`: matmul against a CPU reference, fp32 autograd, SDPA.

| Check | Result |
|---|---|
| NFD on synapse | `pci-0380_1002.present`, as expected |
| Device plugin, unprivileged | Registers `amd.com/gpu: 1` (once the command trap is fixed, §3) |
| Smoke via `amd.com/gpu: 1` | passed for fp32, fp16 and bf16 with SDPA. torch: `AMD Radeon 8065S`, gfx1151, 128 GiB |
| Labeller, unprivileged | Only `device-id`; `/dev/dri/card0` "operation not permitted" |
| Labeller, privileged | cu-count 40, family GC_11_5_0, product-name AMD_Radeon_8065S, simd 80, vram 128G; driver-version empty (inbox) |
| DRA v1.0.1 | ResourceSlice `gpu-0-128`: deviceID 0x1586, CUs 40, memory 128Gi, simd 80, productName empty, **no gfx attribute** |
| Smoke via ResourceClaim (DeviceClass `gpu.amd.com`) | passed for fp32, fp16 and bf16 with SDPA |
| Per-node switch device-plugin → dra → back | Each DaemonSet leaves and arrives as the affinity says. Under dra, `amd.com/gpu` allocatable is 0. After DRA leaves, the kubelet deletes the ResourceSlice by itself within about 25 s |

- Device ownership in the pod differs by path.
  - Device plugin: `/dev/kfd` and `renderD128` keep the host's render GID (993), and `card0`
    keeps `video`.
  - DRA (CDI): everything is `root:root 0660`.
  - So a non-root pod needs the host GIDs as `supplementalGroups` under the device plugin, and
    GID 0 under DRA. That is input for the deferred non-root topic (rex-rancher k96).
- Cluster findings along the way, not AMD-specific:
  - The node registered with the default route's address (eno1 192.168.0.165) instead of the
    join address on vlan30. At the time of the spike, OCP set no `node-ip`. k254 adds an
    explicit one (ocp.yaml `control_planes[].node_ip`, `ocp node add --node_ip`). It needs
    rex-rancher k100. An automatic default (the route to the join server, computed on the
    host) is rex-rancher k111. A default taken from the ssh target was dropped: a NAT
    address is not on the node.
  - After setting `node-ip` by hand, the Cilium agent on the node also had to be restarted.
    Until then CiliumNode kept the old address, the tunnel was broken in one direction, and
    every pull through the `ocp-cache` mirror ran into a 2.5 min timeout before containerd
    fell back to Docker Hub.

## Lib run (2026-10-31, rex-rancher k101 at 0b6e1b3 and k102 at 5310056, same cluster)

The rex-rancher session ran the committed k101 and k102 functions against amdlab through a
kubeconfig, kube-system plus node labels only. Plugin affinity: marker `In [true]` AND
`ocp.internal/amd-gpu.allocation` `NotIn [dra, none]`. DRA affinity: marker `In [true]` AND
allocation `In [dra]`. Labeller affinity: marker only.

| Check | Result |
|---|---|
| `deploy_amd_device_plugin` 1.31.0.11, single | Pod only on synapse, Running, 0 restarts. Spec as built: command `./k8s-device-plugin`, workingDir `/root`, unprivileged. Log "Registration for endpoint amd.com_gpu", "Found 1 AMDGPUs". allocatable `amd.com/gpu` 0 → 1 |
| `deploy_amd_node_labeller` | Pod only on synapse. Same labels as the privileged spike; no `driver-version` |
| `remove_*`, twice | First run deletes DaemonSet, SA, ClusterRoleBinding, ClusterRole; second run reports each as not there, exit 0. allocatable back to 0. The `amd.com/*` node labels stay (documented in the lib's POD) |
| `mixed` naming | Still registers `amd.com_gpu` on the unpartitioned gfx1151 |
| Redeploy over an existing DaemonSet | The update path works live |
| Smoke via `amd.com/gpu: 1` against the lib's plugin | passed for fp32, fp16 and bf16 with SDPA, gfx1151 |
| Label `allocation=dra` on synapse | Plugin DaemonSet goes to DESIRED 0, allocatable `amd.com/gpu` falls to 0 a few seconds after the pod. The labeller keeps running |
| `deploy_amd_dra_driver` v1.0.1 | Kubelet plugin only on synapse, 0 restarts. DeviceClass `gpu.amd.com`, VAP/VAPB present. ResourceSlice of driver `gpu.amd.com`, pool `synapse`, device `gpu-0-128`: deviceID 0x1586, CUs 40, simd 80, memory 128Gi, pciBusID 0000:95:00.0; productName empty, no driverVersion (inbox) |
| Smoke via ResourceClaim against the lib's DRA driver | passed for fp32, fp16 and bf16 with SDPA, gfx1151; devices `root:root` in the pod |
| `remove_amd_dra_driver`, twice | First run deletes DaemonSet, DeviceClass, VAPB, VAP, ClusterRoleBinding, ClusterRole, SA; second run reports all seven as not there, exit 0. The kubelet removes the ResourceSlice about 30 s after the DaemonSet goes |
| Label removed again | The plugin pod returns on its own, registers again, allocatable back to 1 |

- k102's ValidatingAdmissionPolicy (from upstream chart v1.0.1) blocked nothing on 1.36: its
  resourceRules named only `v1beta1`, the cluster serves `resource.k8s.io` only as `v1`, and a
  server dry-run of a foreign-node ResourceSlice as the plugin's SA was admitted. Upstream main
  is not fixed either. rex-rancher k107 (057cef4) names `["v1beta1","v1"]`; live on amdlab:
  - The policy's typeChecking is empty, and the binding is set to Deny.
  - Plain impersonation of the plugin's SA is denied, but only through an evaluation error
    ("no such key: extra") plus failurePolicy Fail, because an impersonated user carries no
    node extra.
  - With the node extra set: `synapse` writing a slice for `otho` is denied by the rule itself
    ("may not modify resourceslices on node 'otho'"), and `otho` writing its own slice is
    admitted. Both were dry-runs.
  - The plugin's own slice was deleted and then recreated under the active policy, with no
    Denied entry in its log.
- The plugin binary in image 1.31.0.11 reports itself as `v1.25.2.7-137-g1de16818`. Never read
  the version off its log.
- The lib's wait reported success one second into a redeploy while the pod was still
  ContainerCreating: it reads stale `status.capacity` (rex-rancher k106; also hits the NVIDIA
  path). OCP is unaffected because it passes `wait => 0` (§3). Fixed in cf10698 to read
  allocatable. Live before the redeploy: capacity 1, allocatable 0, which confirms the bug's
  precondition. A redeploy run gave `[ok]` about 4 s after the plugin registered, but that run
  does not tell old and new code apart. The discriminating run (057cef4) did:
  - Setup: allocation `dra` on synapse, so no plugin pod, capacity 1, allocatable 0.
  - `deploy_amd_device_plugin` with wait polled "No allocatable GPU yet" 24 times, about 5 s
    apart.
  - It then warned "amd.com/gpu resource did not appear — check device plugin" about 2 min
    after the apply. No `[ok]`.
  - The old code would have said `[ok]` on its first poll.
  - Rex::Logger sends everything to STDERR, INFO included.
  - The lib still logs "AMD GPU device plugin ready" right after the warning (rex-rancher
    k110, NVIDIA alike). OCP is not affected (`wait => 0`).
- k103 (4f2f3ca), metrics exporter v1.5.3, marker affinity: pod only on synapse, "serving
  requests on 0.0.0.0:5000"; `/metrics` through the API-server proxy to the Service returned
  117 `amd_` series with the ConfigMap's `cluster_name`, many of them unsupported/0 on the APU.
  A second deploy is a true no-op (resourceVersion and DaemonSet generation unchanged);
  remove twice, then redeploy, both clean. Upstream has no readinessProbe: the pod is Ready a
  few seconds before port 5000 listens (a 502 in that window).

## OCP run (2026-10-31, same cluster, OCP image `live-20bec47`)

The OCP image was built from main at 20bec47 (k254). It carries the unreleased libs: Rex::Rancher 0.005 from rex-rancher 057cef4, and Rex::GPU 0.006 from rex-gpu fed6101. The cluster's OCPNode CRD came from an older image, without `nodeIP` in its schema. `gpu.amd.metrics` is false.

| Step | Result |
|---|---|
| `ocp node rm synapse` | RKE2 uninstalled. `/etc/rancher` and `/var/lib/rancher` are gone. The Node and its OCPNode are deleted |
| `ocp node add synapse … --gpu --node_ip 10.230.30.50` (old CRD) | Host step (k249): the node registers with `ocp.internal/amd-gpu.present=true` and `gfx-target=gfx1151`, set through the config.yaml `node-label`. Wiring (k251): it removed the metrics exporter ("no longer selected") and deployed the labeller. The device plugin failed after 300 s (`0 of 1 pod(s) ready`, "Run `ocp apply`"). Two causes: Cilium sandbox failures on the fresh node, and a 4 min image pull over 192.168.0.165. The apiserver pruned `spec.nodeIP` because the old CRD schema lacks it, so the node registered on 192.168.0.165 and nothing said so (k290) |
| `ocp apply --dry-run` | "No drift detected", although the CRD was outdated (k291) |
| `ocp apply` | exit 0. It deployed the device plugin ("was missing"); the labeller was up to date. It brought the node CRDs up to date (`nodeIP` now in the schema). "CONTROL PLANE DEPLOYED SUCCESSFULLY" |
| `ocp status` (k252, k258, k270) | otho `1x NVIDIA GPU`. synapse: `amd.com/gpu: 1 allocatable (capacity 1)`, gfx target gfx1151, allocation `device-plugin (cluster default gpu.amd.allocation)`. DaemonSets: device plugin 1/1, labeller 1/1, DRA and metrics exporter not deployed, no ResourceSlices. JSON `amd_gpu` gives the same, with `allocation_source: config` |
| Second `node rm` + `node add --node_ip 10.230.30.50` (current CRD) | `spec.nodeIP` and `status.nodeIP` are 10.230.30.50, config.yaml carries `node-ip: [10.230.30.50]`, and the node's InternalIP is 10.230.30.50, with no mismatch warning: k254 works end to end. The AMD step reported both DaemonSets "already deployed (up to date)" and did not wait (k286). `amd.com/gpu` allocatable 1 appeared about 300 s after `node add` returned, about 7 min after the node registered. Cilium's agent on synapse was Ready at 04:15:15, but sandboxes failed (`buildPermitAcquisition`) until 04:20:44. After that the image pulled in 3.4 s |

After the second join, the rest of the acceptance list, all through OCP, with no lib function called by hand:

| Step | Result |
|---|---|
| Smoke via `amd.com/gpu: 1` (OCP's device plugin) | passed for fp32, fp16 and bf16 with SDPA, `AMD Radeon 8065S`, gfx1151, torch 2.9.1+rocm7.2.4. The image (10.4 GB) pulled in 15:39 min because the RKE2 uninstall had emptied containerd. `/dev/kfd` and `renderD128` carry the host render GID 993 in the pod |
| Node label `ocp.internal/amd-gpu.allocation=dra`, then `ocp apply` | exit 0, about 1 min. "AMD GPU node(s): synapse (dra)". It removed the device plugin ("no AMD GPU node has allocation device-plugin") and deployed DRA driver v1.0.1; the labeller was up to date. DeviceClass `gpu.amd.com` and a ResourceSlice for synapse (`gpu-0-128`) appeared; `amd.com/gpu` allocatable 0 |
| Smoke via ResourceClaim (DeviceClass `gpu.amd.com`) | passed for fp32, fp16 and bf16 with SDPA, gfx1151. Devices `root:root` in the pod |
| `ocp status` under dra | `amd.com/gpu: 0 allocatable (capacity 1: stale after a device plugin unregisters, or unhealthy devices; only allocatable schedules)`, `allocation: dra [experimental] (node label ocp.internal/amd-gpu.allocation)`, ResourceSlices: synapse 1 device, DRA kubelet plugin 1/1, device plugin not deployed |
| Label removed, then `ocp apply` | exit 0. It removed the DRA driver ("no AMD GPU node has allocation dra") and deployed the device plugin again. DeviceClass and ResourceSlice are gone, allocatable 1 |
| `ocp apply` once more | exit 0, "No drift detected", every component "up to date". The AMD DaemonSets and the GPU Operator's DaemonSets kept their resourceVersion and generation. Only the Cilium Gateway step prints "Creating Cilium Gateway..." on every run; the Gateway itself stays unchanged (server-side apply, generation 1). That is wording, filed as its own card |

So acceptance items 1 and 3 to 7 hold live through OCP. Item 2 (`install_amd` reports `present`) is covered by the labels the host step set. The check that a node without `--gpu` gets no AMD label ran only in `t/`: the cluster has no second AMD host to leave out.

- On a fresh node, the AMD pods wait on the CNI. A device plugin and labeller on `hostNetwork` would not (rex-rancher k112, backlog). A timeout budget for fresh nodes in OCP is k286.
- A `node add --node_ip` against a cluster whose OCPNode CRD predates k254 loses the address without a word, until the next `ocp apply` refreshes the CRD. k290 makes `node add` refuse instead.

## Open / unverified

- The OCP host step (k249) and OCP's own wiring (k251) ran live, device plugin and DRA alike (see "OCP run"). The DRA switch was tested by the node label only; `gpu.amd.allocation: dra` as the cluster default goes through the same per-node computation, but did not run live.
- The libs OCP ran with are unreleased (Rex::Rancher 0.005 on rex-rancher's `worktree-k95-amd-gpu`, Rex::GPU 0.006 on rex-gpu's `worktree-k1-amd-driver`). The cpanfile stays at the released versions until those are out.
- DRA memory capacity on the APU: 128Gi is the carve-out the driver reports, not "usable
  RAM" (the OS sees 62 GiB). Whether a claim with a memory request behaves sensibly is
  untested. DRA stays experimental.
- RKE2 config key `nonroot-devices`: unverified, deferred anyway.
