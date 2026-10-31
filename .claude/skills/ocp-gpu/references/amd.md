# AMD — host step, labels, cluster stack, drift

OCP's AMD side in full: who touches what, which labels carry the decision, and
how the cluster stack converges. The design, and what was measured live on
synapse (gfx1151 APU, worker of the otho cluster), is in
`docs/superpowers/specs/2026-10-31-amd-gpu-worker-design.md`. When the spec and
the code disagree, the code wins, and the code is what this file states. Generic
ROCm questions (images, HIP, `HSA_OVERRIDE_GFX_VERSION`) belong to skill
`rocm-engineering`.

| Part | Where |
|---|---|
| Host step: driver and node labels | `share/Rexfile` `detect_gpu`, `install_amd`, `_amd_gfx_labels` |
| Switches, label names | `OCP::Config` (`gpu_amd_*`, `$AMD_GPU_*_LABEL`, `@GPU_AMD_*`) |
| Integrated-GPU opt-in per node | `OCP::Node` (`gpu_amd_integrated`, `_install_kubernetes`) |
| Cluster stack | `OCP::Cmd::Apply::AMDGPU`, called from `Apply/Deploy.pm`, `Apply/Drift.pm`, `Node/Add.pm` |
| DaemonSet names | `%OCP::Drift::AMD_GPU_DAEMONSETS`, the one table for drift, apply and status |
| Pins | `OCP::Versions`: `amd_device_plugin`, `amd_dra_driver`, `amd_metrics_exporter` |
| Status | `OCP::Cmd::Status` `_print_amd_gpu`, `_amd_gpu_json` (lane: ocp-status-worker) |
| Tests | `t/249-amd-gpu-host.t`, `t/250-gpu-amd-integrated.t`, `t/251-amd-gpu-stack.t`, `t/252-status-amd-gpu.t`, `t/258-status-json-amd-gpu.t` |

## The libraries are not released yet

Both halves rest on library code that no CPAN release carries yet. The versions
pinned in `cpanfile` have none of it.

- **Rex::GPU::AMD** is on rex-gpu branch `worktree-k1-amd-driver` (rex-gpu k1).
  - Its feature flag is `Rex::GPU->can('amd_class')`.
  - The released detection marks every AMD GPU `compute => 0`. `detect_gpu`
    then says `AMD GPU present, but none Rex::GPU knows to be compute-capable`
    (`amd-unsupported`), and `install_amd` never runs.
  - The `amd_class` guard in `install_amd` covers a Rex::GPU whose detection
    hands an AMD GPU on but that has no Rex::GPU::AMD. It prints `[WARN] AMD
    GPU present (...), but Rex::GPU ... has no AMD support` and never dies.
  - Either way: no driver and **no labels**. No node gets the marker, and the
    cluster stack has nothing to select.
  - Nothing is exported, so call it fully qualified.
- **The `Rex::Rancher::K8s` functions** `deploy_amd_device_plugin`,
  `deploy_amd_node_labeller`, `deploy_amd_dra_driver`,
  `deploy_amd_metrics_exporter` and their `remove_amd_*` counterparts are on
  rex-rancher branch `worktree-k95-amd-gpu`, unmerged (rex-rancher k95, k101,
  k102, k103, k106).
  - Before any call, `AMDGPU::setup` checks that every function this run needs
    exists (`lib_missing`).
  - If one is missing, apply prints a single `[WARN] The AMD GPU stack needs a
    newer Rex::Rancher: Rex::Rancher::K8s <version> has no ...; nothing deployed
    or removed` on STDERR. The result is `skipped` + `warned`, and **never a
    failed apply**.
  - The check runs only when there is something to deploy or remove. With
    nothing to do, the step prints one skip line instead (for example `No AMD
    GPU nodes`).
- The cpanfile pins can only move once the maintainer releases the libraries.

## Host step (`share/Rexfile`)

Detection is shared with NVIDIA (`nvidia-host.md`): one sysfs read, then
`_gpu_actions` returns NVIDIA's answer first, then `amd` or `amd-unsupported`.
`_driver_gpus($detected, 'amd')` drops `compute => 0` and hands on
`compute => undef`, the same rule as for NVIDIA.

`install_amd`:

1. **Integrated gate.** A GPU with `integrated => 1` (the iGPU of a Ryzen CPU or
   APU) is set up only when `gpu_amd_integrated` is true. Otherwise it gets one
   log line ("join the node with --gpu or set gpu.amd.integrated: true") and no
   label.
   - The reason: detection runs on every node, control planes included, and a
     Hetzner AX42's Phoenix iGPU (gfx1103) is nobody's GPU node.
   - `integrated` 0 or undef is handed on.
2. Nothing left → "No AMD GPU to set up". `install_driver` is never called with
   an empty list.
3. `Rex::GPU->can('amd_class')` false → `[WARN]`, return no labels. It never
   dies.
4. Under `gpu.driver: host` it calls
   `Rex::GPU::AMD::install_driver(gpus => \@gpus, method => 'auto', reboot => 0)`.
   - The call returns `present` (a working driver, left alone), `inbox`, or
     `dkms`.
   - It dies before any host change on an unsupported OS or kernel.
   - **OCP never reboots.** A DKMS module that needs a reboot is reported, and
     the reboot is the operator's call.
5. Under `gpu.driver: operator` there is no install. OCP has no AMD operator,
   and the log line says the driver must already be on the host. The GPUs are
   still verified and labelled; otherwise an operator-mode cluster could never
   use an AMD node. A detection that dies under `operator` is a `[WARN]`, and
   the node joins without AMD labels.
6. `Rex::GPU::AMD::verify_amd(gpus => \@gpus)` warns and never dies. When it is
   not `ok`, the task prints `[WARN]`, with a reboot hint after `dkms`.
7. It returns the labels described below. `_with_gpu_labels` appends them to
   the install's `node_labels`, and a key the OCPNode spec already sets keeps
   the spec's value. Rex::Rancher writes them as config.yaml `node-label`.
   - The labels are on the Node from registration on, with no API write.
   - OCP::Node's convergence removes only labels it recorded in
     `ocp.internal/managed-labels`, so a re-apply keeps them.

The host step installs no ROCm (`install_rocm` is never called; containers
bring their own), no container toolkit, no CDI and no containerd config. It
never sets `HSA_OVERRIDE_GFX_VERSION`, which is a workload decision. The
Rexfile writes the label keys out literally, because it runs under rex without
`lib/`. `t/249` holds them equal to the `OCP::Config` constants.

### Where `gpu_amd_integrated` comes from

- `OCP::Node` passes `gpu_amd_integrated => 1` when the OCPNode's `spec.gpu` is
  true (`ocp node add --gpu`) **or** its `gpu_amd_integrated` attribute is set.
  It passes nothing where `gpu` is 0, because there no detection runs at all.
  The Rexfile's default is 0.
- **ocp.yaml `gpu.amd.integrated` reaches no node yet.** `OCP::Node`'s
  attribute has no caller, and its OCPNodeProvider CR channel (the k223 path
  that `gpu.toolkit` takes) is still to come. The control-plane bootstrap never
  passes it. Today an iGPU is set up only through `ocp node add --gpu`.

## Labels

| Label | Set by | Meaning |
|---|---|---|
| `ocp.internal/amd-gpu.present=true` (`$OCP::Config::AMD_GPU_PRESENT_LABEL`) | host step, at registration | at least one AMD GPU accepted, verified or not (a DKMS module waiting for a reboot still counts). **The only trigger and selector of the cluster stack** |
| `ocp.internal/amd-gpu.gfx-target=<gfx>` (`$AMD_GPU_GFX_TARGET_LABEL`) | host step | the gfx target every verified GPU shares. Nothing upstream publishes one |
| `ocp.internal/amd-gpu.gfx-target.<gfx>=<count>` | host step | instead of the above, one label per target when the GPUs differ (AMD's labeller convention) |
| `ocp.internal/amd-gpu.allocation=device-plugin\|dra\|none` (`$AMD_GPU_ALLOCATION_LABEL`) | the user (`ocp node add --label`) or the GPU management system; never OCP | per-node override of `gpu.amd.allocation` |
| `amd.com/gpu.{family,device-id,product-name,vram,cu-count,simd-count,driver-version}` | AMD's labeller DaemonSet | descriptive only. No gfx target; on an APU `vram` is the carve-out; `driver-version` is empty under the inbox driver |

- A gfx target becomes a label only when it matches `gfx[0-9a-z]{1,40}`.
  Anything else is a `[WARN]` and gets no label.
- A GPU without a gfx target (no KFD node, so no working driver) adds no
  gfx-target label.
- **Never gate the AMD stack on NFD.** NFD's
  `feature.node.kubernetes.io/pci-{0300,0302,0380,1200}_1002.present` cannot
  tell an iGPU the gate skipped from one OCP set up. An AX42 control plane
  carries `pci-0300_1002` too.

## Cluster stack (`OCP::Cmd::Apply::AMDGPU`)

**Entry points.**

- `step` runs on the full deploy (`Apply/Deploy.pm`) and on the reconcile path
  (`Apply/Drift.pm`), as `[..] Checking AMD GPU stack...`.
- `after_join` runs once more after the worker step, when a worker that came
  up Ready carries the marker. There is nothing to wait for, since the marker
  comes with registration. It is skipped when the first step failed, warned or
  did not run.
- `ocp node add --gpu` (`_ensure_amd_gpu_stack`) waits up to 300 s for the
  marker or an NFD NVIDIA label, then runs `step`.
  - It is never fatal: the exit code reflects only whether the node is Ready.
  - No GPU shown in time, or a failed component, is said on STDERR together
    with `ocp apply` as the way to get the stack. A missing-lib `[WARN]` stands
    alone.

**Trigger.** The stack needs `gpu.enabled` and at least one Node that the label
selector `ocp.internal/amd-gpu.present=true` returns, with the value checked
again (`marker_nodes`).

**Objects.** All of them come from the lib, all in `kube-system`, with
upstream's names. OCP decides when (trigger), where (affinity), which version
(pins), and what is removed again.

| Role | DaemonSet | Other objects | Pin (image) | `.ocp/deployed.yaml` key |
|---|---|---|---|---|
| `device_plugin` | `amdgpu-device-plugin-daemonset` | none | `amd_device_plugin` (`rocm/k8s-device-plugin:<pin>`) | `amd-gpu-device-plugin` |
| `labeller` | `amdgpu-labeller-daemonset` (privileged) | SA `node-labeller-sa`, ClusterRole `cr-node-labeller`, CRB `labeller` | `amd_device_plugin` (tag `labeller-<pin>`) | `amd-gpu-node-labeller` |
| `dra` (experimental) | `k8s-gpu-dra-driver-kubeletplugin` | SA `k8s-gpu-dra-driver-service-account`, ClusterRole `k8s-gpu-dra-driver-role`, CRB `k8s-gpu-dra-driver-role-binding`, DeviceClass `gpu.amd.com` (`resource.k8s.io/v1`), VAP + VAPB `resourceslices-policy-k8s-gpu-dra-driver` | `amd_dra_driver` (`rocm/k8s-gpu-dra-driver:<pin>`) | `amd-gpu-dra-driver` |
| `metrics` | `amdgpu-metrics-exporter` | SA, ClusterRole, CRB and Service (ClusterIP :5000 `http`, `internalTrafficPolicy: Local`) all `amdgpu-metrics-exporter`, ConfigMap `amdgpu-metrics-exporter-config` | `amd_metrics_exporter` (`rocm/device-metrics-exporter:<pin>`) | `amd-gpu-metrics-exporter` |

- The device plugin hands kubelet DeviceSpecs only, with no CDI and no
  RuntimeClass. It is unprivileged.
- The DRA driver writes its own CDI specs, and containerd 2.x has CDI on by
  default.
- The DRA and metrics init containers run `busybox:1.36`, a moving tag that the
  lib writes and the caller cannot override. It is the one image of the stack
  that OCP's pins do not cover.
- The metrics exporter serves Instinct and Radeon AI only. Upstream does not
  support Ryzen APUs, and many fields read 0 there.

### Affinity: which component selects which nodes

`affinity($component, $default)` returns one `nodeSelectorTerm`. Every
component carries `ocp.internal/amd-gpu.present In [true]`. The two allocation
components AND an allocation term on top:

- The **default's own** component gets `NotIn` the other two values. It holds
  for a node without the label.
- The **other** component gets `In [own value]`.

| `gpu.amd.allocation` | device plugin selects | DRA driver selects |
|---|---|---|
| `device-plugin` (default) | allocation `NotIn [dra, none]` | allocation `In [dra]` |
| `dra` | allocation `In [device-plugin]` | allocation `NotIn [device-plugin, none]` |
| `none` | allocation `In [device-plugin]` | allocation `In [dra]` |

- The labeller and the metrics exporter select on the marker alone.
  `gpu.amd.labeller` (default true) and `gpu.amd.metrics` (default false)
  switch them on or off.
- A node therefore gets exactly one allocation path, or none.
- An allocation label value outside the three falls through `NotIn` to the
  default's component, with a `[WARN]` naming the node.
- `selects()` evaluates the same terms locally to decide which nodes a
  component is for, so apply and the scheduler cannot disagree.

### Reconcile and order

- Each component is hashed as MD5 over canonical JSON of `{call, lib => the
  Rex::Rancher::K8s $VERSION, options}`.
  - The options are `version` and `affinity`. The device plugin adds
    `resource_naming`, `wait => 0` and `node_labeller => 0`, because OCP
    deploys the labeller as its own component.
  - An equal hash with the DaemonSet present means `unchanged`. Otherwise the
    outcome is `deployed` (not recorded before), `restored` (DaemonSet gone) or
    `updated`.
- The lib's calls run with `Rex::Logger` silenced, because STDERR is the error
  channel. Progress is OCP's own, on STDOUT.
- Deploy order: the non-default allocation component (`In`) first, then the
  default's (`NotIn`), then the labeller and the metrics exporter. A switched
  allocation takes the old component off a node before the new one lands.
- When the DRA driver is refused on a cluster without `resource.k8s.io/v1`, the
  step adds a hint: Kubernetes 1.34+, and `device-plugin` in the meantime.

### Readiness: allocatable, never capacity

OCP passes `wait => 0` and checks readiness itself (`wait_ready`, 300 s budget,
10 s interval). The lib's own wait used to read `status.capacity` and reported
success one second into a redeploy (rex-rancher k106).

1. The DaemonSet rolled out: `observedGeneration` >= `generation`,
   `desiredNumberScheduled` > 0, and `numberReady` and `updatedNumberScheduled`
   equal to desired.
2. Device plugin: every node it selects shows `amd.com/gpu` > 0 in
   **`status.allocatable`**. Under `mixed` naming, any `amd.com/*` resource
   counts.
3. DRA driver: one `resource.k8s.io/v1` ResourceSlice of driver `gpu.amd.com`
   exists per node it selects.
4. Labeller and metrics exporter: the DaemonSet alone. The exporter has no
   readinessProbe upstream, so `/metrics` can return 502 for a few seconds
   after the pod is Ready. Apply does not probe it.

**Capacity never proves anything.** The kubelet keeps it after a device plugin
unregisters. Under `dra` a node's allocatable `amd.com/gpu` is 0, which is
correct.

### Removal

- A component that no marker node selects is removed when OCP recorded it in
  `.ocp/deployed.yaml` or its DaemonSet exists. Its hash is forgotten
  afterwards. The causes:
  - the last AMD node is gone;
  - `gpu.enabled: false`;
  - `gpu.amd.labeller` or `gpu.amd.metrics` is switched off;
  - no node has that allocation any more.
- Order: `dra`, `device_plugin`, `labeller`, `metrics`. The DRA driver goes
  first, so a node never has the plugin and the driver at once.
- Unlike the NVIDIA operator, which nothing removes, these components can go:
  they hold nothing of the user's. A device plugin left on a node switched to
  DRA would hand out the same GPU twice.
- The `remove_amd_*` calls are idempotent: a second run reports each object as
  absent and succeeds.
- What stays behind:
  - The labeller's `amd.com/gpu.*` node labels stay.
  - The marker, gfx-target and allocation labels are registration and user
    labels, and OCP never removes them.
  - The kubelet deletes a node's ResourceSlice about 30 s after the DRA
    DaemonSet goes.
- When the Nodes cannot be listed, `setup` dies and nothing is removed. `step`
  turns that into `[!!] AMD GPU stack setup failed`.

## Drift, pins, update

- `OCP::Drift` has four probe entries, each `kind => 'DaemonSet'` and spread
  from `%AMD_GPU_DAEMONSETS`. All are `remedy => undef`, `optional` (absence is
  never drift) and `self_healing`, because `ocp apply` re-deploys them at the
  pin.
  - `amd_device_plugin` is probed twice: the plugin, and the labeller with
    `tag_prefix => 'labeller-'`. The whole tag is compared, so the labeller
    image under a plain tag is drift.
  - `amd_dra_driver` and `amd_metrics_exporter` are probed once each.
- Each pin comment in `OCP::Versions` names its upstream repo and release. All
  AMD images are amd64-only upstream. Never use upstream's moving tags
  (`latest`): OCP pins release tags.
- `ocp update` lists the three `amd_*` keys in `%APPLIED_BY_APPLY` and leaves
  them to `ocp apply`. No Rex task upgrades them.

## Status (read side, ocp-status-worker)

`ocp status` adds an AMD block when a node carries the marker or any
`amd.com/gpu` quantity.

- Per node it shows `amd.com/gpu` as allocatable, with capacity beside it and
  flagged when it differs.
- Next come the gfx target(s) and the effective allocation with its source
  (node label or cluster default). `dra` is marked `[experimental]`.
- It lists the DRA ResourceSlices per node, counting only the newest pool
  generation. A 404 there means "not served", not a fault.
- It shows the four DaemonSets' ready/desired.

`ocp status --json` carries the same as `amd_gpu`, present only when AMD nodes
exist:

```
amd_gpu: { nodes: [{name, allocatable, capacity, gfx_targets, allocation, allocation_source}],
           resource_slices: {state: served|not-served|unknown, devices: {node: n}},
           daemonsets: {<role>: {namespace, name, state: ready|partial|not-deployed|unknown, ready, desired}} }
```

A value that could not be read is `null`, with the reason on STDERR.

## Traps from the live runs

- The device plugin image has no ENTRYPOINT, only Cmd. `args` alone kills the
  container. The lib sets the command.
- The labeller needs **privileged**. Unprivileged, the device cgroup refuses
  `/dev/dri/card0`, and only `device-id` comes through.
- The plugin binary logs a version unrelated to its image tag (image 1.31.0.11
  logs `v1.25.2.7-...`). Never read a version off its log.
- DRA's ValidatingAdmissionPolicy from upstream v1.0.1 names only `v1beta1`, so
  it blocks nothing on a cluster that serves `resource.k8s.io/v1`
  (rex-rancher k107).
- On an APU the DRA memory is the carve-out (128Gi on synapse, while the OS
  sees 62 GiB). A claim with a memory request is untested.
- Non-root GPU pods need the host GIDs: `render` and `video` as
  `supplementalGroups` under the device plugin, GID 0 under DRA (CDI devices
  are `root:root 0660`). It is deferred, with no switch in OCP yet.
- Deferred: AMD GPU Operator mode, Instinct partitioning (CPX/NPS, DCM), the
  device plugin's `product` naming, and DRA's `extendedResourceName`.
