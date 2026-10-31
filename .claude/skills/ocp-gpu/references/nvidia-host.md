# NVIDIA — the host side (`share/Rexfile`)

What runs on a node before it joins: detection, driver, container toolkit, CDI.
The cluster side (ClusterPolicy, NFD, pins, drift) is in `nvidia-cluster.md`.

## Detection — `detect_gpu`

Question: does this host need a driver? Not: is the card worth scheduling on.
The device plugin answers that later.

- `Rex::GPU::Detect::Sysfs->detect` (rex-gpu k73, experimental; since k196) reads
  **sysfs**, not `lspci`: vendor, class, device and subsystem IDs of every device
  under `/sys/bus/pci/devices`, in one read-only command, once per host.
  `detect_gpu` hands the result to `install_nvidia` and `install_amd` as
  `detected`. A hand-run of either task detects for itself.
- NVIDIA is vendor `10de`, class `0300` (VGA) or `0302` (3D controller). The
  result carries full hashes: `compute`, `device_id`, `vgpu`/`vgpu_type`, and
  NVSwitches under `nvswitch`.
- The detection **dies** for a host whose sysfs it cannot read. It never calls
  such a host GPU-less. Under `gpu.driver: operator` that death is only a
  `[WARN]`: there the detection runs for the AMD labels only.
- There is **no model whitelist**, and it must not come back. `lspci` prints
  names from the host's `pci.ids`, which is always older than the newest card.
  A DGX Spark prints `Device [10de:2e12]` for its GB10.
- The library skips virtual display adapters per device (`1af4` virtio, `1b36`
  QEMU, `15ad` VMware, `80ee` VirtualBox), so they never hide a passed-through
  card.
- `_driver_gpus($detected)` is OCP's decision (k194). It keeps every NVIDIA GPU
  except `compute => 0`: Kepler or older, whose last driver is the EOL 470
  branch that Rex::GPU refuses on every OS. It **does** hand on
  `compute => undef`, a card newer than the generation table that sysfs has no
  name for. `install_driver` takes it as an unknown GPU without a constraint.
- `_gpu_actions($detected)` returns one answer per vendor, NVIDIA first:
  - `nvidia`, or `unsupported` when only Kepler-or-older cards are present (no
    driver, no toolkit, no GPU node);
  - then `amd` or `amd-unsupported` the same way;
  - `none` when the host has neither.

  A host with both vendors' cards gets both drivers, NVIDIA's first.
- Under `gpu.driver: operator` the `nvidia`/`unsupported` actions are skipped.
  NVIDIA belongs to the GPU Operator.
- `detect_gpu` is called as a function from the install tasks
  (`_maybe_detect_gpu`), never through `do_task`. `do_task` forks, and the
  return value (the AMD node labels) would never come back (Rex 1.16.1).
- `gpu.enabled: false` (task param `gpu => 0`) skips detection entirely.

## Driver — `install_nvidia`

This works the same on every OS, Ubuntu included since k191 (rex-gpu k69). It
makes one call:

```perl
Rex::GPU::NVIDIA::install_driver(
    gpus => \@gpus,
    (@$nvswitches ? (nvswitches => $nvswitches) : ()),
    ($os eq 'Ubuntu' ? (setup => 'Rex::GPU::NVIDIA::Setup::UbuntuDrivers') : ()),
);
```

- **Never with an empty `gpus` list.** That installs a GPU-agnostic driver; it
  does not skip. With nothing left after `_driver_gpus`, the task returns before
  the driver and before the toolkit.
- The GPUs go over as detected, vGPU keys included. A vGPU guest without its
  licensed driver is refused before anything is installed. NVSwitches make the
  library install Fabric Manager, or die first where the source has none.
- A working driver is left alone. Working means nvidia-smi enumerates GPUs
  **and** `libcuda.so.1` is in the linker cache. Package state is the wrong
  question, because vendor appliances install outside the distro's package
  namespace.
- Only the running kernel's headers are installed, never
  `linux-headers-generic`. On a vendor kernel (a DGX Spark runs
  `6.17.0-1029-nvidia`) the generic headers belong to a different kernel, and
  DKMS would build against the wrong tree.
- **Everywhere but Ubuntu** no `setup` is passed. Rex::GPU picks the branch and
  module by GPU generation from the device IDs. On Debian that is non-free
  `nvidia-driver nvidia-smi libcuda1`, with Blackwell from NVIDIA's CUDA repo.
  It dies before touching the host for Kepler or for an incompatible GPU mix.
- **Ubuntu** passes `setup => 'Rex::GPU::NVIDIA::Setup::UbuntuDrivers'`. That
  departs on purpose from ADR 0015's original "not OCP's decision" (see its
  2026-09-26 amendment).
  - Only the **branch** comes from `ubuntu-drivers list --gpgpu`, which is
    read-only.
  - The **kernel-module flavour** comes from Rex::GPU's device-ID table. It is
    open for Blackwell (GB10 among them) and Grace Hopper (GH200). It is
    proprietary where the table names nothing (the rest of Turing through
    Hopper).
  - Maxwell, Pascal and Volta get the `580-server` branch directly, without
    asking `ubuntu-drivers`.
  - `apt-get` installs the package and `dpkg` verifies it. **`ubuntu-drivers
    install` is never run.**
  - The task dies before any driver package goes in when `ubuntu-drivers` is
    missing, fails, or names nothing for the card. No package name is guessed.
  - A package that cannot drive the card is refused, for example proprietary
    on a Blackwell.
  - R535 is end of life. On 24.04 `nvidia-driver-535` is a transitional
    package that pulls 580, so the old pin pinned nothing. amd64 and arm64
    differ in package names (arm64 comes from ports); `ubuntu-drivers` resolves
    that.

## Toolkit and CDI

- `Rex::GPU::NVIDIA::install_container_toolkit(binaries_suffice => 1)`
  (rex-gpu k74) always runs. When `nvidia-container-runtime` and `nvidia-ctk`
  are on the PATH and `nvidia-ctk --version` runs, neither the apt source nor
  the package is touched. A DGX has both from its vendor image, and OCP does
  not decide where such a host gets its packages afterwards. Anything less, and
  the library installs from NVIDIA's `libnvidia-container` repo.
- `gpu_toolkit => 0` (ocp.yaml `gpu.toolkit: false`, k223):
  `Rex::GPU::NVIDIA::generate_cdi_specs()` runs before `verify_nvidia`. No
  operator toolkit writes `/run/cdi` then. The library writes only the devices
  that do not resolve (rex-gpu k76, Rex::GPU >= 0.004). Live on a GB10, an
  empty `/run/cdi` after a reboot killed the validator, and the node never got
  `nvidia.com/gpu`.
- Toolkit true means no CDI from OCP. A static `/etc/cdi/nvidia.yaml` next to the
  operator's `/run/cdi` would define the kind twice.
- `verify_nvidia()` warns and never dies, because a reboot may still be due.

## containerd — OCP writes nothing

- k3s and RKE2 share the agent code. **At service start** it scans `PATH` for
  `nvidia-container-runtime`, with `/usr/local/nvidia/toolkit` and
  `/opt/kwasm/bin` prepended (where the operator's toolkit DaemonSet installs
  it). It writes what it finds into its own containerd config. k3s also ships
  the `nvidia` RuntimeClass. This was verified on a DGX Spark, with OCP having
  done nothing.
- The scan runs only at service start. Install the runtime before the service,
  or restart the service.
- Neither distribution makes nvidia the **default** runtime. Workloads use
  `runtimeClassName: nvidia`, or the cluster opts in with `--default-runtime`.
- **Never write a `config.toml.tmpl` / `config-v3.toml.tmpl` without
  `{{ template "base" . }}`.** The template is rendered *instead of* the
  generated config and silently drops the mirrors, the sandbox image and CNI.
  OCP once shipped exactly that. The cleanup of that leftover is Rex::Rancher's
  (skill `ocp-rke2`).
- RKE2's unit sets no `PATH`. Rex::Rancher writes one into
  `/etc/default/rke2-{server,agent}` when the runtime is on the host
  (`nvidia_runtime_path => 1`, which OCP always passes). k3s needs nothing.

## `gpu.toolkit` to the hosts (k223, the k31/k217 channel)

- `ensure_provider_cr` writes `spec.gpu.toolkit` (a JSON boolean) onto the
  OCPNodeProvider CR.
- `OCP::Provider->gpu_flags_from_cr` returns `gpu_toolkit` as 0/1. It is absent
  when the CR predates the field.
- robocop, the apply CLI and `ocp node add` hand it to `OCP::Node`.
- The bootstrap passes `$config->gpu_toolkit` to `OCP::Rex::install_server`.
- Absent everywhere means true.
