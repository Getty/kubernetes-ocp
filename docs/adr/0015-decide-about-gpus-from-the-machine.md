# 0015. Decide about GPUs from the machine, not from a model of it

Date: 2026-08-12
Status: accepted

## Context

OCP used to carry its own model of NVIDIA hardware: a whitelist of
compute-capable GPUs, matched against the *name* `lspci` printed, used to decide
whether to install a driver. It also carried a hardcoded driver package
(`nvidia-driver-535`) and `linux-headers-generic`.

Every part of that broke on the first unusual machine — an NVIDIA DGX Spark
(GB10, Grace Blackwell, aarch64, vendor kernel 6.17.0-1029-nvidia):

- The whitelist rejected the GPU with `Unknown NVIDIA GPU: Device`. Not because
  GB10 was missing from the list, but because the *input* was wrong: `lspci`
  prints the name it finds in the host's `pci.ids` database, and that database
  is always older than the newest card. It printed `Device [10de:2e12]`. Adding
  GB10 to the list would not have helped. Meanwhile NFD — already deployed by
  OCP, into the same cluster — labelled the node correctly from
  `pci-0300_10de`. Two detectors, two answers (karr #17).
- `nvidia-driver-535` on Ubuntu 24.04 is a transitional package that pulls 580,
  so the pin never pinned anything, on any architecture. And no single package
  name is correct across architecture *and* GPU generation: Grace Hopper and
  Blackwell run only with the open kernel modules, Maxwell through Volta only
  with the proprietary ones, and open-vs-proprietary is part of the package
  name (karr #12).
- `linux-headers-generic` tracks the generic kernel flavour, which on a vendor
  kernel is the wrong kernel.
- The machine already had a working vendor driver and container toolkit.
  Installing over them would have broken it. The only thing that saved it was
  the whitelist failing first (karr #24).

## Decision

Stop modelling the hardware. Ask the machine, and split the questions by the
moment at which each can actually be answered.

**Before the cluster exists** — Rex, during bootstrap — there is exactly one
question: *does this host need an NVIDIA driver?*

- *Is NVIDIA hardware present?* Read `/sys/bus/pci/devices/*/{vendor,device,class}`
  and keep class `0300`/`0302` with vendor `10de`. No `pciutils`, no `pci.ids`,
  no names — the same pair NFD labels the node with.
- *Is a driver already there?* `nvidia-smi -L` enumerates GPUs **and**
  `libcuda.so` is in the linker cache. If so, install nothing.
- *Is the container toolkit already there?* `nvidia-container-runtime` and
  `nvidia-ctk` are runnable. If so, touch neither the package nor the apt
  source — the source would otherwise decide where the host pulls from in
  future.
- *Which driver package?* Not OCP's decision. `ubuntu-drivers install` resolves
  branch, flavour and architecture from the card's PCI modalias — the same
  evidence NFD uses — and structurally cannot pick a package that does not claim
  the card. Headers are `linux-headers-$(uname -r)`, as NVIDIA documents.
  **If it fails, the task dies with an explanation.** It does not fall back to a
  guessed package name.

Compute capability is not asked before the cluster at all.

**After the cluster exists** the authoritative answer to "is this GPU usable"
is `nvidia.com/gpu` in the node's capacity, published by the device plugin;
`OCP::Kubernetes::node_gpu_count` reads it. The NFD label
`feature.node.kubernetes.io/pci-0300_10de` is the secondary signal.

The short blacklist of virtual display adapters (virtio, QEMU, VMware,
VirtualBox) stays: a list of "definitely not" stays true as hardware moves on,
which a list of "maybe" does not. NVIDIA hardware wins over it, deliberately —
a VM with a passed-through card has both, and there the card decides.

### Alternatives rejected

- **Extend the whitelist with GB10** — the input is the name, and the name was
  not in the host's database. The next card breaks it again.
- **Keep skipping weak display GPUs (MX 150, GT 710)** — the question does not
  arise: a driver on a weak card is useless, not harmful, and whether a card is
  worth scheduling on is the device plugin's answer, not a name-guessing one.
- **Pick an arm64/SBSA package name from NVIDIA's own repository** — would need
  verification on a bare arm64 host, and a wrong guess breaks machines.
- **Fall back to a known package when `ubuntu-drivers` fails** — that fallback
  is the guess this ADR exists to remove.

## Consequences

- The sysfs command was verified on the real GB10:
  `/sys/bus/pci/devices/000f:01:00.0|0x10de|0x2e12|0x030000` — the exact card
  the whitelist rejected.
- A bare arm64 Ubuntu host with an NVIDIA GPU and no driver has never been
  tested, and that is stated rather than assumed: whether `ubuntu-drivers`
  works on SBSA, and whether it picks the `-open` branch on Blackwell, is
  unverified (karr #12). The protection is that it dies rather than guesses.
- Hosts that ship a working stack (DGX OS and friends) are left alone by
  default, and NVIDIA's guidance for them is expressible in `ocp.yaml`:
  `gpu.enabled`, `gpu.driver: host|operator`, `gpu.toolkit`. `gpu.driver`
  croaks on an unknown value rather than falling back to `host` — a typo would
  otherwise leave an operator-configured cluster with no driver at all.
- Auto-detecting host state *into* the ClusterPolicy was deliberately not built:
  `OCP::Cmd::Apply` talks to the API, not to the host, and there is no channel
  from Rex back into it (karr #24).
- Better detection is still only a better prediction. The proof that the GPU
  stack works is `nvidia.com/gpu` in the capacity — which is why ADR 0017
  matters more than this one.
