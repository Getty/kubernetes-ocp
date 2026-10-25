# OCP - Omni Control Plane

Single-config Kubernetes cluster management for RKE2 and K3s on Hetzner Cloud,
on bare-metal servers reached over SSH, or on a single host (Local).

## What OCP is today

- **CLI**: `ocp` with subcommands `init`, `apply`, `status`, `destroy`, `update`,
  `kubeconfig`, `ssh`, `version`, `node`, `provider`.
- **Distributions**: RKE2 and K3s on equal footing (ADR 0012).
- **Providers**: Hetzner Cloud, SSH (existing hosts), Local (single-node).
- **CNI**: Cilium including Gateway API and cert-manager.
- **GPU**: NVIDIA operator + driver + toolkit + DCGM + device-plugin, optional.
- **Robocop**: in-cluster controller path for worker reconciliation
  (a placeholder today, ADR 0021 in progress).
- **Spec/status separation**: spec in Git (`ocp.yaml`), status from the cluster.
- **Toolchain**: Docker-first, built for the architecture of the build machine,
  `cpanfile` + `cpanfile.snapshot` pinned, version manifest in `OCP::Versions`.

Architecture, module map and invariants: skill `ocp-core`. CLI and
config schema: skill `ocp-usage`. Architecture decisions with rationale:
`docs/adr/`.

## What OCP deliberately is not

- Not a multi-cloud orchestrator.
- No addon system. Cilium, cert-manager and GPU are built-in components,
  not Helm stacks on top (ADR 0011).
- No app deployment layer (no ArgoCD setup, no Helm apply for user apps).
- No cloud-agnostic network overlay. Tailscale/Wireguard are not included.
- No web UI.

## TODOs (no promise, loose ideas)

Low priority, no roadmap, no delivery date. If any of this comes, it comes
as a karr ticket on the backlog, not as a phased plan.

- **Vast.ai as a provider**: Conceivable as a source of GPU workers, but probably
  not via a k8s control plane — vast.ai already orchestrates containers itself.
  If at all, then worker-only, attached through the SSH provider adapter
  against existing vast.ai instances. Open, low priority, probably never.
- **More cloud providers**: AWS, GCP, Azure, Hetzner Robot (dedicated).
  Currently not planned — the focus is on Hetzner and SSH.
- **Auto-scaling of node pools**: Not planned.
- **Helm stacks for user addons**: Deliberately not (ADR 0011). If an addon
  needs Helm, it gets hand-rolled and pinned.

## Where I look things up

- `README.md` — quick start, installation path.
- `docs/adr/` — architecture decisions with rationale, indexed in
  `docs/adr/README.md`.
- Skill `ocp-core` — module map, invariants, reconciliation loop.
- Skill `ocp-usage` — CLI commands, provider modes, file layout.
