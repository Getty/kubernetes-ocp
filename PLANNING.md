# OCP - Omni Control Plane

Single-config Kubernetes cluster management for RKE2 and K3s on Hetzner Cloud,
on bare-metal servers reached over SSH, or on a single host (Local).

## Was OCP heute ist

- **CLI**: `ocp` mit Subcommands `init`, `apply`, `status`, `destroy`, `update`,
  `kubeconfig`, `ssh`, `version`, `node`, `provider`.
- **Distributionen**: RKE2 und K3s gleichberechtigt (ADR 0012).
- **Provider**: Hetzner Cloud, SSH (existing hosts), Local (single-node).
- **CNI**: Cilium inklusive Gateway API und cert-manager.
- **GPU**: NVIDIA operator + driver + toolkit + DCGM + device-plugin, optional.
- **Robocop**: in-Cluster-Controller-Pfad für Worker-Reconciliation
  (heute Platzhalter, ADR 0021 in Arbeit).
- **Spec/Status-Trennung**: spec in Git (`ocp.yaml`), status aus dem Cluster.
- **Toolchain**: Docker-first, multi-arch (`linux/amd64,linux/arm64`), `cpanfile`
  + `cpanfile.snapshot` gepinnt, Versions-Manifest in `OCP::Versions`.

Architektur, Modul-Landkarte und Invarianten: Skill `ocp-core`. CLI und
Config-Schema: Skill `ocp-usage`. Architektur-Entscheidungen mit Begründung:
`docs/adr/`.

## Was OCP bewusst nicht ist

- Kein Multi-Cloud-Orchestrator.
- Kein Addon-System. Cilium, cert-manager und GPU sind eingebaute Komponenten,
  keine Helm-Stacks on top (ADR 0011).
- Kein App-Deployment-Layer (kein ArgoCD-Setup, kein Helm-Apply für User-Apps).
- Kein Cloud-agnostisches Network-Overlay. Tailscale/Wireguard nicht drin.
- Keine Web-UI.

## TODOs (kein Versprechen, lose Ideen)

Niedrige Prio, keine Roadmap, kein Lieferdatum. Wenn etwas davon kommt, kommt
es als karr-Ticket auf den Backlog, nicht als Phasenplan.

- **Vast.ai als Provider**: Denkbar als Quelle für GPU-Worker, aber vermutlich
  nicht über k8s-Control-Plane — vast.ai orchestriert selbst schon Container.
  Falls überhaupt dann als Worker-only, angebunden über den SSH-Provider-Adapter
  gegen existierende vast.ai-Instanzen. Offen, niedrige Prio, vermutlich nie.
- **Weitere Cloud-Provider**: AWS, GCP, Azure, Hetzner Robot (Dedicated).
  Aktuell nicht geplant — Fokus liegt auf Hetzner und SSH.
- **Auto-Scaling von Node-Pools**: Nicht geplant.
- **Helm-Stacks für User-Addons**: Bewusst nicht (ADR 0011). Falls ein Addon
  Helm braucht, wird es handgerollt und gepinnt.

## Wo ich nachschaue

- `README.md` — Quick Start, Installationsweg.
- `docs/adr/` — Architektur-Entscheidungen mit Begründung, indexiert in
  `docs/adr/README.md`.
- Skill `ocp-core` — Modul-Landkarte, Invarianten, Reconciliation-Loop.
- Skill `ocp-usage` — CLI-Kommandos, Provider-Modi, Datei-Layout.
