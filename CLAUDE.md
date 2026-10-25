# OCP - Omni Control Plane

Perl-based CLI to manage Kubernetes clusters (RKE2/K3s) on Hetzner, packaged as a CPAN
distribution and shipped as a Docker image. Two components: `ocp` (CLI; bootstraps
control-plane servers) and `robocop` (in-cluster controller; manages worker nodes via
OCPNode/OCPNodeProvider CRDs).

Architektur, CRDs, Modul-Map, Spec/Status-Semantik: **Skill `ocp-core`**.
CLI-Befehle, `ocp.yaml`-Schema, Provider-Modi: **Skill `ocp-usage`**.
Shared house rules (Delegations-Lock, Publish-Gate, karr): skilletor-Bundle `getty-house@getty`;
was nur hier gilt, Lanes, Hazards: `.claude/rules/ocp-rules.md` (auto-loaded).

## Delegation

Verhaltensrelevanten Code an den passenden Agenten delegieren. Der Lock ist Shared House
Rule (Bundle `getty-house@getty`), die Lane-Grenzen stehen in `.claude/rules/ocp-rules.md`. Agents bekommen ihre Skills via `briefing.skills`
force-geladen (siehe `.claude/agents/`); der Main-Agent delegiert, statt sie
selbst zu laden.

| Task | Agent |
|---|---|
| Eingabe-Validierung, `OCP::Choices`, `option(...)` | `ocp-choices-worker` |
| Secrets/Keys, `OCP::Secrets`, `OCP::Keys`, age/SOPS/PIN | `ocp-secrets-worker` |
| Zustandsmaschine, `OCP::Config`, `OCP::Drift`, `OCP::Node` | `ocp-state-worker` |
| Provider, Hetzner/Local/SSH-Provisioning, `OCP::Rex` | `ocp-provider-worker` |
| `ocp init/apply/update/deploy-*`, Dispatcher `bin/ocp` | `ocp-apply-worker` |
| `ocp destroy` | `ocp-destroy-worker` |
| `ocp status` / `ocp version` | `ocp-status-worker` |
| robocop-Controller, IO::Async, Reconciliation | `ocp-robocop-worker` |
| `share/`, Rexfile, Cilium/RKE2/Registry/GPU | `ocp-infra-worker` |
| Übergreifend oder nicht zuordenbar | `ocp-worker` (Default) |
| Tests in `t/` | `ocp-test-writer` |
| POD und Prosa-Dokumente | `ocp-doc-writer` |
| ADR in `docs/adr/` | `ocp-adr-auditor` |
| Commits, `Changes`, Karte → done, Release-Audit | `ocp-release-manager` |

## Wissens-Landkarte (Skills in `.claude/skills/`)

| Skill | Inhalt |
|---|---|
| `ocp-core` / `ocp-usage` | Architektur & CLI |
| `ocp-k8s` / `ocp-rke2` / `ocp-cilium` / `ocp-registry` / `ocp-gpu` | OCP-Konfiguration dieser Stack-Teile |
| `kubernetes-rke2` / `kubernetes-cilium-concepts` / `kubernetes-gpu` / `docker-registry` | die generischen Referenzen darunter |
| `getty-perl-core` / `getty-perl-moo` | Getty's Perl-Hausregeln |
| `perl-kubernetes-rest` / `perl-io-k8s-kubernetes-classes` | Kubernetes::REST / IO::K8s |
| `perl-io-async-future` | Async-Perl für robocop |
| `getty-perl-release-author-getty` / `perl-release-dist-ini` | Release-Konventionen |
| `karr` | Git-natives Ticket-Board |

Nur die `ocp-*`-Skills sind repo-eigen (hier direkt editieren). Alle anderen Skills
kommen über **skilletor** aus ihren Sources (`.claude/skilletor.json`) — sie sind
Build-Artefakte mit eigenem `.gitignore`, **nie mit Edit/Write bearbeiten**: in der
Source ändern und `skilletor sync` (Details: Skill `skilletor`).

## Build & Test

```bash
make test          # bindende Suite (im Docker-Image, gegen cpanfile.snapshot)
make test-v        # dasselbe, verbose
make test-host     # schnell, nicht bindend (Host-CPAN)
make build         # Docker-Image bauen
make snapshot      # cpanfile.snapshot regenerieren (in Docker)
make docker-test   # Image startet — nicht die Suite
make smoke         # ACHTUNG: echter Host, echter Cluster
```

Einzelne Datei: `make test TESTS=t/33-registry-manifests.t`. Toolchain ist
Docker-first — Details + Hazards in `.claude/rules/ocp-rules.md`.

## Workflow

```bash
ocp init --hetzner   # Projekt initialisieren (Token, Keys, Config)
vim ocp.yaml         # Spec bearbeiten
ocp apply            # deployen / reconcilen
ocp status           # Status + Drift
ocp kubeconfig -e    # Kubeconfig mergen
ocp destroy          # echte Server löschen
```

## Verwandte Projekte (Siblings, eigene Repos + Boards)

Nachbar-Repos (`../`): `p5-www-hetzner`, `p5-crypt-age`, `p5-file-sops`,
`p5-net-async-kubernetes`, `io-k8s-p5`, `kubernetes-rest`. Cross-Repo-Arbeit läuft
über karr-Tickets auf dem Board des jeweiligen Repos, nie als Direkt-Edit.
