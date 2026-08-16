# OCP - Omni Control Plane

Perl-based CLI to manage Kubernetes clusters (RKE2/K3s) on Hetzner, packaged as a CPAN
distribution and shipped as a Docker image. Two components: `ocp` (CLI; bootstraps
control-plane servers) and `robocop` (in-cluster controller; manages worker nodes via
OCPNode/OCPNodeProvider CRDs).

Architektur, CRDs, Modul-Map, Spec/Status-Semantik: **Skill `ocp-core`**.
CLI-Befehle, `ocp.yaml`-Schema, Provider-Modi: **Skill `ocp-usage`**.
House rules, Delegations-Lock, Hazards: `.claude/rules/ocp-rules.md` (auto-loaded).

## Delegation

Verhaltensrelevanten Code an den passenden Agenten delegieren. Volle Tabelle + Lock:
`.claude/rules/ocp-rules.md`.

| Task | Agent |
|---|---|
| Input validation, `OCP::Choices`, `option(...)`, `_validate_*` | `ocp-choices-worker` |
| Secrets/Keys: `OCP::Secrets`, `OCP::Keys`, `OCP::ClusterKey`, age/SOPS/PIN | `ocp-secrets-worker` |
| State machine: `OCP::Config`, `OCP::Drift`, `OCP::Node`, `OCP::Versions` | `ocp-state-worker` |
| Provider base + roles, Hetzner/Local/SSH provisioning, `OCP::Rex` | `ocp-provider-worker` |
| `ocp init/apply/status/update/destroy/deploy-image`, `OCP::Cmd::Apply/*` | `ocp-lifecycle-worker` |
| robocop controller, IO::Async, reconciliation loop | `ocp-robocop-worker` |
| `share/`, Rexfile, Cilium/RKE2/registry/GPU stack | `ocp-infra-worker` |
| Cross-cutting oder nicht zuzuordnen | `ocp-worker` (Default) |
| Tests schreiben/erweitern | `ocp-test-writer` |
| POD und Prosa-Doku | `ocp-doc-writer` |
| Pre-Release-Audit | `ocp-release-checker` |
| ADR-Audit/Backfill in `docs/adr/` | `ocp-adr-auditor` |

Agenten bekommen ihre Skills via `briefing.skills` force-geladen (siehe
`.claude/agents/`); der Main-Agent delegiert, statt sie selbst zu laden.

## Wissens-Landkarte (Skills in `.claude/skills/`)

| Skill | Inhalt |
|---|---|
| `ocp-core` / `ocp-usage` | Architektur & CLI |
| `k8s` / `rke2` / `cilium` / `registry` / `gpu` | K8s- & Stack-Patterns |
| `perl-core` / `perl-moo` | Getty's Perl-Hausregeln |
| `perl-kubernetes-rest` / `perl-kubernetes-classes` | Kubernetes::REST / IO::K8s |
| `perl-io-async-future` | Async-Perl für robocop |
| `perl-release-author-getty` / `perl-release-dist-ini` | Release-Konventionen |
| `karr` | Git-natives Ticket-Board |

Shared Skills sind Hardlinks (`manage-skills`) — **nie mit Edit/Write bearbeiten**,
immer `cat > datei` (Details: globale CLAUDE.md / Skill `manage-skills`).

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

`~/dev/perl/`: `p5-www-hetzner`, `p5-crypt-age`, `p5-file-sops`,
`p5-net-async-kubernetes`, `io-k8s-p5`, `kubernetes-rest`. Cross-Repo-Arbeit läuft
über karr-Tickets auf dem Board des jeweiligen Repos, nie als Direkt-Edit.
