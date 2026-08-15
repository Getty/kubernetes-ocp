# OCP - Omni Control Plane

OCP ist ein Perl-basiertes CLI-Tool zur Verwaltung von Kubernetes-Clustern (RKE2/K3s),
entwickelt als CPAN-Distribution mit Docker als primärer Installationsmethode. Zwei
Komponenten: `ocp` (CLI, extern, bootstrapped Control Planes) und `robocop` (Controller
im Cluster, managed Worker-Nodes via OCPNode/OCPNodeProvider CRDs).

Architektur, Stack-Entscheidungen (Cilium, kein Helm), Spec/Status-Trennung,
Modul-Landkarte und Invarianten: **Skill `ocp-core`**. Regeln und Delegations-Lock:
`.claude/rules/ocp-rules.md` (auto-geladen).

## Delegation

Verhaltensrelevanten Code an den passenden Agenten delegieren statt selbst anfassen —
Prinzip und Lanes stehen in `.claude/rules/ocp-rules.md`.

| Task | Agent |
|---|---|
| CLI, Module, Provider, Drift, K8s-Zugriff | `ocp-worker` (Default) |
| robocop Controller, IO::Async, Reconciliation-Loop | `ocp-robocop-worker` |
| manifests/, share/, Rexfile, Cilium/RKE2/Registry/GPU | `ocp-infra-worker` |
| Tests schreiben/erweitern | `ocp-test-writer` |
| POD und Prosa-Doku | `ocp-doc-writer` |
| Pre-Release-Audit | `ocp-release-checker` |
| ADR-Audit/Backfill in docs/adr/ | `ocp-adr-auditor` |

Die Agenten bekommen ihre Skills via `briefing.skills` force-geladen (siehe
`.claude/agents/`); der Main-Agent delegiert, statt sie selbst zu laden.

## Wissens-Landkarte (Skills in `.claude/skills/`)

| Skill | Inhalt |
|---|---|
| `ocp-core` | Architektur, Invarianten, Modul-Map, CRDs, Spec/Status |
| `ocp-usage` | CLI-Kommandos, Provider-Modi, PIN1/PIN2, Datei-Layout |
| `k8s` | Server-Side Apply, Hash-Reconciliation, typed API Patterns |
| `rke2` / `cilium` / `registry` / `gpu` | Komponenten-Konfiguration für OCP |
| `perl-core` / `perl-moo` | Getty's Perl-Hausregeln, Moo-Patterns |
| `perl-kubernetes-rest` / `perl-kubernetes-classes` | Kubernetes::REST / IO::K8s |
| `perl-io-async-future` | Async-Perl für robocop |
| `perl-release-author-getty` / `perl-release-dist-ini` | Release-Konventionen |
| `karr` | Git-natives Ticket-Board (Koordination) |

Shared Skills sind Hardlinks (`manage-skills`) — **nie mit Edit/Write bearbeiten**,
immer `cat > datei` (Details: globale CLAUDE.md / Skill `manage-skills`).

## Build & Test

```bash
make test       # prove -l t/ — flache, mock-basierte Suite, netzwerkfrei
make build      # Docker Image bauen
make snapshot   # cpanfile.snapshot regenerieren — läuft IN Docker, nie auf dem Host
make smoke      # ACHTUNG: bootstrapped einen ECHTEN Host und wischt dessen Cluster
```

Toolchain ist Docker-first: kein `carton install`/`cpm` auf dem Host. `make build` baut
immer nur für die Architektur der Maschine, auf der es läuft — ein arm64-Image entsteht
auf einer arm64-Maschine. `kubectl` existiert nur zum Debuggen im Container — kein
Code-Pfad darf es aufrufen (alles über Kubernetes::REST / IO::K8s).

## Workflow

```bash
ocp init --hetzner   # Projekt initialisieren (Token, Keys, Config)
vim ocp.yaml         # Spec bearbeiten
ocp apply            # Cluster deployen / reconcilen
ocp status           # Status + Drift
ocp kubeconfig -e    # Kubeconfig mergen
ocp destroy          # Cluster löschen (echte Server!)
```

## Verwandte Projekte (Siblings, eigene Repos + Boards)

`~/dev/perl/`: `p5-www-hetzner` (WWW::Hetzner), `p5-crypt-age` (Crypt::Age),
`p5-file-sops` (File::SOPS), `p5-net-async-kubernetes` (Net::Async::Kubernetes),
`io-k8s-p5` (IO::K8s), `kubernetes-rest` (Kubernetes::REST). Cross-Repo-Arbeit läuft
über karr-Tickets auf dem Board des jeweiligen Repos, nie als Direkt-Edit.

Das `cpanfile` ist die Wahrheitsquelle für Dependencies; Getty-eigene Distributionen
sind gepinnt. Bekannte Schuld: `Net::Async::Kubernetes` ist deklariert, aber ungenutzt
(robocop pollt statt zu watchen, `ocp inject-key` deaktiviert) — einlösen oder werfen.
