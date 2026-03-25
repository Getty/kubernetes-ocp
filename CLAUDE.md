# OCP - Omni Control Plane

## Projektstatus

OCP ist ein Perl-basiertes CLI-Tool zur Verwaltung von Kubernetes-Clustern (RKE2/K3s). Das Projekt wird als CPAN-Distribution entwickelt mit Docker als primärer Installationsmethode.

## Stack Entscheidungen

```
RKE2/K3s    → Kubernetes-Distribution (beides unterstützt)
Cilium      → Macht fast alles (CNI, Service Mesh, Ingress, Observability)

Kein: Helm, Istio, Canal
```

### Warum Cilium

```
Übernimmt:
├── CNI (Pod Networking)
├── Network Policies (L3/L4/L7)
├── kube-proxy Replacement (eBPF)
├── Encryption (WireGuard)
├── Ingress (Gateway API)
├── Service Mesh Features
├── Observability (Hubble)
└── DNS Policies

Kein Istio nötig → Overkill, frisst RAM
```

### Package Management

```
Kein Helm als Default.

Stattdessen:
├── Kustomize (in kubectl eingebaut)
├── Plain Manifests (von GitHub Releases)
└── helm template zum Rendern (Build-Zeit, nicht Runtime)

Helm nicht verboten - nur nicht der Default-Weg.
```

## Architektur

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Control Plane Node                                             │
│  ├── RKE2/K3s Control Plane (etcd, apiserver, etc.)            │
│  ├── robocop (Kubernetes Controller)                           │
│  ├── Cilium Operator                                            │
│  ├── cert-manager                                               │
│  └── Registry (pull-through cache + local)                      │
│                                                                 │
│  Worker Nodes                                                   │
│  ├── RKE2/K3s Agent                                             │
│  ├── Cilium Agent                                               │
│  └── Workloads                                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Architektur-Vision (v2)

**Klare Trennung der Verantwortlichkeiten:**

```
┌─────────────────────────────────────────────────────────────────┐
│  OCP CLI (ocp)                                                  │
│  ─────────────────                                              │
│  • Bootstrap Control Plane(s) - EINMALIG                        │
│  • Läuft EXTERN (Laptop, CI/CD)                                 │
│  • Installiert RKE2/K3s, Cilium, Basis-Stack                   │
│  • Deployt robocop in den Cluster                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Kubernetes Cluster                                             │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  robocop (Kubernetes Controller)                          │ │
│  │  ─────────────────────────────────────                    │ │
│  │  • Läuft IM Cluster als Deployment                        │ │
│  │  • Managed ALLE Worker-Nodes via CRDs                     │ │
│  │  • Reconciliation Loop: Watch → Diff → Act → Status       │ │
│  │  • Basiert auf: Net::Async::Kubernetes (IO::Async)        │ │
│  │  • Kann auch Deployments orchestrieren (kein ArgoCD)      │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

**Naming-Schema (RoboCop Theme):**

| Komponente | Name | Beschreibung |
|------------|------|--------------|
| CLI Tool | `ocp` | Omni Control Plane (extern) |
| Controller | `robocop` | Kubernetes Operator (im Cluster) |
| Control Planes | `police1`, `police2`, ... | "Serve the public trust" |

## Bootstrap Flow

```bash
# 1. RKE2 Server (Control Plane)
curl -sfL https://get.rke2.io | sh -

cat > /etc/rancher/rke2/config.yaml << 'EOF'
cni: none
disable-kube-proxy: true
disable:
  - rke2-ingress-nginx
profile: cis-1.23
EOF

systemctl enable --now rke2-server

# 2. Manifests via Kustomize
kubectl apply -k manifests/robocop/

# 3. Worker joinen
curl -sfL https://get.rke2.io | INSTALL_RKE2_TYPE="agent" sh -
# config.yaml mit server + token
systemctl enable --now rke2-agent
```

## OCP Verantwortlichkeiten

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  OCP CLI + robocop Controller:                                  │
│  ├── kubectl apply -k ausführen                                │
│  ├── Reihenfolge orchestrieren (Cilium vor Workloads)         │
│  ├── Health Checks / Readiness warten                          │
│  ├── Node Management (join/leave)                               │
│  ├── Config Management                                          │
│  └── Abstraction über K8s Komplexität                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Projekt-Struktur

```
kubernetes-ocp/
  ├── bin/ocp                    # CLI Tool (Bootstrap)
  ├── bin/robocop                # Controller Entry Point
  ├── lib/OCP/                   # CLI Module
  ├── lib/OCP/K3s.pm             # K3s Installation und Management
  ├── lib/OCP/Rex.pm             # Rex Task Executor (RKE2/K3s via Rexfile)
  ├── lib/OCP/SSH.pm             # SSH Operations
  ├── lib/OCP/Local.pm           # Lokale Installation (ohne SSH)
  ├── lib/OCP/Provider.pm        # Infrastructure Provider Factory
  ├── lib/OCP/Provider/          # Provider Implementations
  │   ├── Hetzner.pm             # Hetzner Cloud (idempotent, Labels)
  │   ├── SSH.pm                 # Bestehende Server
  │   └── Local.pm               # Localhost
  ├── lib/OCP/Kubernetes.pm      # Typed K8s Helpers (Nodes, GPU)
  ├── lib/OCP/Robocop/           # Controller Module (im Cluster)
  ├── lib/OCP/UI/                # Terminal UI (Tickit-basiert)
  ├── manifests/
  │   ├── robocop/               # CRDs, RBAC, Deployment
  │   ├── dev-registry.yaml
  │   └── Rexfile                # Rex Tasks für Server-Provisioning
  └── share/                     # Manifest Templates (cert-manager, etc.)
```

## Datei-Struktur (Projekt)

```
ocp.yaml              # Cluster-Spezifikation (git-versioniert)
secrets.yaml          # SOPS/age verschlüsselte Secrets (git-versioniert)
keys.yaml             # admin-ssh + robo-ssh Keys (SOPS encrypted, git-versioniert)
age.key.enc           # PIN1-protected age key (git-versioniert)
kubeconfig.yaml       # Cluster access (SOPS encrypted, git-versioniert)
.ocp/                 # Lokaler State (gitignored)
  status.yaml         # Runtime-Status (transient)
  age.key             # Age Private Key (decrypted cache)
  age.pub             # Age Public Key
```

## Spec vs Status Trennung

**ocp.yaml (Spec)** wird geschrieben wenn:
- Computed defaults zurückfließen (z.B. IP von Hetzner die nicht angegeben war)
- Alles was der User theoretisch selbst hätte setzen können, aber nicht hat
- Nach dem ersten Apply sind diese Werte "gepinnt"

Beispiel:
```yaml
# Vorher (User schreibt):
controlPlanes:
  provider: hetzner
  serverType: cx32

# Nachher (nach ocp apply):
controlPlanes:
  provider: hetzner
  serverType: cx32
  publicIp: 1.2.3.4      # <- computed, jetzt gepinnt
```

**.ocp/status.yaml (Status)** enthält nur transiente Runtime-Daten:
- Provider-interne IDs (Hetzner Server ID)
- Join Tokens (RKE2/K3s)
- Kubeconfig
- Phase / Timestamps
- Dinge die der User NICHT setzen könnte

**Drift Detection**: Weil setzbare Werte in der Spec stehen, kann OCP erkennen wenn die Realität abweicht:
```
$ ocp status
WARNING: Drift detected!
  cp-1: spec.publicIp=1.2.3.4, actual=2.3.4.5
```

## Implementierte Features

### Commands
- `ocp init` - Projekt initialisieren (git, keys, config)
  - `--hetzner` - Interaktives Hetzner Token Setup
  - `--no-git` - Git-Initialisierung überspringen
  - `--name` - Cluster-Name setzen
  - `--provider` - Provider wählen (hetzner/ssh/local)
  - `--nopassword` - Dev-Modus ohne Verschlüsselung
- `ocp apply` - Cluster deployen/aktualisieren
- `ocp status` - Cluster-Status anzeigen
- `ocp destroy` - Cluster löschen
- `ocp kubeconfig` - Kubeconfig exportieren
- `ocp edit` - Config via TUI bearbeiten
- `ocp version` - Versionen anzeigen
- `ocp update` - Cluster-Komponenten aktualisieren
- `ocp ssh` - SSH auf Cluster-Nodes (mit admin-key)
- `ocp deploy-robocop` - Robocop Controller deployen
- `ocp inject-key` - Robo-Key in Robocop injizieren
- `ocp dev` - Development Tools (Registry, Image Build)
- `ocp hetzner` - Hetzner Cloud Debugging (Server auflisten)

### Module
- **OCP::Config** - Spec/Status Trennung (ocp.yaml vs .ocp/status.yaml), Validation, GPU Config
- **OCP::Secrets** - SOPS/age Wrapper für verschlüsselte Secrets
- **OCP::Keys** - Two-Tier SSH Key Management (admin-key + robo-key)
- **OCP::Password** - Passwort-Prompting und AES-256-GCM Verschlüsselung
- **OCP::SSH** - SSH-Verbindungen und Remote-Befehle (IPC::Open3)
- **OCP::Rex** - Rex Task Executor (RKE2/K3s Installation)
- **OCP::K3s** - K3s Installation und Management (direkt)
- **OCP::Local** - Lokale Installation (ohne SSH, braucht root)
- **OCP::Hetzner** - Hetzner Cloud API Helper (Wizard UI)
- **OCP::Provider** - Factory für Infrastructure Provider
- **OCP::Provider::Hetzner** - Hetzner Server-Lifecycle (idempotent, Label-basiert)
- **OCP::Provider::SSH** - SSH-Provider (bestehende Server)
- **OCP::Provider::Local** - Lokaler Provider (localhost)
- **OCP::Kubernetes** - Typed K8s Helpers (Node Status, GPU Detection)
- **OCP::Versions** - Version Manifest und Komponentenversionen (inkl. GPU Stack)
- **OCP::DevRegistry** - Development Registry Manager (deprecated, nutzt ocp-system)
- **OCP::UI** - Terminal UI für Formulare (Tickit-basiert)
- **OCP::Robocop** - Kubernetes Controller (im Cluster)
- **OCP::Robocop::Controller** - Reconciliation Logic

### Provider
- **Hetzner Cloud** - Via WWW::Hetzner::Cloud (CPAN)
- **SSH** - Bestehende Server als Worker einbinden
- **Local** - Lokale Installation (Docker Mode oder Native)

## Dependencies (cpanfile)

```perl
requires 'Moo';
requires 'MooX::Cmd';
requires 'MooX::Options';
requires 'YAML::XS';
requires 'Path::Tiny';
requires 'namespace::clean';
requires 'WWW::Hetzner';
requires 'Crypt::Age';
requires 'File::SOPS';
requires 'Rex';
requires 'IO::Async';
requires 'Net::Async::Kubernetes';
requires 'IO::K8s';
```

## Externe Tools (im Docker Image)

- `kubectl` - Kubernetes CLI
- `ssh` / `ssh-keygen` - SSH Operations

**Nicht mehr benötigt** (durch reine Perl-Implementierung ersetzt):
- ~~`sops`~~ - ersetzt durch File::SOPS
- ~~`age`~~ - ersetzt durch Crypt::Age

## Build & Test

```bash
make test       # Run tests locally
make test-v     # Run tests verbose
make build      # Build Docker image
make clean      # Clean artifacts
```

## Verwandte Projekte

- `~/dev/perl/p5-www-hetzner` - WWW::Hetzner (auf CPAN)
- `~/dev/perl/p5-crypt-age` - Crypt::Age
- `~/dev/perl/p5-file-sops` - File::SOPS
- `~/dev/perl/p5-net-async-kubernetes` - Net::Async::Kubernetes
- `~/dev/perl/io-k8s-p5` - IO::K8s
- `~/dev/perl/kubernetes-rest` - Kubernetes::REST

## Workflow

```bash
# Neues Projekt
ocp init --hetzner
# -> Fragt nach Hetzner Token, generiert Keys, erstellt Config

# Config bearbeiten
vim ocp.yaml

# Cluster deployen
ocp apply

# Status prüfen
ocp status

# Kubeconfig exportieren
ocp kubeconfig -e

# Cluster löschen
ocp destroy
```

## Config Beispiel (ocp.yaml v2)

```yaml
name: mycluster
controlPlanes:
  provider: hetzner
  location: fsn1
  serverType: cx32
  nodes: 1  # → police1
```

Workers werden via CRDs im Cluster gemanaged (robocop).

## Robocop Controller

**Robocop** ist der Kubernetes Controller, der im Cluster läuft und Worker-Nodes via CRDs managed.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  ocp CLI (extern)                                               │
│  ────────────────                                               │
│  • Bootstrap RKE2/K3s auf erstem Control Plane                  │
│  • Installiert Cilium                                           │
│  • Deployt robocop CRDs + Controller                           │
│  • Läuft auf Laptop/CI/CD                                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Kubernetes Cluster                                             │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  robocop (Deployment in ocp-system namespace)            │ │
│  │  ─────────────────────────────────────                   │ │
│  │  • Watched OCPNode + OCPNodeProvider CRDs                │ │
│  │  • Reconciliation Loop: Provision → Install → Ready      │ │
│  │  • Basiert auf: Net::Async::Kubernetes                   │ │
│  │  • Benutzt: IO::K8s, Kubernetes::REST                    │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### CRDs

**OCPNodeProvider** - Konfiguration für Infrastructure Provider:

```yaml
apiVersion: ocp.internal/v1
kind: OCPNodeProvider
metadata:
  name: hetzner-fsn1
  namespace: ocp-system
spec:
  type: hetzner  # oder: ssh
  hetzner:
    tokenSecretRef:
      name: hetzner-api-token
    location: fsn1
    serverType: cx32
    image: debian-13
```

**OCPNode** - Einzelner Node (CP oder Worker):

```yaml
apiVersion: ocp.internal/v1
kind: OCPNode
metadata:
  name: worker-1
  namespace: ocp-system
spec:
  role: worker  # oder: control-plane
  providerRef: hetzner-fsn1
  serverType: cx23  # Override
  gpu: false
status:
  phase: Ready
  providerId: "12345678"
  publicIP: 1.2.3.4
  joinedAt: 2026-02-15T...
```

### Reconciliation States

```
Pending → Provisioning → Installing → Ready
              ↓
           Failed (retry with backoff)
```

**Pending**: CRD erstellt, noch nichts passiert
**Provisioning**: Infrastructure wird erstellt (Hetzner Server, SSH host verfügbar)
**Installing**: RKE2/K3s wird installiert via Rex
**Ready**: Node im Cluster, healthy
**Failed**: Fehler aufgetreten, retry später

### Manifests

```
manifests/robocop/
├── crds/
│   ├── ocpnodeprovider.yaml  # CRD Definition
│   └── ocpnode.yaml           # CRD Definition
├── rbac.yaml                  # ServiceAccount + ClusterRole
├── deployment.yaml            # robocop Deployment
└── kustomization.yaml         # Kustomize root
```

Deploy via:
```bash
kubectl apply -k manifests/robocop/
```

### Dependencies

```perl
requires 'IO::Async';           # Event loop
requires 'Net::Async::Kubernetes';  # K8s API client mit watchers
requires 'IO::K8s';             # Typed API objects
requires 'Kubernetes::REST';    # Sync API client
```
