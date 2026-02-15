# OCP - Omni Control Plane

## Projektstatus

OCP ist ein Perl-basiertes CLI-Tool zur Verwaltung von Kubernetes-Clustern (RKE2). Das Projekt wird als CPAN-Distribution entwickelt mit Docker als primärer Installationsmethode.

## Stack Entscheidungen

```
RKE2        → Die Basis (statt k3s)
Cilium      → Macht fast alles (CNI, Service Mesh, Ingress, Observability)
Vector      → Ein DaemonSet für alles (Logs + Metriken)
VictoriaMetrics → Metriken Storage (Prometheus-kompatibel, 10x effizienter)
Loki        → Log Storage
Perl DSL    → Orchestrierung und Abstraktion

Kein: Helm, Istio, Prometheus, ArgoCD, Node Exporter, Promtail, Canal
```

### Warum RKE2 statt k3s

```
├── FIPS 140-2 ready (Government/Enterprise)
├── CIS Hardening by default
├── SELinux Support
├── Secrets Encryption at Rest
├── Audit Logging
├── Kein Helm Controller → Wir wollen eh kein Helm
└── Perl DSL hat volle Kontrolle
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
├── helm template zum Rendern (Build-Zeit, nicht Runtime)
└── Perl DSL generiert/orchestriert alles

Helm nicht verboten - nur nicht der Default-Weg.
```

## Architektur

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Management Node (CX32, ~8GB RAM)                               │
│  ├── RKE2 Control Plane (etcd, apiserver, etc.)                │
│  ├── Perl Management Daemon (robocop)                          │
│  ├── VictoriaMetrics                                            │
│  ├── Loki                                                       │
│  ├── Grafana                                                    │
│  ├── kube-state-metrics                                         │
│  ├── Headlamp                                                   │
│  ├── Cilium Operator                                            │
│  └── Vector                                                     │
│                                                                 │
│  Worker Nodes (Bare Metal, viel RAM)                            │
│  ├── RKE2 Agent (~250MB)                                        │
│  ├── Cilium Agent (~300MB)                                      │
│  ├── Vector (~50MB)                                             │
│  └── Workloads (der ganze Rest)                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Monitoring Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  DaemonSet (1x pro Node):                                       │
│  └── Vector                                                     │
│      ├── Sammelt Logs (/var/log/containers)                    │
│      ├── Sammelt Host Metriken                                  │
│      └── Schickt alles zentral                                  │
│                                                                 │
│  Zentral (auf Control Plane):                                   │
│  ├── VictoriaMetrics (statt Prometheus, 10x effizienter)       │
│  ├── Loki (Log Storage)                                         │
│  ├── kube-state-metrics (K8s Object Metriken)                  │
│  └── Grafana (Dashboards)                                       │
│                                                                 │
│  Schon da durch Cilium:                                         │
│  └── Hubble (Network Flows, Service Map)                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Visualisierung

```
├── Grafana       → Metriken/Logs Dashboards
├── Hubble UI     → Network Flows (durch Cilium)
├── Headlamp      → Cluster Resource Browser (wie ArgoCD UI ohne GitOps)
└── k9s           → Terminal UI für Dev/Debugging
```

## Was wir NICHT brauchen

```
❌ Helm (Kustomize + Plain Manifests)
❌ Istio (Cilium macht Service Mesh)
❌ Prometheus (VictoriaMetrics effizienter)
❌ Node Exporter (Vector sammelt Host Metriken)
❌ Promtail (Vector macht Logs)
❌ Canal/Flannel (Cilium)
❌ Nginx Ingress (Cilium Gateway API)
❌ ArgoCD (Perl DSL orchestriert)
❌ Externer etcd für Dev (Single Node reicht)
```

## Architektur-Vision (v2)

**Klare Trennung der Verantwortlichkeiten:**

```
┌─────────────────────────────────────────────────────────────────┐
│  OCP CLI (ocp)                                                  │
│  ─────────────────                                              │
│  • Bootstrap Control Plane(s) - EINMALIG                        │
│  • Läuft EXTERN (Laptop, CI/CD)                                 │
│  • Installiert RKE2, Cilium, Basis-Stack                       │
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
│  │  • Basiert auf: Kubernetes::Controller (IO::Async)        │ │
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

# 2. Manifests via Kustomize (Perl DSL macht das)
kubectl apply -k /opt/ocp/manifests/

# 3. Worker joinen
curl -sfL https://get.rke2.io | INSTALL_RKE2_TYPE="agent" sh -
# config.yaml mit server + token
systemctl enable --now rke2-agent
```

## Perl DSL Verantwortlichkeiten

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Perl DSL / Management Daemon:                                  │
│  ├── Generiert Kustomize Strukturen                            │
│  ├── kubectl apply -k ausführen                                │
│  ├── Reihenfolge orchestrieren (Cilium vor Workloads)         │
│  ├── Health Checks / Readiness warten                          │
│  ├── Node Management (join/leave)                               │
│  ├── Config Management                                          │
│  ├── CRDs für Cilium Policies generieren                       │
│  └── Abstraction über K8s Komplexität                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## CRDs für robocop

```yaml
# Fixer SSH Node
apiVersion: ocp.io/v1
kind: Node
metadata:
  name: avatar
spec:
  provider: ssh
  host: avatar.conflict.industries
  gpu: true
status:
  phase: Ready
  joinedAt: 2026-01-12T...

---
# Dynamischer Hetzner Pool
apiVersion: ocp.io/v1
kind: NodePool
metadata:
  name: hetzner-workers
spec:
  provider: hetzner
  serverType: cx23
  location: fsn1
  min: 0
  max: 10

---
# On-Demand GPU (vast.ai)
apiVersion: ocp.io/v1
kind: NodePool
metadata:
  name: vast-gpus
spec:
  provider: vastai
  gpuType: rtx4090
  maxCostPerHour: 1.50
```

## Projekt-Struktur

```
kubernetes-ocp/
  ├── bin/ocp                    # CLI Tool (Bootstrap)
  ├── lib/OCP/                   # CLI Module
  ├── lib/OCP/RKE2.pm            # RKE2 Installation und Management
  ├── lib/OCP/Robocop/           # Controller Module (im Cluster)
  ├── manifests/                 # Kustomize Basis-Manifeste
  │   ├── cilium/
  │   ├── monitoring/            # Vector, VictoriaMetrics, Loki
  │   └── base/
  └── deploy/robocop.yaml        # Kubernetes Deployment

p5-kubernetes-controller/        # Separates CPAN Modul
  └── lib/Kubernetes/Controller.pm  # IO::Async basiertes Framework
```

## Datei-Struktur (Projekt)

```
ocp.yaml              # Cluster-Spezifikation (git-versioniert)
secrets.yaml          # SOPS/age verschlüsselte Secrets (git-versioniert)
.ocp/                 # Lokaler State (gitignored)
  status.yaml         # Runtime-Status (transient)
  age.key             # Age Private Key
  age.pub             # Age Public Key
  id_ed25519          # SSH Private Key
  id_ed25519.pub      # SSH Public Key
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
  floatingIp: 5.6.7.8    # <- falls Floating IP erstellt wurde
```

**.ocp/status.yaml (Status)** enthält nur transiente Runtime-Daten:
- Provider-interne IDs (Hetzner Server ID)
- Join Tokens (RKE2)
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
- `ocp apply` - Cluster deployen/aktualisieren
- `ocp status` - Cluster-Status anzeigen
- `ocp destroy` - Cluster löschen
- `ocp kubeconfig` - Kubeconfig exportieren
- `ocp hetzner` - Hetzner Cloud Debugging (Server auflisten)

### Module
- **OCP::Config** - Spec/Status Trennung (ocp.yaml vs .ocp/status.yaml)
- **OCP::Secrets** - SOPS/age Wrapper für verschlüsselte Secrets
- **OCP::SSH** - SSH-Verbindungen und Remote-Befehle
- **OCP::RKE2** - RKE2 Installation und Management

### Provider
- **Hetzner Cloud** - Via WWW::Hetzner::Cloud (CPAN)
- **SSH** - Bestehende Server als Worker einbinden

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

## Offene Punkte

- [ ] OCP::RKE2 Modul implementieren (ersetzt OCP::K3s)
- [ ] Cilium Manifeste im Repo
- [ ] Monitoring Stack Manifeste (Vector, VictoriaMetrics, Loki, Grafana)
- [ ] Headlamp Manifest
- [ ] Kubernetes::Controller Framework
- [ ] robocop Implementation

## Verwandte Projekte

- `~/dev/perl/p5-www-hetzner` - WWW::Hetzner (auf CPAN)
- `~/dev/perl/p5-crypt-age` - Crypt::Age Skeleton
- `~/dev/perl/p5-file-sops` - File::SOPS Skeleton

## Workflow

```bash
# Neues Projekt
ocp init --hetzner
# -> Fragt nach Hetzner Token, generiert Keys, erstellt Config

# Config bearbeiten
vim ocp.yaml

# Cluster deployen (RKE2 + Cilium + Monitoring Stack)
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
│  • Bootstrap RKE2 auf erstem Control Plane                      │
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
apiVersion: ocp.io/v1
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
apiVersion: ocp.io/v1
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

### Examples

Siehe `examples/` für vollständige Beispiele:
- `ssh-provider.yaml` - Existing bare metal GPU server
- `hetzner-provider.yaml` - Hetzner Cloud workers

### Dependencies

```perl
requires 'IO::Async';           # Event loop
requires 'Net::Async::Kubernetes';  # K8s API client mit watchers
requires 'IO::K8s';             # Typed API objects
requires 'Kubernetes::REST';    # Sync API client
```
