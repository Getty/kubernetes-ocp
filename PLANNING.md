# OCP - Omni Control Plane

> Self-contained Kubernetes cluster management with a single config file approach.
>
> "Omni" - weil es verschiedene Provider, Methoden und Umgebungen vereint.

## Vision

Ein Tool das Kubernetes Cluster vollständig über eine einzige, selbstbeschreibende Config-Datei verwaltet. Die Config enthält sowohl die gewünschte Spezifikation (spec) als auch den aktuellen Zustand (status) - inspiriert von Kubernetes eigener Ressourcen-Architektur.

**Kernprinzipien:**
- **Single File = Complete Cluster**: Eine `ocp.yaml` Datei reicht um einen Cluster zu erstellen, zu prüfen, oder wiederherzustellen
- **Idempotent by Design**: Jeder `ocp apply` Aufruf konvergiert zum gewünschten Zustand
- **No External State**: Kein Terraform State, kein S3 Backend - der Status lebt in der Config
- **Provider Agnostic**: Hetzner, AWS, Vast.ai, bare SSH - alles über einheitliche Abstraktion
- **Secret References**: Credentials nie in der Config, nur Referenzen auf externe Quellen

---

## Architektur Übersicht

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              OCP Architecture                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Project Directory                                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  ocp.yaml          - Cluster spec + status                          │  │
│   │  secrets.yaml      - Secret references (not values!)                │  │
│   │  addons/           - Cluster addons (ArgoCD, Monitoring, etc.)      │  │
│   │  apps/             - Application deployments                         │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│                                    ▼                                        │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                        OCP CLI                                       │  │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │  │
│   │  │   Parser    │  │ Reconciler  │  │  Executor   │                  │  │
│   │  │  (Config)   │──│   (Diff)    │──│  (Actions)  │                  │  │
│   │  └─────────────┘  └─────────────┘  └─────────────┘                  │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│            ┌───────────────────────┼───────────────────────┐               │
│            ▼                       ▼                       ▼               │
│   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐       │
│   │    Provider     │    │    Network      │    │   Kubernetes    │       │
│   │    Adapters     │    │    Adapter      │    │    Adapter      │       │
│   │  ─────────────  │    │  ─────────────  │    │  ─────────────  │       │
│   │  Hetzner Cloud  │    │  Tailscale      │    │  k3s            │       │
│   │  Hetzner Robot  │    │  Wireguard      │    │  kubeadm        │       │
│   │  AWS EC2        │    │  Native         │    │                 │       │
│   │  Vast.ai        │    │                 │    │                 │       │
│   │  SSH Generic    │    │                 │    │                 │       │
│   └─────────────────┘    └─────────────────┘    └─────────────────┘       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Directory Struktur

```
my-cluster/
├── ocp.yaml                    # Haupt-Config (Cluster spec + status)
├── secrets.yaml                # Secret-Referenzen
│
├── addons/                     # Optionale Cluster-Addons
│   ├── argocd/
│   │   ├── addon.yaml          # Addon-Definition
│   │   └── values.yaml         # Helm values / Kustomize patches
│   ├── cert-manager/
│   ├── monitoring/
│   └── ingress-nginx/
│
├── apps/                       # Optionale App-Deployments
│   ├── my-app/
│   │   ├── app.yaml            # App-Definition
│   │   ├── deployment.yaml
│   │   └── secrets.yaml        # App-spezifische Secret-Refs
│   └── another-app/
│
└── environments/               # Optionale Environment-Overrides
    ├── prod/
    │   └── overrides.yaml
    └── staging/
        └── overrides.yaml
```

---

## Config File Spezifikation

### ocp.yaml - Vollständiges Beispiel

```yaml
apiVersion: ocp/v1
kind: Cluster
metadata:
  name: production
  created: null                          # Wird bei Erstellung gesetzt

spec:
  # ═══════════════════════════════════════════════════════════════════
  # KUBERNETES DISTRIBUTION
  # ═══════════════════════════════════════════════════════════════════
  kubernetes:
    distribution: k3s                    # k3s | kubeadm
    version: v1.29.0+k3s1
    config:                              # Distribution-spezifische Config
      disableServiceLB: false
      disableTraefik: true               # Wir nutzen eigenen Ingress
      clusterCidr: 10.42.0.0/16
      serviceCidr: 10.43.0.0/16

  # ═══════════════════════════════════════════════════════════════════
  # NETWORK OVERLAY
  # ═══════════════════════════════════════════════════════════════════
  network:
    overlay: tailscale                   # tailscale | wireguard | none
    tailscale:
      authKeyRef: tailscale-authkey      # Referenz auf secrets.yaml

  # ═══════════════════════════════════════════════════════════════════
  # CONTROL PLANE NODES
  # ═══════════════════════════════════════════════════════════════════
  controlPlanes:
    count: 3                             # 1 oder 3 für HA
    provider: hetzner-cloud
    hetzner:
      serverType: cpx21
      location: fsn1
      image: ubuntu-22.04
      sshKeyRef: hetzner-ssh-key         # Referenz auf secrets.yaml

  # ═══════════════════════════════════════════════════════════════════
  # WORKER NODE POOLS
  # ═══════════════════════════════════════════════════════════════════
  workers:
    - name: general
      count: 3
      provider: hetzner-cloud
      hetzner:
        serverType: cpx31
        location: fsn1
        image: ubuntu-22.04
      labels:
        workload: general
      taints: []

    - name: gpu
      count: 0                           # 0 = Pool definiert aber keine Nodes
      provider: vastai
      vastai:
        gpuType: RTX_4090
        minVram: 24
        maxPrice: 0.50
      labels:
        workload: gpu
        nvidia.com/gpu: "true"
      taints:
        - key: nvidia.com/gpu
          value: "true"
          effect: NoSchedule

  # ═══════════════════════════════════════════════════════════════════
  # SSH ACCESS (für alle Provider)
  # ═══════════════════════════════════════════════════════════════════
  ssh:
    privateKeyRef: ssh-private-key       # Referenz auf secrets.yaml
    publicKeyRef: ssh-public-key
    user: root                           # Default SSH user

  # ═══════════════════════════════════════════════════════════════════
  # ADDONS (Reihenfolge = Install-Order)
  # ═══════════════════════════════════════════════════════════════════
  addons:
    - path: addons/cert-manager
      enabled: true
    - path: addons/ingress-nginx
      enabled: true
    - path: addons/argocd
      enabled: true
    - path: addons/monitoring
      enabled: false                     # Deaktiviert

  # ═══════════════════════════════════════════════════════════════════
  # APPS
  # ═══════════════════════════════════════════════════════════════════
  apps:
    - path: apps/my-app
    - path: apps/api-gateway

# ═════════════════════════════════════════════════════════════════════
# STATUS (wird von OCP befüllt - NICHT manuell editieren)
# ═════════════════════════════════════════════════════════════════════
status:
  phase: Running                         # Pending | Provisioning | Running | Degraded | Failed
  lastReconciled: "2024-01-20T14:22:00Z"

  cluster:
    apiEndpoint: https://100.64.0.1:6443
    joinToken: K10abc123...              # k3s join token
    caCertHash: sha256:abc123...         # Für kubeadm
    kubeconfig: |
      apiVersion: v1
      kind: Config
      clusters:
      - cluster:
          server: https://100.64.0.1:6443
          certificate-authority-data: LS0tLS1C...
        name: production
      users:
      - name: admin
        user:
          client-certificate-data: LS0tLS1C...
          client-key-data: LS0tLS1C...
      contexts:
      - context:
          cluster: production
          user: admin
        name: default
      current-context: default

  nodes:
    - name: cp-1
      role: control-plane
      pool: null
      provider: hetzner-cloud
      providerId: "12345678"             # Hetzner Server ID
      publicIp: 168.119.1.10
      privateIp: 10.0.0.1
      overlayIp: 100.64.0.1              # Tailscale IP
      phase: Ready                       # Pending | Provisioning | Joining | Ready | NotReady | Deleting
      createdAt: "2024-01-15T10:35:00Z"
      joinedAt: "2024-01-15T10:37:00Z"

    - name: cp-2
      role: control-plane
      pool: null
      provider: hetzner-cloud
      providerId: "12345679"
      publicIp: 168.119.1.11
      privateIp: 10.0.0.2
      overlayIp: 100.64.0.2
      phase: Ready
      createdAt: "2024-01-15T10:35:30Z"
      joinedAt: "2024-01-15T10:38:00Z"

    - name: worker-general-1
      role: worker
      pool: general
      provider: hetzner-cloud
      providerId: "12345680"
      publicIp: 168.119.1.20
      overlayIp: 100.64.0.10
      phase: Ready
      createdAt: "2024-01-15T10:40:00Z"
      joinedAt: "2024-01-15T10:42:00Z"
      labels:
        workload: general

  addons:
    - name: cert-manager
      phase: Ready
      version: v1.13.0
      installedAt: "2024-01-15T10:45:00Z"

    - name: argocd
      phase: Ready
      version: v2.9.0
      installedAt: "2024-01-15T10:46:00Z"
```

### secrets.yaml - Secret Referenzen

```yaml
apiVersion: ocp/v1
kind: SecretRefs

# Secret Provider Konfiguration
providers:
  env:
    type: environment

  file:
    type: file

  vault:
    type: hashicorp-vault
    address: https://vault.example.com
    auth:
      method: token
      tokenRef: env:VAULT_TOKEN

  sops:
    type: sops
    ageKeyFile: ~/.config/sops/age/keys.txt

  onepassword:
    type: 1password
    account: my-team.1password.com

# Secret Definitionen
secrets:
  # === Provider Credentials ===
  hetzner-token:
    provider: env
    key: HETZNER_API_TOKEN

  vastai-apikey:
    provider: env
    key: VASTAI_API_KEY

  aws-credentials:
    provider: file
    path: ~/.aws/credentials
    profile: ocp

  # === SSH Keys ===
  ssh-private-key:
    provider: file
    path: ~/.ssh/ocp_cluster

  ssh-public-key:
    provider: file
    path: ~/.ssh/ocp_cluster.pub

  # === Network Overlay ===
  tailscale-authkey:
    provider: vault
    path: secret/infrastructure/tailscale
    key: authkey

  wireguard-privatekey:
    provider: sops
    file: secrets/wireguard.enc.yaml
    key: privateKey

  # === Application Secrets ===
  database-credentials:
    provider: onepassword
    vault: Infrastructure
    item: Production Database
```

---

## CLI Commands

### Kern-Commands

| Command | Beschreibung |
|---------|--------------|
| `ocp init` | Neues Projekt-Directory mit Template erstellen |
| `ocp apply` | Reconcile: Desired State → Actual State |
| `ocp apply --only cluster` | Nur Cluster (keine Addons/Apps) |
| `ocp apply --only addons` | Nur Addons |
| `ocp apply apps/my-app` | Nur spezifische App |
| `ocp status` | Cluster-Status anzeigen (read-only) |
| `ocp diff` | Zeige was `apply` ändern würde |
| `ocp destroy` | Cluster vollständig löschen |
| `ocp destroy --keep-config` | Löschen aber Status behalten |

### Node-Management

| Command | Beschreibung |
|---------|--------------|
| `ocp nodes` | Node-Liste anzeigen |
| `ocp nodes add --pool general` | Node zu Pool hinzufügen |
| `ocp nodes remove <name>` | Node entfernen (drain + delete) |
| `ocp nodes ssh <name>` | SSH zu Node |
| `ocp nodes logs <name>` | Node Logs anzeigen |

### Secret-Management

| Command | Beschreibung |
|---------|--------------|
| `ocp secrets check` | Prüfe ob alle Referenzen auflösbar |
| `ocp secrets list` | Liste alle referenzierten Secrets |
| `ocp secrets reveal <name>` | Zeige Secret-Wert (für Debugging) |

### Utilities

| Command | Beschreibung |
|---------|--------------|
| `ocp kubeconfig` | Kubeconfig ausgeben |
| `ocp kubeconfig --export` | Nach ~/.kube/config exportieren |
| `ocp kubectl -- get pods` | kubectl mit Cluster-Config ausführen |
| `ocp refresh` | Status von Live-APIs aktualisieren |
| `ocp validate` | Config validieren ohne Änderungen |

---

## Reconciliation Logic

### Haupt-Reconciliation-Loop

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ocp apply                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. PARSE                                                                   │
│     ├── Load ocp.yaml                                                       │
│     ├── Load secrets.yaml                                                   │
│     ├── Resolve all secret references                                       │
│     └── Validate config                                                     │
│                                                                             │
│  2. QUERY ACTUAL STATE                                                      │
│     ├── Provider APIs: Welche Server existieren?                           │
│     ├── Network: Welche Nodes sind im Overlay?                             │
│     └── Kubernetes API: Welche Nodes sind registered?                      │
│                                                                             │
│  3. CALCULATE DIFF                                                          │
│     ├── Nodes to create (in spec, not in provider)                         │
│     ├── Nodes to join (in provider, not in k8s)                            │
│     ├── Nodes to delete (in provider, not in spec)                         │
│     └── Config changes (spec differs from actual)                          │
│                                                                             │
│  4. EXECUTE ACTIONS (in order)                                              │
│     ├── Create missing servers (Provider API)                              │
│     ├── Wait for servers ready (SSH reachable)                             │
│     ├── Setup network overlay (Tailscale/WG join)                          │
│     ├── Install/Join Kubernetes (k3s/kubeadm)                              │
│     ├── Apply labels and taints                                            │
│     ├── Remove excess nodes (drain → delete → terminate)                   │
│     └── Install/Update Addons                                              │
│                                                                             │
│  5. UPDATE STATUS                                                           │
│     ├── Write new node information                                         │
│     ├── Update cluster endpoints                                           │
│     ├── Save kubeconfig                                                    │
│     └── Write ocp.yaml back to disk                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Node Lifecycle States

```
                    ┌──────────────┐
                    │   (config)   │
                    │  spec.count  │
                    └──────┬───────┘
                           │ ocp apply
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Pending                                   │
│              (in spec, action planned)                          │
└─────────────────────────────┬───────────────────────────────────┘
                              │ Provider.CreateServer()
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Provisioning                                │
│            (server creating, waiting for IP)                    │
└─────────────────────────────┬───────────────────────────────────┘
                              │ SSH reachable
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Installing                                 │
│         (network overlay + k3s/kubeadm installing)              │
└─────────────────────────────┬───────────────────────────────────┘
                              │ k3s/kubeadm join success
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Joining                                  │
│              (waiting for node Ready in k8s)                    │
└─────────────────────────────┬───────────────────────────────────┘
                              │ kubectl: node Ready
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                          Ready                                   │
│                  (fully operational)                            │
└─────────────────────────────┬───────────────────────────────────┘
                              │ spec.count decreased OR node unhealthy
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Draining                                  │
│              (kubectl drain, workloads moving)                  │
└─────────────────────────────┬───────────────────────────────────┘
                              │ drain complete
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Deleting                                  │
│         (kubectl delete node, provider terminate)               │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
                         (removed from status)
```

---

## Implementation Phasen

### Phase 1: Core MVP (Hetzner Cloud + SSH Workers) ✅ CURRENT FOCUS

**Ziel:** k3s Cluster auf Hetzner Cloud + bestehende Bare-Metal Server als Worker einbinden

**Scope:**
- [ ] Project Structure & CLI Framework (Perl)
- [ ] Config Parsing (ocp.yaml, secrets.yaml)
- [ ] Secret Resolution (env, file providers)
- [ ] Hetzner Cloud Provider Adapter
  - [ ] Server erstellen
  - [ ] Server löschen
  - [ ] Server Status abfragen
  - [ ] SSH Key Management
- [ ] SSH Generic Provider Adapter (für bestehende Server)
  - [ ] Server Status abfragen (SSH erreichbar?)
  - [ ] Kein Create/Delete (Server existiert bereits)
  - [ ] Für: GPU Server (Hetzner Dedicated), Storage Server, etc.
- [ ] k3s Adapter
  - [ ] Single Control Plane Installation
  - [ ] Worker Node Join
  - [ ] Node entfernen (drain + delete)
  - [ ] Kubeconfig extrahieren
- [ ] Basic Reconciliation Loop
- [ ] Status Management (ocp.yaml updates)
- [ ] CLI Commands: init, apply, status, destroy, kubeconfig

**Nicht in Phase 1:**
- Multi Control Plane (HA)
- Network Overlay (Tailscale/WG)
- Addons/Apps
- SSH-basierte Control Planes

**Use Cases Phase 1:**
```
┌─────────────────────────────────────────────────────────────────┐
│                     Phase 1 Setup                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Hetzner Cloud                    Existing Bare Metal          │
│   ┌─────────────┐                 ┌─────────────┐              │
│   │ Control     │                 │ GPU Server  │              │
│   │ Plane       │◄────────────────│ (Worker)    │              │
│   │ (cpx21)     │     k3s join    │ Hetzner Ded │              │
│   └─────────────┘                 └─────────────┘              │
│         ▲                                                       │
│         │ k3s join                                              │
│         │                         ┌─────────────┐              │
│   ┌─────────────┐                 │ Storage     │              │
│   │ Worker      │                 │ Server      │              │
│   │ (cpx31)     │                 │ (Worker)    │              │
│   │ Hetzner Cld │                 └──────┬──────┘              │
│   └─────────────┘                        │                      │
│                                          │ k3s join             │
│                         ◄────────────────┘                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 2: SSH Control Planes & HA

**Ziel:** Control Planes auf eigenen Servern (Home Setup) + HA

**Scope:**
- [ ] SSH-basierte Control Plane Installation
  - [ ] k3s server install via SSH
  - [ ] Für: Home Server, lokale VMs, etc.
- [ ] HA Control Plane (3 nodes)
- [ ] Tailscale Network Overlay
- [ ] Wireguard Alternative
- [ ] API Endpoint Management (VIP oder DNS)
- [ ] Automatic failover handling

**Use Cases Phase 2:**
```
┌─────────────────────────────────────────────────────────────────┐
│                     Phase 2: Home Setup                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Home Network (SSH-basiert)                                    │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│   │ CP-1        │  │ CP-2        │  │ CP-3        │            │
│   │ (NUC)       │──│ (RPi)       │──│ (VM)        │            │
│   └─────────────┘  └─────────────┘  └─────────────┘            │
│         │                │                │                     │
│         └────────────────┼────────────────┘                     │
│                          │                                      │
│                    Tailscale Mesh                               │
│                          │                                      │
│   ┌─────────────┐  ┌─────────────┐                             │
│   │ Worker-1    │  │ Worker-2    │                             │
│   │ (Desktop)   │  │ (Laptop)    │                             │
│   └─────────────┘  └─────────────┘                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 3: Multi-Provider

**Ziel:** Nodes von verschiedenen Providern mischen

**Scope:**
- [ ] AWS EC2 Provider
- [ ] Hetzner Robot (Dedicated) Provider
- [ ] Vast.ai Provider (GPU Nodes)
- [ ] SSH Generic Provider (eigene Server)
- [ ] Cross-Provider Networking

### Phase 4: Addons System

**Ziel:** Cluster-Addons deklarativ verwalten

**Voraussetzung:** Mindestens ein Worker Node muss Ready sein (Control Plane hat NoSchedule taint)

**Architektur:**
```
┌─────────────────────────────────────────────────────────────────┐
│                     Addon Processing                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ocp apply (Host)                                              │
│        │                                                        │
│        ▼                                                        │
│   Check: min 1 Worker Ready?                                    │
│        │                                                        │
│        ├── No  → Skip Addons, Warn User                        │
│        │                                                        │
│        └── Yes → Start Addon Processor                         │
│                       │                                         │
│                       ▼                                         │
│              ┌─────────────────┐                               │
│              │  Docker Container │  (optional, für Helm etc.)  │
│              │  ───────────────  │                             │
│              │  - helm          │                               │
│              │  - kustomize     │                               │
│              │  - jsonnet       │                               │
│              │  - kubectl       │                               │
│              └────────┬─────────┘                               │
│                       │                                         │
│                       ▼                                         │
│              Apply to Cluster                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Scope:**
- [ ] Addon Definition Format
- [ ] Helm Installation Method
- [ ] Kustomize Installation Method
- [ ] Plain Manifests Method
- [ ] Addon Dependencies
- [ ] Addon Updates
- [ ] Docker-based Addon Processor (optional)

### Phase 5: Apps & Secrets

**Ziel:** Applikationen deployen mit Secret-Injection

**Scope:**
- [ ] App Definition Format
- [ ] Namespace Management
- [ ] Secret Injection in K8s Secrets
- [ ] Jsonnet Support
- [ ] Vault Provider
- [ ] SOPS Provider
- [ ] 1Password Provider

### Phase 6: Advanced Features

**Ziel:** Production-ready Features

**Scope:**
- [ ] kubeadm Support (Alternative zu k3s)
- [ ] Auto-Scaling (Node Pools)
- [ ] Scheduled Scaling
- [ ] Backup & Restore
- [ ] Cluster Cloning
- [ ] Environment Overrides
- [ ] Drift Detection & Alerts
- [ ] Web UI (optional)

---

## Technical Decisions

### Sprache: Perl

**Begründung:**
- Überall auf Debian/Ubuntu vorinstalliert
- Mächtiges Text-Processing und System-Scripting
- CPAN Ecosystem für robuste Module
- Potentiell als CPAN Distribution veröffentlichbar
- Kein Compile-Schritt nötig
- Entwickler-Expertise vorhanden

### CPAN Abhängigkeiten

| Dependency | Zweck |
|------------|-------|
| `Moo` | OOP Framework (leichtgewichtig) |
| `YAML::XS` | YAML Parsing (schnell) |
| `JSON::XS` | JSON Parsing |
| `HTTP::Tiny` | HTTP Client (Core seit 5.14) |
| `IO::Socket::SSL` | HTTPS Support |
| `Net::OpenSSH` | SSH Client |
| `Path::Tiny` | File Operations |
| `Try::Tiny` | Exception Handling |
| `Log::Any` | Logging Framework |
| `Getopt::Long` | CLI Argument Parsing (Core) |

### Optional / Später

| Dependency | Zweck |
|------------|-------|
| `App::Cmd` oder eigenes | CLI Framework |
| `Template::Toolkit` | Template Processing |
| `Parallel::ForkManager` | Parallel Node Operations |

### Externe Tools (zur Runtime)

| Tool | Zweck | Verfügbarkeit |
|------|-------|---------------|
| `ssh` | Fallback wenn Net::OpenSSH Probleme | Überall |
| `kubectl` | K8s API Interaktion | Muss installiert sein oder wir bundlen es |
| `curl` | Fallback für HTTP | Überall |

### Keine Abhängigkeiten auf

- Terraform (kein externes State Management)
- Ansible (kein zusätzliches Config Management)
- Go/Rust (keine Compilation nötig)

### Docker für Addon-Processing

Addons können komplexere Tools brauchen (Helm, Kustomize, Jsonnet). Statt diese alle zu installieren:
- Addon-Processing läuft in Docker-Container
- Container hat alle Tools vorinstalliert
- Wird nur gestartet wenn Addons deployed werden
- Benötigt mindestens einen Worker Node (Control Plane hat NoSchedule taint)

---

## Error Handling & Recovery

### Idempotenz-Garantien

| Situation | Verhalten |
|-----------|-----------|
| Server existiert bereits | Skip creation, verify status |
| k3s bereits installiert | Skip install, verify join status |
| Node bereits im Cluster | Skip join, verify Ready status |
| Network bereits konfiguriert | Skip setup, verify connectivity |
| Addon bereits installiert | Check version, upgrade if needed |

### Failure Recovery

| Failure | Recovery |
|---------|----------|
| Server creation failed | Retry mit exponential backoff |
| SSH connection failed | Retry, dann Server als Unhealthy markieren |
| k3s install failed | Cleanup, retry from scratch |
| Join failed | Check token validity, regenerate if needed |
| Partial apply | Resume from last successful state |

### Rollback Strategie

Kein automatisches Rollback - stattdessen:
1. Status reflektiert immer den AKTUELLEN Zustand
2. User kann alten spec wiederherstellen (git revert)
3. `ocp apply` konvergiert zum neuen (alten) spec

---

## Security Considerations

### Secrets

- Niemals Secrets in ocp.yaml (nur Referenzen)
- Kubeconfig im Status ist akzeptabel (ist ohnehin Cluster-Access)
- Provider Tokens immer via Referenz
- SOPS für verschlüsselte Files in Git

### Network

- Default: Tailscale für Node-zu-Node Kommunikation
- Kubernetes API nur über Overlay erreichbar (optional)
- SSH Keys dediziert für Cluster (nicht personal keys)

### Least Privilege

- Provider API Keys nur mit nötigen Permissions
- Tailscale Keys: ephemeral, reusable, tagged
- K8s RBAC für Addon Service Accounts

---

## File Locations

### Project Directory (User)

```
~/projects/my-cluster/
├── ocp.yaml
├── secrets.yaml
├── addons/
└── apps/
```

### OCP Config Directory

```
~/.config/ocp/
├── config.yaml          # Global defaults
└── cache/               # Provider response cache
```

### Runtime

```
/tmp/ocp-<cluster>/      # Temporary files during apply
├── ssh-socket           # SSH connection multiplexing
└── scripts/             # Generated install scripts
```

---

## Testing Strategy

### Unit Tests

- Config parsing
- Diff calculation
- Secret resolution
- Provider API mocking

### Integration Tests

- Hetzner API (mit Test-Account)
- k3s Installation (in Docker/VM)
- Full reconciliation loop

### E2E Tests

- Complete cluster lifecycle auf Hetzner
- Multi-node scenarios
- Failure injection

---

## Open Questions

1. **Cluster Naming:** Wie verhindern wir Namenskonflikte bei Provider-Ressourcen?
   - Vorschlag: `ocp-<cluster-name>-<node-name>` als Server-Name

2. **Multi-Cluster:** Ein ocp.yaml pro Cluster, oder mehrere Cluster in einem File?
   - Vorschlag: Ein File pro Cluster, aber `ocp.yaml` kann andere importieren

3. **Concurrent Applies:** Was wenn zwei Terminals gleichzeitig `ocp apply` ausführen?
   - Vorschlag: Lock-File in Project Directory

4. **Long-Running Operations:** Wie mit Timeouts umgehen?
   - Vorschlag: Configurable timeouts, resume capability

5. **Upgrade Path:** Wie ocp.yaml Schema-Updates handhaben?
   - Vorschlag: apiVersion bump, Migration Scripts

---

## Next Steps

1. **Repository Setup**
   - Go Module initialisieren
   - Directory Structure anlegen
   - CI Pipeline (GitHub Actions)

2. **Phase 1 Implementation**
   - Config Types definieren
   - CLI Skeleton
   - Hetzner Provider
   - k3s Adapter
   - Reconciliation Loop

3. **Documentation**
   - README mit Quick Start
   - Config Reference
   - Provider Documentation
