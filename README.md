# OCP - Omni Control Plane

Kubernetes cluster management with CRDs and in-cluster automation. Deploy RKE2/K3s clusters with Cilium CNI, manage nodes via Kubernetes-native CRDs.

## Features

### Core

- **RKE2 + K3s Support** - Production-ready RKE2 or lightweight K3s via config
- **Cilium CNI** - eBPF-based networking, kube-proxy replacement, Gateway API ingress
- **Core Registry** - Pull-through cache for Docker Hub + local registry for user images
- **cert-manager** - Automated SSL certificate management with Let's Encrypt support
- **GPU Support** - Auto-detection, NVIDIA driver + container toolkit, Kubernetes device plugin
- **Single-Node Mode** - Control plane can host workloads (auto-untaint)
- **Component Reconciliation** - Re-run `ocp apply` to deploy missing components on existing clusters

### Providers

- **Hetzner Cloud** - Automated server provisioning with API integration
- **SSH** - Use existing bare-metal or VMs as workers
- **Local** - Install on localhost with intelligent mode detection:
  - **Docker Mode**: When running `docker run raudssus/ocp`, automatically uses SSH to localhost (127.0.0.1) with clear user messaging
  - **Native Mode**: When installed via CPAN, installs directly without SSH (requires sudo)
  - Auto-detects environment and guides user through setup

### Automation

- **CRD-Based Management** - Robocop controller manages nodes via OCPNode/OCPNodeProvider CRDs
- **Rex Framework** - Server provisioning and configuration management (share/Rexfile)
- **Drift Detection** - Spec/Status separation with automatic reconciliation
- **Development Mode** - Built-in registry and image building from source

### Security (Defense in Depth)

- **Two-Tier SSH Keys** - Separate keys for automation vs admin access:
  - **admin-ssh** - Control plane deployment + manual SSH (age+PIN2 encrypted)
  - **robo-ssh** - Worker automation ONLY (age encrypted, memory-only in robocop)
- **PIN-Based Protection** - Two-factor defense:
  - **PIN1** - Encrypts age.key (cluster access)
  - **PIN2** - Encrypts admin-ssh key (control plane deployment)
- **Memory-Only Secrets** - robo-ssh key stored in RAM only (CRIU checkpoints in tmpfs)
- **Control Plane Isolation** - Robocop controller CANNOT access control planes
- **Pure Perl Encryption** - No external tools required via [Crypt::Age](https://metacpan.org/pod/Crypt::Age) and [File::SOPS](https://metacpan.org/pod/File::SOPS)
- **Git-Safe Secrets** - All secrets encrypted in repo, recoverable with PIN1+PIN2

### User Experience

- **Clean Error Messages** - No Perl stacktraces, user-friendly output
- **Auto-Detection** - Intelligent defaults based on environment
- **Docker-First** - Optimized for Docker workflow, works natively too

## Installation

### Docker (recommended)

```bash
docker pull raudssus/ocp:latest

# Initialize new project
docker run --rm -it \
  -v $(pwd):/ocp \
  raudssus/ocp init --hetzner

# Deploy cluster
docker run --rm -it \
  -v $(pwd):/ocp \
  -v ~/.ssh:/home/ocp/.ssh:ro \
  raudssus/ocp apply

# Get kubeconfig (exported to .kube/config in project dir)
docker run --rm -it \
  -v $(pwd):/ocp \
  raudssus/ocp kubeconfig -e

# Copy to ~/.kube/config
cp .kube/config ~/.kube/config

# Or direct to stdout
docker run --rm -it \
  -v $(pwd):/ocp \
  raudssus/ocp kubeconfig > ~/.kube/config

# Alternative: Use alias for convenience
# Linux (use host network to access localhost)
alias ocp='docker run --rm -it --net=host -v $(pwd):/ocp -e TZ=${TZ:-$(cat /etc/timezone 2>/dev/null || echo UTC)} -e LANG raudssus/ocp'

# Mac/Windows (host.docker.internal works automatically)
alias ocp='docker run --rm -it -v $(pwd):/ocp raudssus/ocp'

# Then use it:
ocp status
ocp kubeconfig > ~/.kube/config
```

### CPAN

```bash
cpanm OCP
```

### From Source

```bash
git clone https://github.com/Getty/kubernetes-ocp.git
cd kubernetes-ocp
cpanm --installdeps .
perl -Ilib bin/ocp --help
```

## Quick Start

### Hetzner Cloud
```bash
# Initialize project
ocp init --hetzner

# Deploy cluster
ocp apply

# Get kubeconfig
ocp kubeconfig > ~/.kube/config
kubectl get nodes
```

### Local (Localhost)

#### Using Docker (Recommended)

**Linux:**
```bash
# Use --net=host so container can access host's localhost
docker run --rm --net=host -v $(pwd):/ocp raudssus/ocp init --provider local
cat .ocp/id_ed25519.pub >> ~/.ssh/authorized_keys
docker run --rm --net=host -v $(pwd):/ocp raudssus/ocp apply
docker run --rm --net=host -v $(pwd):/ocp raudssus/ocp kubeconfig > ~/.kube/config
```

**Mac/Windows:**
```bash
# host.docker.internal works automatically
docker run --rm -v $(pwd):/ocp raudssus/ocp init --provider local
cat .ocp/id_ed25519.pub >> ~/.ssh/authorized_keys
docker run --rm -v $(pwd):/ocp raudssus/ocp apply
docker run --rm -v $(pwd):/ocp raudssus/ocp kubeconfig > ~/.kube/config
```

**Important:** On Linux, use `--net=host` to allow Docker to access your host's localhost (127.0.0.1). On Mac/Windows, `host.docker.internal` is available automatically.

**What happens in Docker mode:**

OCP automatically detects it's running in a container and displays:

```
╔═══════════════════════════════════════════════════════════════╗
║  DOCKER MODE: Using SSH to localhost (127.0.0.1)             ║
║                                                               ║
║  OCP is running in Docker and needs SSH access to install     ║
║  Kubernetes on your host system.                             ║
║                                                               ║
║  Make sure you added the SSH key to your host:               ║
║    cat .ocp/id_ed25519.pub >> ~/.ssh/authorized_keys         ║
╚═══════════════════════════════════════════════════════════════╝
```

Clear, transparent communication about what's happening!

**Testing SSH connection:**

```bash
# Test if SSH key works (before running ocp apply)
ssh -i .ocp/id_ed25519 root@127.0.0.1 'echo SSH works!'

# Or for remote hosts
ssh -i .ocp/id_ed25519 root@yourserver.com 'echo SSH works!'
```

If SSH doesn't work, make sure the public key is in `~/.ssh/authorized_keys` on the target host.

#### Using CPAN (System-Wide Installation)

**Option 1: System-wide OCP + Direct Local Install**

```bash
# Install OCP system-wide (as root)
sudo cpanm OCP

# Initialize (as user)
ocp init --provider local

# Deploy (as root - OCP must be in root's PATH)
sudo ocp apply

# Get kubeconfig (as user)
ocp kubeconfig > ~/.kube/config
kubectl get nodes
```

**Option 2: User Installation + SSH to Localhost** (Recommended)

```bash
# Install OCP as user
cpanm OCP

# Use SSH provider to localhost
ocp init --provider ssh --host 127.0.0.1
cat .ocp/id_ed25519.pub >> ~/.ssh/authorized_keys

# Deploy via SSH (works with user's perl environment)
ocp apply

# Get kubeconfig
ocp kubeconfig > ~/.kube/config
```

**Note:** Local provider requires root access to install Kubernetes. Either install OCP system-wide (Option 1) or use SSH to localhost (Option 2) to avoid sudo/environment issues.

### SSH (Existing Server)
```bash
# Initialize with SSH
ocp init --provider=ssh --host=yourserver.com

# Add public key to server
cat .ocp/id_ed25519.pub
# -> Copy to server's ~/.ssh/authorized_keys

# Deploy
ocp apply
```

## Commands

| Command | Description |
|---------|-------------|
| `ocp init` | Initialize project (git, keys, config) |
| `ocp init --hetzner` | Interactive Hetzner token setup |
| `ocp init --provider=ssh --host=HOST` | SSH-only cluster (no cloud) |
| `ocp init --provider=local` | Local single-node cluster (localhost) |
| `ocp apply` | Reconcile cluster to match config |
| `ocp status` | Show cluster status |
| `ocp destroy` | Destroy cluster |
| `ocp kubeconfig` | Output kubeconfig |
| `ocp kubeconfig -e` | Export to ~/.kube/config |
| `ocp dev --build --update` | Build robocop from source and deploy |

## Configuration

OCP uses `ocp.yaml` for cluster specification:

```yaml
name: mycluster

kubernetes:
  distribution: k3s
  version: v1.31.3+k3s1

controlPlanes:
  provider: hetzner
  serverType: cpx21
  location: fsn1
  image: debian-13
  nodes: cp

workers:
  - name: hetzner-workers
    provider: hetzner
    serverType: cpx31
    location: fsn1
    nodes: 2

  - name: bare-metal
    provider: ssh
    nodes:
      - name: gpu-server
        host: 192.168.1.100
      - name: storage-server
        host: 192.168.1.101

ssh:
  privateKey: .ocp/id_ed25519
  publicKey: .ocp/id_ed25519.pub

# Optional: SSL configuration for Let's Encrypt
ssl:
  email: admin@example.com  # Required for Let's Encrypt, optional for self-signed

# Optional: Disable components (default: all enabled)
# notraefik: true  # Disable Traefik ingress controller
# nocert: true     # Disable cert-manager
```

## Core Registry

OCP deploys a registry stack on every cluster:

- **ocp-cache** (NodePort 30500) - Pull-through cache for `docker.io`. Every image pulled once is cached locally. Subsequent pulls are instant and don't count against Docker Hub rate limits.
- **ocp-registry** (NodePort 30501) - Local registry for user images. Push your own images without needing Docker Hub.

RKE2's `registries.yaml` is auto-configured on all nodes to use the cache. containerd tries `localhost:30500` first and falls back to Docker Hub if the cache isn't running yet.

Images can be referenced as `ocp.internal/myapp:latest` — containerd resolves this to the local registry via the mirror config.

```yaml
# Optional: use an external registry cache instead of ocp-cache
registry:
  cache: https://my-proxy.example.com/   # replaces ocp-cache
  name: my.registry                       # default: ocp.internal
```

## SSL & Ingress

OCP uses **Cilium Gateway API** for ingress and **cert-manager** for SSL certificates.

### Automatic SSL with Let's Encrypt

For public clusters with a domain, add your email to enable Let's Encrypt:

```yaml
ssl:
  email: admin@example.com
```

This creates three ClusterIssuers:
- `selfsigned-issuer` - For internal/development certificates
- `letsencrypt-prod` - Production Let's Encrypt certificates
- `letsencrypt-staging` - Staging (for testing, to avoid rate limits)

### Self-Signed Certificates (Local/Internal)

For local or internal clusters, **omit the ssl.email** - OCP will only create the `selfsigned-issuer`:

```yaml
# No ssl block = self-signed certificates only
name: mycluster
```

This protects against accidentally hitting Let's Encrypt rate limits on non-public clusters.

### Example HTTPRoute with SSL

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: myapp
spec:
  parentRefs:
  - name: cilium-gateway
    namespace: kube-system
  hostnames:
  - myapp.example.com
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
    backendRefs:
    - name: myapp
      port: 80
```

### Disable cert-manager

```yaml
nocert: true     # Don't install cert-manager (manual certificates)
```

## Project Structure

```
myproject/
├── ocp.yaml           # Cluster spec (git versioned)
├── secrets.yaml       # Encrypted secrets (SOPS, git versioned)
├── keys.yaml          # SSH keys: admin-ssh + robo-ssh (SOPS encrypted, git versioned)
├── age.key.enc        # PIN1-protected age key (git versioned)
├── kubeconfig.yaml    # Cluster access (SOPS encrypted, git versioned)
├── .gitignore
└── .ocp/              # Local state (gitignored)
    ├── status.yaml    # Runtime status
    ├── age.key        # Age private key (decrypted cache)
    └── age.pub        # Age public key
```

## Security Model (Defense in Depth)

OCP implements a multi-layered security approach with PIN-based protection and key separation.

### Two-Tier SSH Keys

OCP generates separate SSH keys for different purposes:

| Key | Purpose | Encryption | Usage |
|-----|---------|------------|-------|
| **admin-ssh** | Human access | age + PIN2 | Control plane deployment, manual SSH |
| **robo-ssh** | Automation | age only | Worker provisioning (robocop controller) |

**admin-key** is protected with **age + PIN2** (double encryption):
- Used by `ocp apply` to deploy control planes
- Used by `ocp ssh` for manual node access
- Requires PIN2 every time (admin presence required!)
- NEVER touches workers (that's robocop's job)

**robo-key** is protected with **age only** (single encryption):
- Used by robocop controller to provision workers
- Stored in robocop's memory ONLY (never on disk!)
- Injected with `ocp inject-key` (requires PIN2 for approval)
- CANNOT access control planes (not authorized!)

### PIN-Based Protection

- **PIN1** - Encrypts `age.key` (cluster access)
- **PIN2** - Encrypts `admin-ssh` key (control plane deployment)

**Why two PINs?**
- **Defense in Depth** - Repo alone is useless (needs PIN1)
- **Admin Approval** - Control planes require admin presence (PIN2)
- **Team Sharing** - Share repo (git) + PIN1 + PIN2 (via 1Password/Signal)
- **Recovery** - Lost `.ocp/`? → `git clone + PIN1 + PIN2` = recovered!

### Memory-Only Key Storage (Robocop)

Robocop controller keeps robo-ssh key in RAM only:

1. Admin runs `ocp inject-key` (requires PIN2)
2. robo-key injected into robocop memory via TCP socket
3. Robocop creates CRIU checkpoint in `/dev/shm` (tmpfs, RAM)
4. If robocop crashes → restore from checkpoint (no re-injection!)
5. If node reboots → checkpoint lost, need admin to re-inject

**Security benefit:** robo-key NEVER on persistent disk!

### File Structure

```
git-tracked (encrypted):
├── ocp.yaml           # Cluster spec
├── keys.yaml          # admin-ssh + robo-ssh (SOPS encrypted)
├── age.key.enc        # PIN1-protected age key
├── secrets.yaml       # Hetzner token, etc. (SOPS encrypted)
└── kubeconfig.yaml    # Cluster access (SOPS encrypted)

gitignored:
├── .ocp/
│   ├── age.key        # Decrypted (cached)
│   └── age.pub        # Public key
└── .kube/
    └── config         # Decrypted kubeconfig (for kubectl)
```

### Encryption Stack

OCP uses [File::SOPS](https://metacpan.org/pod/File::SOPS) format with [Crypt::Age](https://metacpan.org/pod/Crypt::Age) encryption - **all in pure Perl** (no external tools!).

**Example encrypted file:**

```yaml
hetzner_token: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
sops:
  age:
    - recipient: age1abc...
      enc: |
        -----BEGIN AGE ENCRYPTED FILE-----
        ...
```

### Workflow

```bash
# 1. Initialize (generates keys, prompts for PIN1+PIN2)
ocp init --hetzner

# 2. Deploy control plane (requires PIN2)
ocp apply

# 3. Deploy robocop controller (no PIN needed yet)
ocp deploy robocop

# 4. Inject robo-key (requires PIN2 - admin approval!)
ocp inject-key

# 5. Add workers via CRDs (robocop automates this)
kubectl apply -f worker-pool.yaml
```

### Dev Mode (--nopassword)

For development/testing, you can disable encryption:

```bash
# Single key, no encryption
ocp init --nopassword

# No PIN prompts
ocp apply
```

⚠️ **Only use in dev/testing!** Production should use default secure mode.

## Providers

### Hetzner Cloud

Creates and manages cloud servers via Hetzner Cloud API.

```yaml
controlPlanes:
  provider: hetzner
  serverType: cpx21      # cx22, cpx21, cpx31, etc.
  location: fsn1         # fsn1, nbg1, hel1, ash, hil
  image: debian-13
```

Requires `HETZNER_API_TOKEN` environment variable or encrypted in `secrets.yaml`.

### SSH

Adds existing servers as workers. OCP does not create or destroy these servers.

```yaml
workers:
  - name: bare-metal
    provider: ssh
    nodes:
      - name: gpu-1
        host: 192.168.1.50
      - name: gpu-2
        host: 192.168.1.51
```

## How It Works

1. **Parse** - Load ocp.yaml, decrypt secrets
2. **Diff** - Compare desired spec with actual status
3. **Execute** - Create/delete servers, install k3s, join nodes
4. **Update** - Write new status to .ocp/status.yaml

Each `ocp apply` is idempotent - running it multiple times converges to the desired state.

## Dependencies

- [WWW::Hetzner](https://metacpan.org/pod/WWW::Hetzner) - Hetzner Cloud API
- [Crypt::Age](https://metacpan.org/pod/Crypt::Age) - Age encryption (pure Perl)
- [File::SOPS](https://metacpan.org/pod/File::SOPS) - SOPS format (pure Perl)
- [Moo](https://metacpan.org/pod/Moo) - OOP framework
- [MooX::Cmd](https://metacpan.org/pod/MooX::Cmd) - CLI framework
- [YAML::XS](https://metacpan.org/pod/YAML::XS) - Config parsing

## Docker Image

The Docker image includes:

- Perl 5.42
- kubectl (latest stable)
- All OCP dependencies
- No external crypto tools needed (pure Perl)

```bash
# Build locally
make build

# Run tests
make test
```

## License

Perl 5

## Links

- **Repository**: https://github.com/Getty/kubernetes-ocp
- **CPAN**: https://metacpan.org/pod/OCP
- **Issues**: https://github.com/Getty/kubernetes-ocp/issues
- **Docker Hub**: https://hub.docker.com/r/raudssus/ocp
