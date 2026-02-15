# OCP - Omni Control Plane

Kubernetes cluster management with CRDs and in-cluster automation. Deploy RKE2/K3s clusters with Cilium CNI, manage nodes via Kubernetes-native CRDs.

## Features

### Core

- **RKE2 + K3s Support** - Production-ready RKE2 or lightweight K3s via config
- **Cilium CNI** - eBPF-based networking, kube-proxy replacement, service mesh
- **GPU Support** - Auto-detection and NVIDIA driver installation
- **Single-Node Mode** - Control plane can host workloads (auto-untaint)

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

### Security

- **Encrypted Secrets** - Pure Perl encryption via [Crypt::Age](https://metacpan.org/pod/Crypt::Age) and [File::SOPS](https://metacpan.org/pod/File::SOPS)
- **SSH Key Management** - Automatic key generation and distribution
- **Age Encryption** - No external tools required (pure Perl implementation)

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
  -v $(pwd):/project \
  raudssus/ocp init --hetzner

# Deploy cluster
docker run --rm -it \
  -v $(pwd):/project \
  -v ~/.ssh:/home/ocp/.ssh:ro \
  raudssus/ocp apply

# Get kubeconfig (exported to .kube/config in project dir)
docker run --rm -it \
  -v $(pwd):/project \
  raudssus/ocp kubeconfig -e

# Copy to ~/.kube/config
cp .kube/config ~/.kube/config

# Or direct to stdout
docker run --rm -it \
  -v $(pwd):/project \
  raudssus/ocp kubeconfig > ~/.kube/config

# Alternative: Use alias for convenience
# Linux (use host network to access localhost)
alias ocp='docker run --rm -it --net=host -v $(pwd):/project raudssus/ocp'

# Mac/Windows (host.docker.internal works automatically)
alias ocp='docker run --rm -it -v $(pwd):/project raudssus/ocp'

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
docker run --rm --net=host -v $(pwd):/project raudssus/ocp init --provider local
cat .ocp/id_ed25519.pub >> ~/.ssh/authorized_keys
docker run --rm --net=host -v $(pwd):/project raudssus/ocp apply
docker run --rm --net=host -v $(pwd):/project raudssus/ocp kubeconfig > ~/.kube/config
```

**Mac/Windows:**
```bash
# host.docker.internal works automatically
docker run --rm -v $(pwd):/project raudssus/ocp init --provider local
cat .ocp/id_ed25519.pub >> ~/.ssh/authorized_keys
docker run --rm -v $(pwd):/project raudssus/ocp apply
docker run --rm -v $(pwd):/project raudssus/ocp kubeconfig > ~/.kube/config
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
```

## Project Structure

```
myproject/
├── ocp.yaml           # Cluster spec (git versioned)
├── secrets.yaml       # Encrypted secrets (git versioned)
├── .gitignore
└── .ocp/              # Local state (gitignored)
    ├── status.yaml    # Runtime status
    ├── age.key        # Age private key
    ├── age.pub        # Age public key
    ├── id_ed25519     # SSH private key
    └── id_ed25519.pub # SSH public key
```

## Secrets Management

OCP uses [File::SOPS](https://metacpan.org/pod/File::SOPS) format with [Crypt::Age](https://metacpan.org/pod/Crypt::Age) encryption - all in pure Perl.

```bash
# Token is stored encrypted in secrets.yaml
ocp init --hetzner

# Or set via environment variable
export HETZNER_API_TOKEN="your-token"
```

The `secrets.yaml` file can be safely committed to git - values are encrypted while keys remain readable:

```yaml
hetzner_token: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
sops:
  age:
    - recipient: age1abc...
      enc: |
        -----BEGIN AGE ENCRYPTED FILE-----
        ...
```

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
