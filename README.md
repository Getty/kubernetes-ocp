# OCP - Omni Control Plane

Kubernetes cluster management with CRDs and in-cluster automation. Deploy RKE2/K3s clusters with Cilium CNI, manage nodes via Kubernetes-native CRDs.

## Features

- **RKE2 + K3s Support** - Production-ready RKE2 or lightweight K3s via config
- **Cilium CNI** - eBPF-based networking, kube-proxy replacement, service mesh
- **GPU Support** - Auto-detection and NVIDIA driver installation
- **CRD-Based Management** - Robocop controller manages nodes via OCPNode/OCPNodeProvider CRDs
- **Multiple Providers** - Hetzner Cloud for managed servers, SSH for existing machines
- **Rex Automation** - Server provisioning via Rex framework
- **Encrypted Secrets** - Pure Perl encryption via [Crypt::Age](https://metacpan.org/pod/Crypt::Age) and [File::SOPS](https://metacpan.org/pod/File::SOPS)
- **Spec/Status Separation** - Clean state management with drift detection
- **Development Mode** - Built-in registry and image building from source

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
alias ocp='docker run --rm -it -v $(pwd):/project raudssus/ocp'
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
```bash
# Initialize local cluster
docker run --rm -v $(pwd):/project raudssus/ocp init --provider local

# Add SSH key to localhost (required for Docker mode)
cat .ocp/id_ed25519.pub >> ~/.ssh/authorized_keys

# Deploy (Docker → SSH → localhost)
docker run --rm -v $(pwd):/project raudssus/ocp apply

# Get kubeconfig
docker run --rm -v $(pwd):/project raudssus/ocp kubeconfig > ~/.kube/config
kubectl get nodes
```

**Note:** When running in Docker, OCP uses SSH to connect to your host system (127.0.0.1) to install Kubernetes. This is clearly indicated during deployment.

#### Using CPAN (Advanced)
```bash
# Install OCP via CPAN
cpanm OCP

# Initialize local cluster
ocp init --provider local

# Deploy directly (no SSH, requires root)
sudo ocp apply

# Get kubeconfig
ocp kubeconfig > ~/.kube/config
kubectl get nodes
```

**Note:** When running natively (not in Docker), OCP installs Kubernetes directly without SSH.

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
