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
- **Local** - Treat this machine as the cluster node. Same behaviour as the SSH provider, minus the SSH: provider operations run directly on localhost. Installation itself still goes through Rex over SSH to 127.0.0.1, so the OCP public key has to be in the host's `authorized_keys`.

### Automation

- **CRD-Based Management** - Robocop controller manages nodes via OCPNode/OCPNodeProvider CRDs
- **Rex Framework** - Server provisioning and configuration management (share/Rexfile)
- **Drift Detection** - `ocp status` compares the running cluster against the version manifest and `ocp.yaml`; `ocp apply` runs the upgrade step for whatever can be fixed automatically

### Security (Defense in Depth)

- **Two-Tier SSH Keys** - Separate keys for automation vs admin access:
  - **admin-ssh** - Control plane deployment + manual SSH (age+PIN2 encrypted)
  - **robo-ssh** - Worker automation ONLY (age encrypted, memory-only in robocop)
- **PIN-Based Protection** - Two-factor defense:
  - **PIN1** - Encrypts age.key (cluster access)
  - **PIN2** - Encrypts admin-ssh key (control plane deployment)
- **Memory-Only Secrets** - robo-ssh key stored in RAM only (CRIU checkpoints in tmpfs). The controller side is implemented; the `ocp inject-key` half is currently disabled
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

# Get kubeconfig. In a container ~/.kube/config is the container's home, so
# redirect to your own file instead:
docker run --rm -it \
  -v $(pwd):/ocp \
  raudssus/ocp kubeconfig > ~/.kube/config

# Installed natively, -e merges it into your existing kubeconfig:
ocp kubeconfig -e

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
ocp keys show --purpose admin >> ~/.ssh/authorized_keys
docker run --rm --net=host -v $(pwd):/ocp raudssus/ocp apply
docker run --rm --net=host -v $(pwd):/ocp raudssus/ocp kubeconfig > ~/.kube/config
```

**Mac/Windows:**
```bash
# host.docker.internal works automatically
docker run --rm -v $(pwd):/ocp raudssus/ocp init --provider local
ocp keys show --purpose admin >> ~/.ssh/authorized_keys
docker run --rm -v $(pwd):/ocp raudssus/ocp apply
docker run --rm -v $(pwd):/ocp raudssus/ocp kubeconfig > ~/.kube/config
```

**Important:** On Linux, use `--net=host` to allow Docker to access your host's localhost (127.0.0.1). On Mac/Windows, `host.docker.internal` is available automatically.

**How the local provider works:** it does what the SSH provider does, without the SSH — provider operations (checking the host, uninstalling) run directly on the machine. The Kubernetes installation itself still goes through Rex over SSH to 127.0.0.1, which is why the public key has to be in `~/.ssh/authorized_keys` even for a local cluster.

**Testing SSH connection:**

```bash
# Secure mode (the default): the private half lives in keys.yaml behind PIN2,
# so test through OCP rather than with a key file
ocp ssh --node 127.0.0.1

# Dev mode (--nopassword) keeps its single key on disk
ssh -i .ocp/id_ed25519 root@127.0.0.1 'echo SSH works!'
```

If SSH doesn't work, make sure the right public key is in `~/.ssh/authorized_keys` on the target host: `ocp keys show --purpose admin` in secure mode, `.ocp/id_ed25519.pub` in dev mode.

#### Using CPAN (System-Wide Installation)

**Option 1: System-wide OCP**

```bash
# Install OCP system-wide (as root)
sudo cpanm OCP

# Initialize (as user)
ocp init --provider local

# Deploy (as root - OCP must be in root's PATH)
sudo ocp apply

# Get kubeconfig (as user)
ocp kubeconfig -e
kubectl get nodes
```

**Option 2: User Installation + SSH to Localhost** (Recommended)

```bash
# Install OCP as user
cpanm OCP

# Use SSH provider to localhost
ocp init --provider ssh --host 127.0.0.1
ocp keys show --purpose admin >> ~/.ssh/authorized_keys

# Deploy via SSH (works with user's perl environment)
ocp apply

# Get kubeconfig
ocp kubeconfig > ~/.kube/config
```

**Note:** Both options need root on the target machine to install Kubernetes, and both reach it over SSH to 127.0.0.1. Option 2 keeps OCP itself in your user environment.

### SSH (Existing Server)
```bash
# Initialize with SSH
ocp init --provider=ssh --host=yourserver.com

# Add the ADMIN public key to the server — that is the key every ocp
# command uses, on every provider (in dev mode it is .ocp/id_ed25519.pub)
ocp keys show --purpose admin
# -> Copy to the server's /root/.ssh/authorized_keys

# Deploy
ocp apply
```

> **Upgrading an existing `provider: ssh` cluster?** Its machines were set up
> with `.ocp/id_ed25519.pub` and have never seen the admin key. Append
> `ocp keys show --purpose admin` to `/root/.ssh/authorized_keys` on every
> machine *before* running any further `ocp` command — OCP no longer offers
> the bootstrap key and there is no fallback to it.

## Commands

| Command | Description |
|---------|-------------|
| `ocp init` | Initialize project (git, keys, config) |
| `ocp init --hetzner` | Interactive Hetzner token setup |
| `ocp init --provider=ssh --host=HOST` | SSH-only cluster (no cloud) |
| `ocp init --provider=local` | Local single-node cluster (localhost) |

`ocp init` flags:

| Flag | Purpose |
|------|---------|
| `--name NAME` | Cluster name (default: current directory basename) |
| `--provider NAME` | `hetzner` (default), `ssh`, `local` |
| `--host HOST` | SSH host for `--provider=ssh` |
| `--dist NAME` | Kubernetes distribution: `rke2` (default) or `k3s` |
| `--hetzner` | Prompt for a Hetzner Cloud API token and store it encrypted |
| `--nopassword` | Disable encryption (dev/test only) |
| `--nogit` | Skip git initialization |
| `--force`, `-f` | Overwrite existing files |
| `--service NAME` | Service manager: `systemd` or `none` (default: `none` for local, `systemd` for others) |
| `--ssh-key PATH` | Use existing SSH private key instead of generating one |
| `ocp apply` | Reconcile cluster to match config, fix drift |
| `ocp status` | Show cluster status and drift |
| `ocp destroy` | Destroy cluster |
| `ocp kubeconfig` | Print kubeconfig to stdout |
| `ocp kubeconfig -e` | Merge into `$KUBECONFIG` or `~/.kube/config` |
| `ocp kubeconfig -o FILE` | Write kubeconfig to FILE |
| `ocp version` | Show OCP and component versions |
| `ocp update` | Update cluster components to the bundled versions |
| `ocp update --dry-run` | Show what would be updated |
| `ocp ssh --node NAME\|IP` | SSH into a cluster node (admin key) |
| `ocp node ls` | List OCPNode CRs |
| `ocp node add NAME --role worker` | Add a node via OCPNode CR |
| `ocp node rm NAME` | Drain and remove a node |
| `ocp provider ls` | List OCPNodeProviders |
| `ocp provider add --name N --type hetzner --token-file F` | Register a provider |
| `ocp provider rm NAME` | Remove a provider |
| `ocp deploy-robocop` | Deploy the robocop controller and its CRDs |
| `ocp inject-key` | Inject the robo-ssh key (currently disabled) |
| `ocp hetzner` | List Hetzner servers (debugging) |

## Imperative Node/Provider Management

After `ocp apply`, you can add nodes and providers without editing `ocp.yaml`:

```bash
# Register a provider (token from a file)
ocp provider add --name hetzner-a --type hetzner \
                 --token-file token.txt --default

# Add a worker
ocp node add worker-1 --role worker

# See what you've got
ocp node ls
ocp provider ls

# Remove a node (drain + provider delete + CR cleanup)
ocp node rm worker-1
```

## Configuration

OCP uses `ocp.yaml` for cluster specification:

```yaml
name: mycluster

kubernetes:
  dist: rke2              # or k3s
  version: v1.31.3+rke2r1 # empty = latest

control_planes:
  provider: hetzner
  server_type: cpx21
  location: fsn1
  image: debian-13
  nodes: 1                # 1 CP, or N identical CPs

workers:                  # consumed once by `ocp apply`, translated to OCPNode/OCPNodeProvider CRs
  - name: hetzner-workers
    provider: hetzner
    server_type: cpx31
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
  private_key: .ocp/id_ed25519
  public_key: .ocp/id_ed25519.pub

# Optional: SSL configuration for Let's Encrypt
ssl:
  email: admin@example.com  # Required for Let's Encrypt, optional for self-signed

# Optional: host system settings, detected from your machine on `ocp init`
system:
  timezone: Europe/Berlin
  locale: en_US.UTF-8
  ntp: true

# Optional: GPU stack (enabled by default when a GPU is detected)
gpu:
  enabled: true
  driver: host        # host | operator

# Optional: robocop controller. Defaults to on when a hetzner provider is
# configured, off otherwise.
robocop: true

# Optional: Cilium LB-IPAM. Off by default — its default pool takes over the
# host IP via ARP, which breaks sshd and the API server.
lbipam: false

# Optional: disable components (default: enabled)
# nocert: true     # Disable cert-manager
```

### Spec vs CR workflow

`workers:` in `ocp.yaml` is **input, not state**. On `ocp apply`, OCP
translates each worker pool into `OCPNodeProvider` / `OCPNode` CRs in the
cluster and never reads `ocp.yaml:workers` again. After the first apply,
all node and provider management goes through the CLI subcommands
(`ocp node add/rm`, `ocp provider add/rm`) or directly via `kubectl edit`
on the CRs — the robocop controller reconciles the rest.

## Core Registry

OCP deploys a registry stack on every cluster:

- **ocp-cache** (NodePort 30500) - Pull-through cache for `docker.io`. Every image pulled once is cached locally. Subsequent pulls are instant and don't count against Docker Hub rate limits.
- **ocp-registry** (NodePort 30501) - Local registry for user images. Push your own images without needing Docker Hub.

RKE2's `registries.yaml` is auto-configured on all nodes to use the cache. containerd tries `localhost:30500` first and falls back to Docker Hub if the cache isn't running yet.

Images can be referenced as `ocp.internal/myapp:latest` — containerd resolves this to the local registry via the mirror config.

```yaml
registry:
  cache: https://my-proxy.example.com/   # use this instead of deploying ocp-cache
  upstream: https://mirror.example.com/  # what ocp-cache pulls from (default: Docker Hub)
  name: my.registry                      # local registry hostname (default: ocp.internal)
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
└── .ocp/
    ├── age.key        # Decrypted (cached)
    ├── age.pub        # Public key
    └── status.yaml    # What the cluster actually looks like
```

`ocp kubeconfig -e` merges into `$KUBECONFIG` or `~/.kube/config`; nothing
writes a project-local `.kube/`.

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
ocp deploy-robocop

# 4. Inject robo-key (requires PIN2 - admin approval!)
#    Currently disabled - see the note under Security above.
ocp inject-key

# 5. Add workers as CRs (robocop reconciles them, or the CLI does it directly)
ocp node add worker-1 --role worker
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
control_planes:
  provider: hetzner
  server_type: cpx21      # cx22, cpx21, cpx31, etc.
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

### Drift

OCP pins component versions in the version manifest (`ocp version` prints it)
and writes computed values back into `ocp.yaml`. Reality can move away from
both — someone upgrades Cilium by hand, a server comes back with a new
address, a deploy half-finishes. Both commands look for that:

```bash
$ ocp status
...
=== Drift ===
  [drift] Cilium runs v1.17.0, expected 1.19.2
  [drift] police1 runs v1.30.0+rke2r1, expected v1.31.3+rke2r1

1 of 2 can be reconciled automatically: run 'ocp apply'.
```

What is compared:

| Source of truth | Compared against | Fixed by `ocp apply` |
|-----------------|------------------|----------------------|
| Version manifest | Image tag of the running cilium-operator | yes, runs the Cilium upgrade |
| Version manifest | Image tag of the running cert-manager | yes, runs the cert-manager upgrade |
| Version manifest | Component missing from the cluster | yes, deploys it |
| `kubernetes.version` | kubelet version per node | no — distribution upgrades are manual |
| `control_planes[].public_ip` | recorded node status | no — decide which one is right yourself |

Automatic remediation needs SSH access to the control plane. When the admin
key is not available, `ocp apply` reports the drift and points at
`ocp update --component NAME` instead of failing.

## Docker Image

The Docker image includes:

- Perl 5.42
- All OCP dependencies
- kubectl (latest stable) — for poking at the cluster by hand; OCP itself
  never shells out to it, all Kubernetes access goes through
  [Kubernetes::REST](https://metacpan.org/pod/Kubernetes::REST) and
  [IO::K8s](https://metacpan.org/pod/IO::K8s)
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
