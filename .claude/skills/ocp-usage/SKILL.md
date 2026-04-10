---
model: sonnet
---

# OCP Usage & Workflows

## Standard Workflow

```bash
ocp init                    # Initialize project (keys, config, git)
ocp apply                   # Deploy control plane
ocp status                  # Check cluster state
ocp kubeconfig -e           # Export kubeconfig
ocp deploy-robocop          # Deploy in-cluster controller
ocp inject-key              # Give robocop the automation SSH key
ocp destroy                 # Tear down cluster
```

## Provider Modes

### Hetzner Cloud
```bash
ocp init --hetzner          # Interactive: prompts for API token
ocp init --provider hetzner # Same, non-interactive
```
- Creates servers via Hetzner API
- Uploads SSH key, creates server with labels
- Labels: `ocp-cluster=<name>`, `ocp-role=control-plane`, `ocp-node=police1`

### SSH (Existing Servers)
```bash
ocp init --provider ssh --host myserver.com
```
- No server creation — uses existing host
- Node name derived from hostname (myserver.com -> myserver)
- Destroy: runs `rke2-uninstall.sh` or `k3s-uninstall.sh`

### Local
```bash
ocp init --provider local
```
- Installs directly on localhost (requires root)
- No SSH, uses `OCP::Local` module
- Good for single-node dev clusters

## Security Model (PIN1/PIN2)

### Default (Secure) Mode
- **age.key**: Master encryption key (encrypted with PIN1 -> age.key.enc)
- **keys.yaml**: Contains two SSH keys (encrypted with age)
  - **robo-key**: Automation only, age-encrypted, no PIN2
  - **admin-key**: Control plane access, age+PIN2 encrypted

### Dev Mode (`--nopassword`)
- Single SSH key in `.ocp/id_ed25519` (unencrypted)
- No PIN prompts
- For local development only

### Key Usage
- `ocp apply` requires admin-key (PIN2 prompt)
- `ocp ssh` requires admin-key (PIN2 prompt)
- robocop controller uses robo-key (injected once, kept in memory)
- robo-key CANNOT access control planes

## Config Structure (ocp.yaml)

```yaml
name: mycluster
k8s:                          # or "kubernetes"
  dist: rke2                  # or k3s
  version: ''                 # empty = latest
cps:                          # or "controlPlanes"
  provider: hetzner
  serverType: cx32
  location: fsn1
  image: debian-13
workers:
  - name: pool1
    provider: hetzner
    serverType: cpx21
    nodes: 3
ssh:
  privateKey: .ocp/id_ed25519
  publicKey: .ocp/id_ed25519.pub
system:
  timezone: Europe/Berlin
  locale: de_DE.UTF-8
  ntp: true
registry:
  cache: ''                   # external docker.io cache
  upstream: ''                # external local registry
  name: ocp.internal          # internal registry name
ssl:
  email: admin@example.com    # Let's Encrypt email
gpu:
  enabled: true               # auto-detect (default)
  driver: host                # host (Rex installs) or operator
```

## Reconciliation

Running `ocp apply` on an existing cluster (kubeconfig.yaml present) enters reconciliation mode:
1. Checks each component's hash against `.ocp/deployed.yaml`
2. Re-applies only changed components
3. Components checked: registry, NFD, GPU Operator, cert-manager

## File Layout

```
ocp.yaml              # Spec (git-tracked)
keys.yaml             # Encrypted SSH keys (git-tracked)
secrets.yaml          # Encrypted secrets (git-tracked)
age.key.enc           # PIN1-protected age key (git-tracked)
kubeconfig.yaml       # Encrypted kubeconfig (git-tracked)
.ocp/                 # Local state (gitignored)
  age.key             # Decrypted age key
  age.pub             # Public key
  status.yaml         # Runtime status
  deployed.yaml       # Component hashes
  id_ed25519          # SSH key (dev mode only)
.kube/
  config              # Decrypted kubeconfig (for kubectl)
```

## Naming Convention (RoboCop Theme)

| Component | Name | Description |
|-----------|------|-------------|
| CLI | `ocp` | Omni Control Plane |
| Controller | `robocop` | Kubernetes Operator |
| Control Planes | `police1`, `police2`, ... | "Serve the public trust" |
