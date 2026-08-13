---
name: ocp-usage
description: OCP CLI usage — commands and flags, ocp.yaml schema (snake_case!), provider modes, PIN1/PIN2 security model, reconciliation/drift behavior from the user's side, file layout. Architecture and internals live in ocp-core.
---

# OCP Usage & Workflows

Verified against the code 2026-08-12 (OCP::Config, OCP::Cmd::*, OCP::Drift), including
live runs of each command in the shipped Docker image (not `--help` text or source
inspection alone — see the note on dash/underscore flags below, where `--help` output
alone would have been actively misleading).

## Standard Workflow

```bash
ocp init --hetzner          # init project (keys, config, git); prompts for API token
vim ocp.yaml                # edit spec (snake_case keys — see below)
ocp apply                   # deploy CP; also applies CRDs, providers, robocop
ocp status                  # cluster state + drift report
ocp kubeconfig -e           # merge kubeconfig into $KUBECONFIG / ~/.kube/config
ocp destroy                 # tear down cluster (real servers!)
```

`ocp apply` deploys robocop itself when `robocop` is enabled and workers exist;
if robocop isn't ready within 60s, apply falls back to CLI-side reconcile via
`OCP::Node`. `ocp deploy-robocop` still exists as a manual/standalone step.
`ocp inject-key` is **disabled** — it dies with an explanation (the old
kubectl port-forward path was removed; pending reimplementation via
Kubernetes::REST port_forward).

## Command Reference

`MooX::Options::Role` normalizes hyphens to underscores when matching an incoming flag
against a declared option name, so `--dry-run` and `--dry_run` both work for the same
option — `--help` only ever prints one spelling, which is not evidence the other is
rejected. The docs below use the hyphenated form throughout, matching `xt/smoke.sh` and
`README.md`. **One real exception**: `ocp node add --no_wait` must be underscored. A
leading `--no-` is peeled off *before* the dash/underscore substitution, as a
Getopt::Long-style negation marker (`^(\-+)(no\-)?(.*)$`) — so `--no-wait` is parsed as
"negate a boolean option called `wait`", which doesn't exist, and dies with `Unknown
option: wait`. `--no_wait` has no literal `no-` for that regex to match, so it goes
straight through as the option name itself.

- `ocp init` — project init (keys, config, git)
  - `--hetzner` — interactive Hetzner token setup (NOT the same as
    `--provider hetzner`, which skips the token prompt)
  - `--provider hetzner|ssh|local` — **default is hetzner**, matching the
    spec-wide default in `OCP::Config` (an absent provider reads as hetzner
    everywhere else too). A bare `ocp init` therefore stays offline and ends
    with a reminder that a token is still needed before `ocp apply`; the
    token itself is the separate `--hetzner` step. `--provider ssh` dies
    without `--host`.
  - `--host HOST` — SSH host (for provider ssh)
  - `--name` — cluster name · `--nogit` — skip git init
  - `--nopassword` — dev mode without PINs
  - `--dist rke2|k3s` — distribution
  - `--ssh-key PATH` — reuse an existing private key (copied to `.ocp/`)
  - `--service systemd|none` — for provider local
  - `--force` — overwrite existing config
- `ocp apply [--only control-planes|workers|NODE] [--dry-run]` — deploy/reconcile
- `ocp status` — cluster state incl. drift report
- `ocp update [--dry-run] [--component NAME] [--force]` — update components;
  refuses to run without `status.ocpVersion` (stamped by apply)
- `ocp destroy [--force] [--keep-status]` — tear down; `--force` skips the
  confirmation prompt; deletes status.yaml + kubeconfig.yaml afterwards
  unless `--keep-status`
- `ocp kubeconfig` — stdout; `-e` merge (with backup, other clusters kept),
  `-o FILE` write to file, `--refresh` re-fetch from cluster
- `ocp version` — versions (needs the ocpVersion stamp for "deployed")
- `ocp ssh --node <name|ip>` — SSH to nodes (admin-key, PIN2)
- `ocp deploy-robocop` — robocop + CRDs standalone
- `ocp inject-key` — disabled (dies with explanation)
- `ocp hetzner [--list] [--label KEY=VAL]` — Hetzner debugging
- `ocp node add NAME --role ROLE [--provider NAME] [--host HOST]
  [--server-type TYPE] [--location LOC] [--image IMG] [--gpu] [--no_wait]`
  — create an OCPNode CR (note: `--no_wait`, underscore — see above)
- `ocp node rm NAME` — drain + remove (OCP::Node->teardown)
- `ocp node ls` — list OCPNode CRs (name, role, phase, provider, IP, age)
- `ocp provider add --name NAME --type hetzner --token-file FILE
  [--location LOC] [--server-type TYPE] [--image IMG] [--default]`
  — OCPNodeProvider CR + Secret
- `ocp provider rm NAME` — blocked while OCPNodes reference it
- `ocp provider ls` — list providers with reference counts

## ocp.yaml Schema — snake_case, no aliases

There is NO key normalization (plain `YAML::XS::LoadFile`) and NO camelCase
aliases: `controlPlanes:`/`cps:`/`k8s:` are **not** read. Canonical keys:

```yaml
name: mycluster
kubernetes:
  dist: rke2                # or k3s
  version: ''               # empty = fall back to the OCP::Versions manifest
                            # (NOT "latest upstream")
control_planes:             # Hash, Hash + "nodes: N", or Array of hashes
  provider: hetzner
  server_type: cx32
  location: fsn1
  image: debian-13
  # host / service / network_interface / public_ip (pinned after apply)
workers:                    # optional pools; apply turns each entry into
  - name: pool1             # Pending OCPNode CRs (CR-first), reconciled by
    provider: hetzner       # robocop or the CLI fallback
    server_type: cpx21
    nodes: 3
ssh:
  private_key: .ocp/id_ed25519
  public_key: .ocp/id_ed25519.pub
robocop: true               # default false; auto-true when a hetzner
                            # provider is configured
lbipam: true                # opt-in LB-IPAM + L2 announcements (ARP takeover
                            # on the node network — know what you're doing)
nocert: false               # skip cert-manager stack
registry:
  cache: ''                 # external docker.io pull-through cache
  upstream: ''              # external local registry
  name: ocp.internal        # internal registry name (default)
ssl:
  email: admin@example.com  # ACME/Let's Encrypt (cert-issuers)
system:
  timezone: Europe/Berlin   # detected from host at init
  locale: de_DE.UTF-8
  ntp: true
gpu:
  enabled: true             # default true; false skips hardware detection
                            # and the GPU Operator entirely
  driver: host              # host (Rex installs the driver) or operator
                            # (the operator's driver DaemonSet)
  toolkit: true             # default true; NVIDIA container toolkit via the
                            # operator — set false on hosts that already
                            # have it (e.g. DGX vendor images)
```

## Provider Modes

### Hetzner Cloud
- `ocp init --hetzner` prompts for the API token; `--provider hetzner` alone
  does not.
- Servers created via API, idempotent by labels: `ocp-cluster=<name>`,
  `ocp-role=control-plane|worker`, `ocp-node=<nodename>`.

### SSH (existing servers)
- `ocp init --provider ssh --host myserver.com` — `--host` is required.
  Hetzner, not ssh, is the init default, so `--provider ssh` without
  `--host` dies immediately.
- Node name = hostname up to the first dot (`avatar.conflict.industries` →
  `avatar`); same rule for ssh worker pools.
- Destroy runs `rke2-uninstall.sh || k3s-uninstall.sh` plus cleanup of
  `/usr/local/bin/cilium`, `/opt/cni`, `/run/k3s`.

### Local
- `OCP::Provider::Local`: provider operations run locally (open3), but
  `resolve_host` returns `127.0.0.1` so the actual install still goes through
  the normal Rex/SSH path. `--service systemd|none` controls service setup.

## Security Model (PIN1/PIN2)

- **age.key** master key, encrypted with PIN1 → `age.key.enc`.
- **keys.yaml** two-tier: **robo-ssh** (automation) age-only, no PIN2;
  **admin-ssh** (control-plane access) age + PIN2 double-encrypted.
- robo-key cannot reach control planes — by convention; currently it is never
  deployed at all (inject-key disabled).
- **PIN2 prompts**: `ocp apply` (secure mode) and `ocp ssh`. PIN1 prompts
  whenever only `age.key.enc` exists. destroy/update/node do not prompt.
- **Dev mode (`--nopassword`)**: single unencrypted key `.ocp/id_ed25519`, no
  PIN prompts — but a plain age.key is still generated and
  **kubeconfig.yaml stays encrypted even in dev mode**. Apply detects dev
  mode by the absence of keys.yaml.

## Reconciliation & Drift

`ocp apply` with an existing `kubeconfig.yaml` enters reconcile mode:

1. **Drift detection first** (`OCP::Drift`): Cilium and cert-manager version
   drift carry Rex remedies (`upgrade_cilium`/`upgrade_cert_manager`) and are
   fixed automatically; distribution drift and moved pinned IPs are
   report-only — a human decides. `ocp status` shows the same drift report.
2. **Hash-based components** (`.ocp/deployed.yaml`, MD5 of generated
   manifests): registry, NFD, GPU operator. cert-manager is tracked by
   component version, not manifest hash.
3. Apply stamps `status.ocpVersion` at the end — `ocp update` and
   `ocp version` depend on it.

Fresh bootstrap additionally deploys: Cilium Gateway API, cert-issuers
(selfsigned + ACME with `ssl.email`), `registry.local` DNS entry in CoreDNS,
and LB-IPAM (only when `lbipam: true`).

Worker flow is CR-first: apply always applies CRDs, creates an
OCPNodeProvider + Secret per configured provider (`<type>-default`), an
observational OCPNode for the CP, and Pending OCPNodes for worker pool
entries; robocop (or the CLI fallback) reconciles them
Pending→Provisioning→Installing→Joining→Ready. Details: skill `ocp-core`,
decision history: `docs/adr/`.

## File Layout

```
ocp.yaml              # spec (git-tracked)
keys.yaml             # encrypted SSH keys (git-tracked)
secrets.yaml          # encrypted secrets (git-tracked)
age.key.enc           # PIN1-protected age key (git-tracked)
kubeconfig.yaml       # encrypted kubeconfig (git-tracked, even in dev mode)
.ocp/                 # local state (gitignored)
  age.key / age.pub   # decrypted/public age key
  status.yaml         # runtime status incl. ocpVersion stamp
  deployed.yaml       # component hashes
  id_ed25519          # SSH key (dev mode only)
```

There is no project-local `.kube/` — `ocp kubeconfig -e` merges into
`$KUBECONFIG` / `~/.kube/config`. Init's generated `.gitignore` only ignores
`.ocp/` (a stray `.kube/` entry it used to write has been removed).

## Naming (RoboCop Theme)

| Component | Name |
|-----------|------|
| CLI | `ocp` |
| Controller | `robocop` |
| First control plane | `police1` (hostname `<cluster>-police1`) |

For ssh providers the CP is named after the host instead. Note: apply
currently only deploys `control_planes[0]` — police2+ (multi-CP) is not
implemented yet.
