---
name: ocp-core
description: OCP architecture and invariants — CLI vs robocop split, stack decisions (Cilium, no Helm), spec/status separation, module map, CRDs, reconciliation states. Load for any work on lib/, bin/, or share/ (templates + Rexfile).
---

# OCP Core — Architecture & Invariants

OCP (Omni Control Plane) is a Perl CLI managing Kubernetes clusters (RKE2/K3s),
shipped as a CPAN distribution with Docker as the primary install method.

## The split: ocp CLI vs robocop

```
ocp CLI (extern: Laptop/CI)              robocop (im Cluster)
────────────────────────────             ─────────────────────────────
Bootstrap Control Plane(s), EINMALIG     Deployment in ocp-system
Installiert RKE2/K3s, Cilium, Stack      Watched OCPNode/OCPNodeProvider CRDs
Deployt robocop + CRDs                   Reconciliation: Provision→Install→Ready
```

Naming (RoboCop theme): CLI `ocp`, Controller `robocop`, Control Planes
`police1`, `police2`, … ("Serve the public trust").

**robocop is opt-in and default off**: `robocop: true|false` in ocp.yaml,
auto-true when any hetzner provider is configured.

## Stack decisions — and why

- **RKE2/K3s** — both supported as distribution (`--dist`).
- **Cilium does almost everything**: CNI, Network Policies (L3/L4/L7),
  kube-proxy replacement (eBPF), WireGuard encryption, Ingress via Gateway API,
  service mesh features, Hubble observability, DNS policies. **No Istio** —
  overkill, eats RAM. No Canal.
- **No Helm as default.** Kustomize (built into kubectl), plain manifests from
  GitHub releases, `helm template` only for build-time rendering. Helm is not
  forbidden — just never the default path.

## Hard invariants

1. **No kubectl in code — ever.** Every K8s access goes through
   Kubernetes::REST / IO::K8s (Server-Side Apply patterns: skill `k8s`).
   kubectl exists in the Docker image for human debugging only; no code path
   may shell out to it.
2. **Docker-first toolchain.** `carton install`, `cpm`, snapshot regeneration
   and running `ocp` itself happen inside the Docker image, never on the host
   (`make snapshot`, `make docker-test`). Host runs produce inconsistent
   results and pollute host CPAN state. Missing a Docker-ized Make target?
   Add one — don't fall back to host execution.
3. **cpanfile is the source of truth** for dependencies. Getty-authored deps
   are pinned (WWW::Hetzner, Crypt::Age, File::SOPS, IO::K8s,
   Kubernetes::REST, Net::Async::Kubernetes, Rex::Interface::Connection::LibSSH).
4. **Known debt:** `Net::Async::Kubernetes` is declared but unused — robocop
   polls in a loop instead of watching, and `ocp inject-key` (needs
   `port_forward`) is disabled. Either redeem or drop; don't silently build on
   the assumption it is wired up.

## Spec vs Status separation

- **ocp.yaml (spec, git-versioned)** — everything the user *could* have set.
  Computed defaults flow back and are pinned after first apply (e.g. a Hetzner
  IP that wasn't specified). Written by `OCP::Config`.
- **.ocp/status.yaml (transient)** — only what the user could *not* set:
  provider-internal IDs, join tokens, kubeconfig, phase/timestamps.
- **Drift detection (`OCP::Drift`)** compares pinned spec values and component
  versions against the live cluster. `ocp apply` runs the Rex task for every
  drift entry with a `remedy` (Cilium/cert-manager upgrades); distribution
  upgrades and moved IPs are report-only — a human decides.

Minimal spec — ocp.yaml keys are **snake_case, no camelCase aliases** (plain
`YAML::XS::LoadFile`, no normalization). A `workers:` list is still read, but
apply turns it into Pending OCPNode CRs (CR-first) rather than deploying
directly:

```yaml
name: mycluster
control_planes:
  provider: hetzner
  location: fsn1
  server_type: cx32
  nodes: 1        # → police1
robocop: true     # optional; default false, auto-true with a hetzner provider
```

## Module map

| Module | Owns |
|---|---|
| `OCP::Config` | spec/status split, validation, GPU config |
| `OCP::Secrets` / `OCP::Keys` / `OCP::Password` | SOPS/age wrapper; two-tier SSH keys (admin-key + robo-key); PIN prompting, AES-256-GCM |
| `OCP::SSH` | SSH connections + remote commands (LibSSH) |
| `OCP::Rex` | Rex task executor (RKE2/K3s install via share/Rexfile) |
| `OCP::Hetzner` | Hetzner Cloud API helper (WWW::Hetzner) |
| `OCP::Provider` | provider factory; `->from_cr` builds from an OCPNodeProvider CR (resolves Secret refs) |
| `OCP::Provider::Hetzner` | server lifecycle, idempotent, label-based |
| `OCP::Role::Provider::ExistingHost` | shared behavior of non-provisioning providers; consumers supply `resolve_host`, `host_reachable`, `run_command` |
| `OCP::Provider::SSH` / `::Local` | ExistingHost via SSH / localhost (install still runs via Rex/SSH on 127.0.0.1) |
| `OCP::Kubernetes` | typed K8s helpers (node status, GPU detection) |
| `OCP::Kubeconfig` | rename/merge kubeconfig (`ocp kubeconfig -e`) |
| `OCP::Drift` / `OCP::Versions` | drift detection; version manifest incl. GPU stack |
| `OCP::Node` | trigger-neutral node reconcile state machine, used by both `ocp apply` (one-shot) and robocop (watch loop); owns lease mechanics |
| `OCP::K8s` (+ `::OCPNode`, `::OCPNodeProvider`) | registers the CRDs as IO::K8s typed classes on a Kubernetes::REST api |
| `OCP::Robocop` (+ `::Controller`) | in-cluster controller + reconciliation logic |

## CRDs (ocp.internal/v1, namespace ocp-system)

**OCPNodeProvider** — infrastructure provider config:

```yaml
spec:
  type: hetzner            # or: ssh
  hetzner:
    tokenSecretRef: { name: hetzner-api-token }
    location: fsn1
    serverType: cx32
    image: debian-13
```

**OCPNode** — a single node:

```yaml
spec:
  role: worker             # or: control-plane
  providerRef: hetzner-fsn1
  serverType: cx23         # override
  gpu: false
status:
  phase: Ready
  providerId: "12345678"
  publicIP: 1.2.3.4
```

Reconciliation states: `Pending → Provisioning → Installing → Joining → Ready`,
plus `Failed` (retry with backoff). Manifests live in `share/robocop/`
(crds/, rbac.yaml, deployment.yaml, kustomization.yaml).

## Repo layout

```
bin/ocp, bin/robocop       # entry points
lib/OCP/…                  # modules (map above)
share/                     # templates, Rexfile, nfd/, gpu-operator/, patches/, bin/
share/robocop/             # CRDs, RBAC, deployment (kustomize root)
t/NN-topic.t               # flat, numbered, mock-based tests
xt/smoke.sh                # real-machine smoke test (make smoke) — destructive
```

Related sibling distributions (each its own repo + board):
`p5-www-hetzner`, `p5-crypt-age`, `p5-file-sops`, `p5-net-async-kubernetes`,
`io-k8s-p5`, `kubernetes-rest`.

CLI command surface, provider modes, PIN1/PIN2 security model, project file
layout (ocp.yaml, keys.yaml, .ocp/): skill `ocp-usage`. Server-Side Apply and
hash-reconciliation patterns: skill `k8s`.
