---
name: ocp-usage
description: Use when running the ocp CLI or writing ocp.yaml — commands and flags, the snake_case schema, provider modes, the PIN1/PIN2 model, drift behaviour.
---

# OCP Usage & Workflows

Not on CPAN: `dist.ini` sets `no_cpan = 1`, so `cpanm OCP` finds nothing. Run `ocp` via
the Docker image (`docker pull raudssus/ocp`) or a git checkout with
`cpanm --installdeps .` — see `README.md` for both paths.

## Standard Workflow

```bash
ocp init --hetzner          # init project (keys, config, git); prompts for API token
vim ocp.yaml                # edit spec (snake_case keys — see below)
ocp apply                   # deploy CP; also applies CRDs, providers, robocop
ocp status                  # cluster state + drift report
ocp kubeconfig -e           # merge kubeconfig into $KUBECONFIG / ~/.kube/config
ocp destroy                 # tear down cluster (real servers!)
```

## Hazards

- `ocp apply` and `ocp destroy` create and delete real, paid Hetzner servers and install or uninstall RKE2/K3s on ssh/local machines. Run them only on a project and target you mean to change.
- `ocp status`, `ocp health`, `ocp node ls` and `ocp apply --dry-run` are read-only and never prompt for a PIN.
- Encrypted files (`keys.yaml`, `secrets.yaml`, `age.key.enc`, `kubeconfig.yaml`) are committed; `.ocp/` (decrypted state) stays gitignored.

## Security model in brief

- PIN1 unlocks `age.key.enc` (the outer gate: `keys.yaml`, `secrets.yaml`, `kubeconfig.yaml` all depend on it). PIN2 additionally protects the admin SSH key, which opens every machine the CLI reaches. The robo key (robocop's automation key) is age-only, no PIN2.
- Dev mode (`ocp init --nopassword`) has no PINs; `ocp keys secure` migrates a project to secure mode later.
- A lost PIN1 or PIN2 has no recovery inside OCP: read references/pin-recovery.md before improvising.

## Where the detail lives

Read the reference file that matches the task; each is one level deep and self-contained.

- `references/commands.md` — read when running or changing any `ocp` command: flags, exit codes, confirmations, `--json` output (`status`, `health`, `node ls`), `node add/rm/trust-host`, `provider`, `keys` (`show`, `authorized-keys`, `secure`, `add-pin2`, `recipients`, `operator`), `deploy-image`, `inject-key`, the dash/underscore flag rule, and how `ocp apply` deploys robocop and its `security_level`.
- `references/schema.md` — read when writing or validating `ocp.yaml`: every key, `node_ip`, `network:` (pod_cidr, lb_pool, l2), validation rules and limits, `gpu.amd`.
- `references/providers.md` — read when choosing or debugging a provider mode: Hetzner, SSH (existing servers, node naming, worker by name), Local.
- `references/security-model.md` — read for the full PIN1/PIN2 model: key tiers, who gets which key, the two-key rule for ssh workers, operator/Leitstand identity, which commands prompt for PINs, `--pins-stdin`, dev mode.
- `references/pin-recovery.md` — read when a PIN is lost, an admin key is locked out or must be replaced, or `keys.yaml` has an admin key without PIN2.
- `references/reconcile-drift.md` — read when `ocp apply` reconciles an existing cluster: drift detection and remedies, hash-based components, the CR-first worker flow.

## File Layout

```
ocp.yaml              # spec (git-tracked)
keys.yaml             # encrypted SSH keys (git-tracked)
secrets.yaml          # encrypted secrets (git-tracked)
age.key.enc           # PIN1-protected age key (git-tracked)
.sops.yaml            # optional: further age recipients (ocp keys recipients)
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

For ssh providers the first CP is named after the host instead. On RKE2,
`control_planes[1..]` join as `police2`, `police3`, … (Pending OCPNodes with
role control-plane, k8). k3s builds only police1 and warns on STDERR.
