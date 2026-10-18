---
name: ocp-usage
description: Use when running the ocp CLI or writing ocp.yaml — commands and flags, the snake_case schema, provider modes, the PIN1/PIN2 model, drift behaviour.
---

# OCP Usage & Workflows

Verified against the code 2026-08-16 (OCP::Config, OCP::Cmd::*, OCP::Drift, OCP::Keys,
OCP::Secrets, OCP::ClusterKey), including live runs of each command in the shipped
Docker image (not `--help` text or source inspection alone — see the note on
dash/underscore flags below, where `--help` output alone would have been actively
misleading).

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

The robocop image is amd64 only: with only `cax*` (ARM) control planes `ocp apply` warns (pod stays Pending).
`ocp apply` deploys robocop itself when `robocop` is enabled and workers exist;
if robocop isn't ready within 60s, apply falls back to CLI-side reconcile via
`OCP::Node`. `ocp deploy-robocop` still exists as a manual/standalone step.

The robocop credential story is `robocop.security_level`: `secret` (default) |
`secret_approved` | `inject`. Under `inject`, the private robo key is never
stored in the cluster — `ocp deploy-robocop` writes only its public half into
the Secret, and `ocp inject-key [--timeout N]` (`OCP::Cmd::InjectKey`; PIN1 to
decrypt, PIN2 as the admin approval) sends the private key over a Kubernetes
port-forward straight into the running robocop pod's memory
(`OCP::Robocop::KeyInjection`). Nothing is checkpointed: after a pod restart
the key is gone, robocop is not Ready, and every OCPNode in `Pending`,
`Provisioning` or `Installing` carries condition `SSHKeyAvailable=False`
(reason `KeyInjectionRequired`) until `ocp inject-key` runs again.

## Command Reference

`MooX::Options::Role` normalizes hyphens to underscores when matching an incoming flag
against a declared option name, so `--dry-run` and `--dry_run` both work for the same
option — `--help` only ever prints one spelling, which is not evidence the other is
rejected. The docs below use the hyphenated form throughout, matching `xt/smoke.sh` and
`README.md`. **The one shape that never works is a leading `--no-`**: it is peeled off
*before* the dash/underscore substitution, as a Getopt::Long-style negation marker
(`^(\-+)(no\-)?(.*)$`), so `--no-foo` is read as "negate a boolean option called `foo`"
and dies with `Unknown option: foo` unless such an option exists. Every negative flag in
this CLI is therefore spelled without the dash — `--nogit`, `--nopassword`, `--nowait`.
`ocp node add` still accepts `--no_wait` as an alias for `--nowait`.

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
  - `--name` — cluster name · `--nogit` — skip git init (`.gitignore` with `.ocp/` is still written; `.ocp/` also ignores itself)
  - `--nopassword` — dev mode without PINs (not one-way: `ocp keys secure`
    switches the project later)
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
- `ocp inject-key [--timeout SECONDS]` — hand the robo private key to a
  running robocop pod for `robocop.security_level: inject` (PIN1 + PIN2;
  default timeout 30s)
- `ocp hetzner [--list] [--label KEY=VAL]` — Hetzner debugging
- `ocp node add NAME --role ROLE [--provider NAME] [--host HOST]
  [--server-type TYPE] [--location LOC] [--image IMG] [--gpu]
  [--label K=V]... [--taint K=V:Effect]... [--nowait]`
  — create an OCPNode CR (`--no_wait` is kept as an alias, see above)
- `ocp node rm NAME` — drain + remove (OCP::Node->teardown)
- `ocp node ls` — list OCPNode CRs (name, role, phase, provider, IP, age)
- `ocp provider add --name NAME --type hetzner --token-file FILE
  [--location LOC] [--server-type TYPE] [--image IMG] [--default]`
  — OCPNodeProvider CR + Secret
- `ocp provider rm NAME` — blocked while OCPNodes reference it
- `ocp provider ls` — list providers with reference counts
- `ocp keys show [--purpose admin|automation|general] [--name NAME]` — print
  a **public** key from `keys.yaml` (see "PIN Loss & Admin-Key Rotation"
  below — there is no rotate/add subcommand for the admin/robo SSH keys)
- `ocp keys authorized-keys [--purpose all|admin|automation|operator]` — the
  `authorized_keys` lines a machine needs (k209): default `all` = admin +
  robo (an ssh worker) + every operator key (k216, optional — none is fine),
  `--purpose admin` for a control plane. STDOUT only key lines, names on
  STDERR; PIN1 at most, never PIN2; finds every wanted key before printing
  any (missing admin/robo, or `--purpose operator` with none → error, nothing
  printed). Dev mode prints `.ocp/id_ed25519.pub` for any purpose but
  `operator` (refused: no operators in dev mode).
- `ocp keys secure [--drop-bootstrap]` — dev mode → secure mode (k96).
  Order is the point: PIN1 (unless `age.key.enc` exists) + PIN2 set, admin +
  robo keys staged in `.ocp/keys.yaml.pending` (gitignored), both publics
  appended (blob-dedup) to `/root/.ssh/authorized_keys` on every machine over
  the bootstrap key, admin key tested alone on each — only if ALL pass:
  `age.key.enc` + staging → `keys.yaml` (SOPS re-encrypted for its
  recipients). Machines = OCPNodes (`status.publicIP || spec.host`, any role)
  + ocp.yaml CPs with an address, deduped by name/address; a kubeconfig whose
  API does not answer aborts before any prompt; pool hosts without OCPNode are
  only named. A failed host → STDERR, exit 1, still dev mode, staging kept; a
  re-run reuses it (PIN2 once). After the switch: Hetzner re-upload under
  `ocp-<name>-admin/-robo` (ensure replaces dev mode's bootstrap key there),
  robocop Secret via `robocop_step` with the run's admin key (no 2nd PIN2),
  running robocop pods deleted to re-read env. `--drop-bootstrap` removes the
  bootstrap blob's lines with the admin key, only where it works; never
  deletes `.ocp/id_ed25519`. Already secure: `[ok]`, or only the drop step.
- `ocp keys recipients ls|add AGE1|rm AGE1` — age recipients of the SOPS
  files (k212): project key always, plus the governing `.sops.yaml`'s rule.
  add/rm rewrite the project's own `.sops.yaml` (never one further up — edit
  that by hand, then add/rm re-encrypts) and re-encrypt keys/secrets/
  kubeconfig.yaml via File::SOPS rotate (PIN1). rm prints on STDERR what to
  rotate (secrets.yaml entries, kubeconfig admin creds; git history stays
  readable for the removed one). Inner age layer of keys.yaml private keys
  stays project-key-only.
- `ocp keys operator add --name NAME --ssh-pubkey FILE --age AGE1` /
  `ocp keys operator rm NAME` — a Leitstand (operator) that runs `ocp apply`
  unattended (k216). Run where the project key is (PIN1, PIN2 for the admin
  key; an operator/other `SOPS_AGE_KEY_FILE` identity is refused). add:
  name `[a-z0-9][a-z0-9-]*` (≤63), checks before any PIN; SSH public key onto
  every machine (`OCP::Role::Cmd::Machines`, same walk as `keys secure`) with
  the admin key FIRST — a failed host → STDERR, exit 1, nothing recorded,
  re-run idempotent; then `.sops.yaml` gets AGE1 (external `.sops.yaml` →
  stop before any machine, same message as `recipients add`) and keys.yaml
  an entry `{name, type, purpose: operator, public, age, created,
  deprecated: 0}` with NO `private` (`OCP::Keys::add_public_key`), files
  re-encrypted. Same add again = ok; same name + other keys, a taken SSH key
  or age recipient, the project key as AGE1 → error. rm: blob off every
  machine (admin key), entry + recipient out, re-encrypt, rotation hint on
  STDERR; a machine that fails is named with a manual `grep -vF` line, exit
  1, but entry/recipient go anyway. Not built: Hetzner servers created later
  do not get the operator key (re-run `add` after they join).
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
    labels:                 # optional, onto each Node (OCPNode spec.labels)
      ai.citilan.de/node-class: general
    taints: ["dedicated=ml:NoSchedule"]   # optional, kubectl syntax
                            # apply pulls changes onto existing workers;
                            # removes only what the pool set (ocp.internal/pool-*)
ssh:
  private_key: .ocp/id_ed25519
  public_key: .ocp/id_ed25519.pub
robocop: true               # default false; auto-true when a hetzner
                            # provider is configured
lbipam: true                # opt-in LB-IPAM + L2 announcements (ARP takeover
                            # on the node network — know what you're doing)
cilium:                     # optional Cilium Helm values, install + upgrade
  devices: [enP7s7.30]      # Helm `devices` (keep Cilium off fabric NICs)
  helm_values: {}           # anything else; not ipam (OCP's)
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
- Destroy runs Rex::Rancher's uninstall line over SSH: every RKE2/K3s
  uninstaller present, then `/usr/local/bin/cilium`, `/opt/cni`, `/run/k3s`
  and Cilium's datapath; RKE2/K3s still installed, or Cilium state that
  survived (reboot needed), fails it with the reason.

### Local
- `OCP::Provider::Local`: provider operations run locally (open3), but
  `resolve_host` returns `127.0.0.1` so the actual install still goes through
  the normal Rex/SSH path. `--service systemd|none` controls service setup.

## Security Model (PIN1/PIN2)

- **age.key** master key, encrypted with PIN1 → `age.key.enc`.
- **keys.yaml** two tiers and only two: **robo-ssh** (automation) age-only, no
  PIN2; **admin-ssh** (everything a human triggers) age + PIN2.
- The robo key's deployment path depends on `robocop.security_level`:
  `secret`/`secret_approved` put the private key into the
  `robocop-credentials` Secret (self-heals across pod restarts;
  `secret_approved` gates the write with PIN2); `inject` keeps only the
  public half in the Secret and hands the private key to a running robocop
  pod's memory over a Kubernetes port-forward via `ocp inject-key` (PIN1 +
  PIN2) — never on disk, lost again on every pod restart. It still never
  opens a control plane: `OCP::ClusterKey` always picks the admin key there,
  on every provider.
- The robo key's public half reaches Hetzner servers automatically,
  uploaded under `ocp-<name>-robo` (`OCP::Config::robo_ssh_key_name`, k101;
  every server is created with both keys, control plane included);
  `ssh`-provider operators must add it to `authorized_keys` themselves —
  nothing does that for them.
- **Two-key rule for ssh workers (k209):** robocop joins and tears down
  workers with the robo key, `ocp node rm`/`ocp ssh`/a CLI join use the
  admin key. So a `provider: ssh` worker needs **both** public keys
  (`ocp keys authorized-keys | ssh root@W 'cat >> ~/.ssh/authorized_keys'`);
  a control plane needs the admin key. With only one, robocop's join works
  and `ocp node rm` ends `Failed` with rke2 still running (or the reverse).
  `ocp node add` on an ssh provider says so before the join; a refused key
  names the missing one (`OCP::SSH key_purpose`, from
  `OCP::Node ssh_key_purpose`: CLI paths `admin`, robocop `automation`).
- **The admin key opens every machine the CLI reaches, on every provider.**
  Hetzner gets it through the API before the server exists; a
  `provider: ssh` machine gets it from a human
  (`ocp keys authorized-keys --purpose admin` → `authorized_keys`). The
  provider decides who distributes it, not which key. `OCP::ClusterKey` is
  the CLI's choice only — robocop never goes through it.
- **Operator / Leitstand (k216):** `SOPS_AGE_KEY_FILE` (set, non-empty) is the
  age identity of EVERY decrypt in `OCP::Secrets`/`OCP::Keys` — no PIN1,
  never copied to `.ocp/age.key`, never used to write `.ocp/age.pub`;
  `age.key.enc` stays the project key behind PIN1. Without `.ocp/age.pub` the
  project recipient is read off the files (identity opens keys.yaml's private
  keys → it is the project key; else bindings − `.sops.yaml` list − operator
  ages − own identity); ambiguous → every write dies (put the project
  recipient into `.ocp/age.pub`). `OCP::ClusterKey::identity_of` →
  `project|operator|other`: operator (identity recipient == an entry's
  `age`) → the operator key from `OCP_OPERATOR_KEY` (path; public half must
  match the entry), origin `operator`, no PIN2, temp pair for Rex; other →
  refused by name. Operator cannot: open robo/admin private keys (inner layer
  project-key-only; named error), PIN2 approval (`secret_approved`,
  `inject-key` → refused, no prompt), a first `ocp apply` (no kubeconfig.yaml
  → refused). robocop Secret under an operator: exists → `[WARN]` on STDERR,
  left as is, Deployment still ensured; missing → robocop step failed, apply
  exit 1; `inject` needs only the public half → written normally.
- **PIN2 prompts**: `ocp apply`, `ocp ssh`, `ocp update`, `ocp node add`,
  `ocp inject-key`, and `ocp destroy` when the node list contains an ssh
  machine. PIN1 prompts whenever only `age.key.enc` exists. Read-only paths
  (`ocp status`, drift detection, `--dry-run`) never prompt. They use the
  Kubernetes API; the host probe for drift (legacy containerd template) opens
  a read-only SSH connection with the project key when one is at hand and is
  silently skipped otherwise — it prints no Rex output.
- **Dev mode (`--nopassword`)**: single unencrypted key `.ocp/id_ed25519`, no
  PIN prompts — but a plain age.key is still generated and
  **kubeconfig.yaml stays encrypted even in dev mode**. Apply detects dev
  mode by the absence of keys.yaml. This is the ONLY mode with a bootstrap
  key; secure mode has none, on any provider. `ocp keys secure` migrates a
  dev-mode project (above); never create `keys.yaml` by hand in one — its
  machines would refuse every key secure mode offers.
- **Migration hazard**: an ssh-provider cluster built before the bootstrap key
  was dropped has that key in `authorized_keys` and not the admin one. Add the
  admin key there before running anything else. There is no fallback — OCP
  diagnoses the lockout (`OCP::ClusterKey::migration_hint`) but never reaches
  for the old key.

## PIN Loss & Admin-Key Rotation

What happens when you don't have a PIN any more, or want to swap the admin
key on a cluster that already exists — two permanent states ADR 0027 created
by dropping the bootstrap key, and neither is covered anywhere else.

- **PIN1 lost** → everything. `age.key.enc` cannot be opened, so
  `keys.yaml`, `secrets.yaml`, `kubeconfig.yaml` are all unreadable —
  admin key's public half included. No recovery inside OCP; it is the outer
  gate by design (ADR 0006).
- **PIN2 lost** → the admin private key, permanently
  (`OCP::Keys::_double_decrypt` needs it; nothing else in OCP does) — and
  since ADR 0027 removed the bootstrap key, also **SSH to every machine in
  the cluster**. No second, PIN-less key still opens a control plane or an
  `ssh`-provider node. No recovery inside OCP either: the way back is
  out-of-band (rescue console / IPMI / provider UI to hand-add a fresh key),
  not a command — OCP has nothing left it can reach the machine with.
- **`.ocp/age.key` deleted** → not lost. `git clone` + PIN1 regenerates it
  from the committed `age.key.enc` (`ensure_age_key`/`restore_age_recipient`).
- **robo-ssh key ≠ a second door for a locked-out admin.** PIN1 alone
  decrypts it (`OCP::Keys::get_automation_key`, no PIN2 ever), but
  `OCP::ClusterKey` never selects it for a human login — that picks only
  the bootstrap key (dev mode) or the admin key (secure mode), on every
  provider. Its public half does reach machines, though: every Hetzner
  server under `ocp-<name>-robo` (k101) and every `ssh` worker (k209), so
  PIN1 alone *does* open those as root — by hand (`ssh -i`), not through an
  `ocp` command. A `provider: ssh`/`local` control plane carries only the
  admin key, and no `ocp` command reaches anything without PIN2. So losing
  PIN2 still means out-of-band recovery for the control plane.
- **No rotation command exists.** `ocp keys` has only `show` and
  `authorized-keys` (both print public halves; plus `recipients`, which is
  about age recipients, not SSH keys, and `secure`, which only moves a
  dev-mode project that has no keys.yaml yet); `ocp init`, even
  `--force`, skips key generation entirely whenever an automation-purpose
  key is already in `keys.yaml` (`OCP::Cmd::Init`, unconditional on
  `--force`). Adding a replacement admin key today needs
  `OCP::Keys->add_key` called from outside the CLI.
- **Rotation order that doesn't lock you out**: generate a new keypair
  yourself and keep the plaintext → add it to `keys.yaml` as a second
  `purpose: admin` entry, old entry untouched → distribute the new public
  half everywhere (`ocp keys show --name <new-name>`; `ssh`/`local` by
  hand, Hetzner re-upload under the existing key name only affects servers
  created afterward, never already-running ones) → verify with the
  plaintext key directly (`ssh -i`, not `ocp ssh` — `get_admin_key` with no
  name walks `keys.yaml` in order and keeps resolving to the *oldest*
  non-deprecated admin entry until you act) → only then
  `OCP::Keys->deprecate_key`/`delete_key` the old entry. Different
  operation from the one-time bootstrap-key migration above — that moves an
  `ssh` cluster off the retired bootstrap key once; this replaces the admin
  key itself, repeatably.

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

For ssh providers the CP is named after the host instead. Note: apply
currently only deploys `control_planes[0]` — police2+ (multi-CP) is not
implemented yet.
