---
name: ocp-usage
description: Use when running the ocp CLI or writing ocp.yaml — commands and flags, the snake_case schema, provider modes, the PIN1/PIN2 model, drift behaviour.
---

# OCP Usage & Workflows

Verified against the code 2026-10-31: the `network:` block and the commands
`status --json`, `health`, `node ls --json`, `node rm --keep-machine`,
`node trust-host` and `deploy-image`, by source and POD only (OCP::Config,
OCP::Cmd::*), no live run; likewise `hetzner list`, `kubeconfig --readonly`,
`provider add`, `--pins-stdin` and the PIN2 list (k294); the destroy, update
and trust-host confirmations, `validate` and `fixable` the same day, by source
only (k302). The rest was
verified 2026-08-16 (OCP::Config, OCP::Cmd::*, OCP::Drift, OCP::Keys,
OCP::Secrets, OCP::ClusterKey), including live runs of each command in the
shipped Docker image (not `--help` text or source inspection alone — see
the note on dash/underscore flags below, where `--help` output alone would
have been actively misleading).

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
`ocp apply` deploys robocop itself when `robocop` is enabled, with or without
workers listed, unless `--only` narrows the run to anything but `workers`;
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

`OCP::Role::Cmd::_option_argv_spelled` (k167) rewrites hyphens to underscores before
MooX::Options sees the command line, for every argument whose underscored name is a
declared option of that command, wherever it stands (also right after a boolean:
`--force --pins-stdin`, which MooX::Options' own rewrite missed). So `--dry-run` and
`--dry_run` both work for the same option — `--help` only ever prints one spelling,
which is not evidence the other is rejected — and an unknown dashed name still reaches
Getopt::Long and is refused. The docs below use the hyphenated form throughout,
matching `xt/smoke.sh` and `README.md`. **The one shape that never works is a leading
`--no-`**: MooX::Options peels it off *before* its dash/underscore substitution, as a
Getopt::Long-style negation marker (`^(\-+)(no\-)?(.*)$`), so `--no-foo` is read as
"negate a boolean option called `foo`"
and dies with `Unknown option: foo` unless such an option exists. Every negative flag in
this CLI is therefore spelled without the dash — `--nogit`, `--nopassword`, `--nowait`.
`ocp node add` still accepts `--no_wait` as an alias for `--nowait`. The exception is
an option declared `negatable`: `ocp deploy-image --no-restart`/`--no-wait` work, and
so do `--norestart`/`--nowait` (`t/54-deploy-image.t`).

- `ocp init` — project init (keys, config, git)
  - `--hetzner` — interactive Hetzner token setup (NOT the same as
    `--provider hetzner`, which skips the token prompt). Then, at a terminal,
    location and server-type pickers from the live catalogue. When the
    catalogue cannot be read, STDERR says why (`[!!] Could not read the
    Hetzner catalogue: …`: the API's message, the status, or the failed
    connection, token masked; `_catalogue_error`, k265) and init keeps the
    defaults (`OCP::Config::%HETZNER_DEFAULTS`: cpx22 / fsn1 / debian-13,
    control planes only, k264). Init scaffolds no worker pool; an existing
    ocp.yaml keeps its own as they are.
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
- `ocp status [--json]` — spec summary, then (once deployed) nodes, GPUs and
  the drift report; read-only. Exit 1 when the kubeconfig cannot be
  decrypted, the API does not answer or drift detection dies (cause on
  STDERR), else 0. `--json` (k230): one canonical object on STDOUT (sorted
  keys, no timestamps: an unchanged cluster gives identical bytes),
  diagnostics on STDERR, same exit code. Keys: `cluster`, `config`,
  `deployed` (false before the first apply, exit 0), `spec`, `nodes` (by
  name; `gpu` = `nvidia.com/gpu` allocatable, `gpu_capacity` beside it,
  k270), `drift` (`fixable` = `ocp apply` closes it, k312: a remedy, a
  `self_healing` entry or kind `missing`; report-only entries and kind
  `error` = could not be checked are never fixable, k262), `error` when
  something was missing,
  `amd_gpu` only on a cluster with an AMD node (k258).
- `ocp health [--json]` — one pod scan through the API, no waiting, changes
  nothing (k230). Same classification as the health gate at the end of
  `ocp apply` (`OCP::Cmd::Apply::Health`): `critical` = durable fault in
  `kube-system`, `warning` = one elsewhere, `starting` = still coming up.
  Exit 1 on a critical pod or when the cluster cannot be reached, else 0.
  `--json`: `{fatal, healthy, pods: [{namespace, name, state, reason}]}`,
  pods by namespace then name, `healthy` true only with no pod listed;
  unreachable → `error` + empty `pods`, cause on STDERR. A long-stuck pod's
  `reason` carries its minutes, so compare namespace/name/state, not reason.
- `ocp update [--dry-run] [--component NAME] [--force]` — update components;
  refuses to run without `status.ocpVersion` (stamped by apply). `--force`
  here means "even if the versions match", not "skip a question". When the
  version manifest lists manual steps (and not under `--dry-run`) it asks
  "Manual steps required. Continue?" on STDERR (k303): a person at a
  terminal answering `y`/`yes`, anything else or EOF → "Aborted", exit 1,
  nothing changed. Without a terminal it reads nothing from STDIN, says so
  on STDERR and exits 1; there is no switch that confirms from a script.
- `ocp destroy [--force] [--keep-status]` — tear down. Before anything is
  stopped or deleted it asks "Are you sure you want to destroy this
  cluster?" on STDERR (k301): `y`/`yes` at a terminal confirms, anything
  else or EOF → "Aborted; nothing was deleted", exit 1. Without a terminal
  it reads nothing from STDIN (a piped `y` is no confirmation), says on
  STDERR that it needs a person at a terminal or `--force`, deletes
  nothing, exit 1. `--force` (`-f`) skips the question and is the only way
  without a terminal. With no node found it still asks, naming the local
  files it would remove (k304), and `--force` skips that too; with no
  file to remove nothing is asked. Afterwards it deletes status.yaml +
  deployed.yaml unless `--keep-status`; the encrypted kubeconfig.yaml goes
  either way. A teardown that leaves something standing on purpose (every
  line saying NOT torn down, or NOT deleted for old-label servers) ends on
  STDERR `Teardown INCOMPLETE` and exits 1 instead of "Cluster destroyed.";
  deletes, uninstalls and the state cleanup run as before, `--keep-status`
  changes only which files go. With the cluster API unreadable, a
  `provider: local` pool's worker (this machine) is named NOT torn down on
  STDERR with the script to run by hand: `/usr/local/bin/rke2-uninstall.sh`
  (K3s: `/usr/local/bin/k3s-agent-uninstall.sh`); nothing is uninstalled on
  a guess
- `ocp kubeconfig` — stdout; `-e` merge (with backup, other clusters kept),
  `-o FILE` write to file; `--refresh` is not implemented (dies: the stored
  kubeconfig.yaml is authoritative)
- `ocp kubeconfig --readonly [--name NAME] [--server URL] [--revoke]` (k230)
  — a read-only kubeconfig (ServiceAccount `ocp-readonly-NAME`, default name
  `leitstand`, bound to `view` plus Nodes/OCPNodes/OCPNodeProviders) on
  STDOUT, hints on STDERR, nothing saved; the token is a secret. `--server`
  replaces the admin kubeconfig's API URL; `--revoke` deletes the account and
  its token. Never with `-e`/`-o`/`--refresh`; `--name`/`--server`/`--revoke`
  only with `--readonly`.
- `ocp version` — versions (needs the ocpVersion stamp for "deployed")
- `ocp ssh --node <name|ip>` — SSH to nodes (admin-key, PIN2). An OCPNode
  target is verified against its `status.hostKeys` pins (one batch-mode
  probe connection first; changed key → refused, `ocp node trust-host NAME`;
  no pins → trusted on first contact and pinned, k235). CPs and bare
  addresses stay on the project's known_hosts. Under an operator identity
  the key is `OCP_OPERATOR_KEY`, no PIN2. Every target gets that probe
  (k237): a refused key (`Permission denied`) prints the `wait_for_ssh`
  diagnosis (`OCP::SSH::rejection_message`: which key, how to install it);
  `migration_hint` only for such a real refusal. Never blocks — hands over
  to ssh anyway.
- `ocp deploy-robocop` — robocop + CRDs standalone. An OCPNode/OCPNodeProvider
  CRD in the cluster that declares fields this ocp's does not (one a newer ocp
  installed) is left as it is, with the `[skip]` line `ocp apply` gives it
  (`OCP::Cmd::Apply::CR::skip_newer_crd`, k311; `OCP::Drift::crd_schema_diff`
  judges both). A CRD it cannot read (anything but a 404) stops the command
  with the cause rather than being written over blind.
- `ocp deploy-image (--image REF | --tag TAG [--repo REPO]) [--wait
  [--timeout SECONDS]] [--no-restart] [--namespace NS] [--cluster NAME]`
  — roll a robocop image into the running Deployment (`ocp-system/robocop`,
  container `controller`) through the API. REF is `REPO:TAG` or
  `REPO@sha256:<64hex>`; `--image` excludes `--repo` and `--tag`; the repo
  defaults to `raudssus/ocp`, or `OCP_IMAGE_REPO`. One strategic-merge patch
  sets the image together with `OCP_DISTRIBUTION`/`OCP_POD_CIDR` from
  ocp.yaml (k187), then a `restartedAt` annotation patch unless
  `--no-restart`. No Deployment → dies, pointing at `ocp deploy-robocop`.
  An override, not a setting (k227): the next `ocp apply`/`deploy-robocop`
  writes `robocop.image` (else the CLI's own version) back, and the command
  prints `[WARN] ad-hoc override` when the image differs from that.
  `--wait` (off by default) waits the way `kubectl rollout status` does —
  new generation observed, every replica updated, no old pod left, all
  available — for `--timeout` seconds (default 300, refused without
  `--wait`); a timeout says on STDERR what it still waited for, exit 1.
  `--cluster`/`OCP_CLUSTER` choose nothing: the target is the project's
  kubeconfig, so the name is a guard (k293): anything but ocp.yaml's `name`
  dies before a patch is sent ("is not this project's cluster"), and so do
  `--cluster` and `OCP_CLUSTER` disagreeing.
- `ocp inject-key [--timeout SECONDS]` — hand the robo private key to a
  running robocop pod for `robocop.security_level: inject` (PIN1 + PIN2;
  default timeout 30s)
- `ocp hetzner list [--label KEY=VAL]` — Hetzner debugging: the servers the
  token sees (bare `ocp hetzner` dies, a subcommand is required)
- `ocp node add NAME --role ROLE [--provider NAME] [--host HOST]
  [--server-type TYPE] [--location LOC] [--image IMG] [--gpu]
  [--node-ip IP] [--label K=V]... [--taint K=V:Effect]... [--nowait]`
  — create an OCPNode CR (`--no_wait` is kept as an alias, see above).
  On a hetzner provider `--server-type` is needed unless the OCPNodeProvider
  has `spec.hetzner.serverType` (the `hetzner-default` apply writes has none):
  with neither, `create_server` refuses and the node goes Failed, nothing
  ordered (k308; the cx32 fallback is gone).
  `--node-ip` becomes `spec.nodeIP` (see "node_ip" below). `--gpu` sets
  `spec.gpu: true` and opens the integrated-GPU gate (see "gpu.amd" below).
  Under `gpu.enabled: false` the kill switch wins over `--gpu` and no GPU is
  set up on the node (k358 for the CLI's own join without robocop, k31 for
  robocop's join); `gpu.driver: operator` leaves the NVIDIA driver to the GPU
  Operator on that join too (k358).
  Once the node is Ready, it also deploys the node's GPU stack (skill
  `ocp-gpu`).
- `ocp node rm NAME [--keep-machine]` — drain + remove (OCP::Node->teardown):
  cordon, drain, delete the Hetzner server or uninstall RKE2/K3s (ssh/local;
  an ssh node with the cluster key — PIN2 in secure mode), then the Node and
  the OCPNode. For ssh/local nodes it checks the machine's host key against the
  pins first (k235): a changed key refuses before lease, cordon or drain —
  nothing is touched. A Ready worker without pins (pre-pinning install, or
  after `trust-host`) is pinned by TOFU on its next reconcile
  (`OCP::Node::_pin_unpinned`). A node that could not be taken off its
  machine is not removed (k175): STDERR, exit 1, the OCPNode stays `Failed`,
  a re-run retries. A lease robocop holds refuses with the holder named.
  When the machine cleanup itself failed, the error ends with the way out:
  `--keep-machine` (k229), the same teardown minus the server delete or
  uninstall — no provider built, no cluster key, no PIN2, no host-key check,
  and a missing OCPNodeProvider does not stop it. STDOUT then says what was
  left (a Hetzner server that keeps billing, by id; an RKE2/K3s install
  whose running agent registers its Node again). Never implied.
- `ocp node trust-host NAME [--yes]` — forget an OCPNode's pinned host keys
  (k235), after a rebuilt machine refused with "host key of … changed".
  Lists the fingerprints on STDERR and asks there, at a terminal only
  (k293): `y`/`yes` confirms, anything else or EOF → "Aborted", exit 1.
  Without a terminal it reads nothing from STDIN (a piped `y` does not
  count), says on STDERR that it needs a person at a terminal or `--yes`,
  keeps the pins, exit 1; `--yes` skips the question and is the only way
  to confirm from a script (`OCP::Role::Cmd::Confirm`). Then `status.hostKeys` is merge-patched away, and
  `status.message` with it when it is that complaint; the next contact is
  TOFU again. No pins → says so, exit 0. Kubernetes API only, no SSH.
- `ocp node ls [--json]` — list OCPNode CRs (name, role, phase, provider,
  IP = `status.address`, else `status.publicIP`, age). `--json` (k230): an
  array, one object per OCPNode by name, canonical, on STDOUT and nothing
  else; Kubernetes API only, no SSH. Every key is always there (null when
  unknown): `name role pool host address publicIP phase reconciler
  kubernetesNodeName labels gpu runtime kubelet os kernel`, joined with the
  Kubernetes Node (`status.kubernetesNodeName`, else the OCPNode's name).
  `gpu` is `nvidia.com/gpu` allocatable, always a number; `reconciler` is
  `cli` or `robocop@POD`; `pool` comes from annotation `ocp.internal/pool`,
  else from ocp.yaml's pools by the names apply gives their OCPNodes (null
  for an `ocp node add` node).
- `ocp provider add --name NAME --type hetzner|ssh|local [--token-file FILE]
  [--location LOC] [--server-type TYPE] [--image IMG] [--ssh-key-name NAME]
  [--default]` — OCPNodeProvider CR (+ token Secret for hetzner, which needs
  `--token-file`; the other four value flags are hetzner-only too).
  `--ssh-key-name` is the uploaded key every server boots with, default
  `ocp-<cluster>-admin`
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
  Before PIN1 it checks ocp.yaml: a migration runs all of `validate()` (k321);
  `--drop-bootstrap` on a project that is already secure checks only the shape
  of what the machine lookup reads (`control_planes`, `workers`, hosts, a
  pool's `nodes`), in validate()'s words (k346). Errors go to STDERR, exit 1,
  before PIN1, the cluster or SSH.
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
  name `[a-z0-9][a-z0-9-]*` (≤63), checks before any PIN (its arguments, and
  the shape of what the machine lookup reads in ocp.yaml, in validate()'s
  words, k346: STDERR, exit 1, before PIN1, the cluster or SSH; rm checks the
  same shapes); SSH public key onto
  every machine (`OCP::Role::Cmd::Machines`, same walk as `keys secure`) with
  the admin key FIRST — a failed host → STDERR, exit 1, nothing recorded,
  re-run idempotent; then `.sops.yaml` gets AGE1 (external `.sops.yaml` →
  stop before any machine, same message as `recipients add`) and keys.yaml
  an entry `{name, type, purpose: operator, public, age, created,
  deprecated: 0}` with NO `private` (`OCP::Keys::add_public_key`), files
  re-encrypted. Same add again = ok; same name + other keys, a taken SSH key
  or age recipient, the project key as AGE1 → error. rm: blob off every
  machine (admin key), entry + recipient out, re-encrypt, rotation hint on
  STDERR (names every file re-encrypted, keys.yaml included, k237); a machine that fails is named with a manual `grep -vF` line, exit
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
  # host / private_ip / public_ip / name / service (pinned after apply);
  # `nodes: N` on the mapping form only. Any other key is
  # refused (k347), `count:` and `network_interface:` included
  node_ip: 10.0.0.5         # optional, never defaulted; see "node_ip" below
workers:                    # optional pools; apply turns each entry into
  - name: pool1             # Pending OCPNode CRs (CR-first), reconciled by
    provider: hetzner       # robocop or the CLI fallback
    server_type: cpx22      # required on a hetzner pool (k308): no default
    nodes: 3                # a count; an ssh pool lists hosts (strings or
                            # {host: …}) instead, see "Shapes" below
    labels:                 # optional, onto each Node (OCPNode spec.labels)
      ai.citilan.de/node-class: general
    taints: ["dedicated=ml:NoSchedule"]   # optional, kubectl syntax
                            # apply pulls changes onto existing workers;
                            # removes only what the pool set (ocp.internal/pool-*)
ssh:
  private_key: .ocp/id_ed25519
  public_key: .ocp/id_ed25519.pub
robocop: true               # default false; auto-true when a hetzner
                            # provider is configured. true/false (or 1/0) or
                            # a mapping {enabled, security_level, image};
                            # a string like no/off is refused
lbipam: true                # opt-in LB-IPAM + L2 announcements (ARP takeover
                            # on the node network — know what you're doing)
network:                    # optional; see "network" below
  pod_cidr: 10.42.0.0/16    # cluster-cidr + Cilium pool, install time only
  lb_pool:                  # LB-IPAM pool, read only with lbipam: true
    cidr: 10.0.0.240/28     # or start: + stop:, never both
  l2:                       # L2 announcement policy, lbipam: true only
    interfaces: ['^eth[0-9]+$']   # replaces the default regexes
    node_selector:          # only these nodes announce
      ai.citilan.de/l2-announce: "true"
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
  amd:                      # optional; absent = these defaults. An unknown
                            # key or value is a validate error
    allocation: device-plugin  # device-plugin | dra | none
    resource_naming: single    # single | mixed, for the device plugin
    labeller: true             # AMD's node labeller
    metrics: false             # device-metrics-exporter
    integrated: false          # iGPU/APU on every node
```

### node_ip — the address a node registers by (k254)

`control_planes[].node_ip`, and `ocp node add --node-ip` (the OCPNode's
`spec.nodeIP`), set the InternalIP a node registers by. That is the RKE2/K3s
`node-ip`.

- **The value** is one IP, or `v4,v6` (one address per family), with no
  whitespace. A hostname, a CIDR, loopback or link-local is refused before
  anything is ordered or installed. `ocp node add`, ocp.yaml and a
  hand-written `spec.nodeIP` refuse a value in the same words
  (`OCP::Choices::node_ip_error`).
- **Explicit only, no default.** Without it, no node-ip is passed, and the
  node registers the address of its default route. On a multi-homed host
  that can be the wrong address. Skill `ocp-rke2`
  (`references/install-flow.md`) has why and how to fix it.
- **It names one machine.** It is refused:
  - on a `workers:` pool and on the entries of its `nodes:` list (set it per
    node with `ocp node add` instead);
  - on a `control_planes:` mapping with `nodes:` above 1 (list the control
    planes one by one instead);
  - when two control planes share an address.
- **It needs a Rex::Rancher with node_ip support** (rex-rancher k100). That is
  part of Rex::Rancher 0.005, which OCP's cpanfile requires (vendored until its
  CPAN release). With an older one, the install of a node with a
  node_ip dies with the reason before its host is touched, and its OCPNode
  ends in `Failed`. Nodes without a node_ip install as before.
- **It needs an OCPNode CRD that stores `spec.nodeIP`** (k290). An older
  ocp's CRD drops the field without an error, so `ocp node add --node-ip`
  reads the CRD first and refuses (STDERR, exit 1, nothing written, before
  the SSH probe and PIN2) until `ocp apply` has updated it.
- **Registered elsewhere anyway?** Once the node is Ready, `ocp apply` or
  `ocp node add` prints one `[WARN]` on STDERR that names the fix. The same
  note stays in the OCPNode's `status.message`, whoever did the join. It is
  never fatal.

### network — pod CIDR, LB-IPAM pool, L2 announcements (k182, k127, k210)

- **`pod_cidr`** (k182) is one value for two things: the RKE2/K3s
  `cluster-cidr` and Cilium's cluster pool. Unset, it is
  `$OCP::Config::DEFAULT_POD_CIDR`, the built-in cluster-cidr of both
  distributions (Cilium's own default overlaps most host LANs).
  - **Install time only.** A fresh server and a fresh Cilium take it; a
    running cluster keeps its pool. `OCP::Drift` reports a difference,
    report-only: state the running pool in ocp.yaml, or rebuild.
  - A control plane joining as another RKE2 server repeats it (k184);
    robocop gets it as `OCP_POD_CIDR`.
- **`lb_pool`** (k127) is the `CiliumLoadBalancerIPPool` block: `cidr`, or
  `start` + `stop`, never both, IPv4 only. Read only under `lbipam: true`.
  Unset, the pool is the node IP as a `/32`, on a single-node cluster only.
  On a multi-node cluster the LB-IPAM step refuses ("set network.lb_pool"),
  and `ocp apply` prints that as `[WARN] LB-IPAM setup failed` and carries on.
- **`l2`** (k127) shapes the `CiliumL2AnnouncementPolicy`, also only under
  `lbipam: true`.
  - `interfaces` (Go/RE2 regexes) replaces
    `$OCP::Config::DEFAULT_L2_INTERFACES` (k210): `eth*` and `en*`, VLAN
    suffix allowed, minus switchdev `…np<N>` fabric ports.
  - `node_selector` (label → value) becomes the policy's
    `nodeSelector.matchLabels`, so only those nodes announce.
- **The checks** live in `OCP::Config::validate`.
  - `pod_cidr`, the default too: an IPv4 CIDR, no host bits, a prefix
    shorter than /24 (Cilium gives every node a /24), clear of the service
    network `$OCP::Config::SERVICE_CIDR`, the node addresses ocp.yaml names
    and `lb_pool`.
  - `lb_pool`: its shape and IPv4 addresses, and `start` not after `stop`
    (compared as addresses; equal is a pool of one, k292). `l2.node_selector`:
    a non-empty mapping of scalars. `l2.interfaces`: a non-empty list of
    strings.
  - An unknown key is refused under `network:`, `network.lb_pool` and
    `network.l2`, as under `cilium:` and `gpu.amd:` (k292): a misspelt key
    would leave its default in force.
  - **The service network** `$OCP::Config::SERVICE_CIDR` (10.43.0.0/16, the
    built-in service-cidr of RKE2 and K3s) is held against the same
    addresses as the pod CIDR (k299): control-plane `host`, `public_ip`,
    `private_ip` and `node_ip`, worker pool hosts, and `network.lb_pool`.
    One inside it is refused, whatever `pod_cidr` is; ocp.yaml has no key
    to move the service network, so the line says to use an address
    outside it.
  - **Shapes name their key** (k296, k305). A wrong shape gets one line
    naming it, not a Perl error: `control_planes`, `workers` and their
    entries, `network`, `cilium`, `gpu`, `gpu.amd`. `gpu: false` is refused
    with the hint `gpu: { enabled: false }`. A list as `name:` is refused, as
    is `control_planes: []`.
  - **`robocop:`** (k315) takes only true/false (or 1/0) or a mapping of
    `enabled`, `security_level` and `image`; `enabled` takes true/false too.
    A string like `no` or `off` is refused, with the hint `write robocop:
    false`: `robocop: must be true, false or a mapping (enabled,
    security_level, image), not 'no'`. A key outside the three is refused.
  - **A pool's `nodes:`** (k315) hangs on its provider. An `ssh` pool lists its
    hosts (strings, or mappings with `host`); every other provider counts its
    machines (`nodes: 3`, a whole number). Wrong: "nodes must be a list of
    hosts for an ssh pool" / "nodes must be a whole number".
  - **The other switches** (k320): `gpu.enabled`, `gpu.toolkit`,
    `gpu.amd.labeller`, `gpu.amd.metrics`, `gpu.amd.integrated`, `lbipam`,
    `nocert` and `system.ntp` take only true/false (or 1/0), as `robocop:`
    does (`OCP::Config::_is_switch`). A string such as `no` is refused:
    `gpu.enabled: must be true or false, not 'no'; write enabled: false`
    (`_switch_error`; the hint, `_boolean_hint`, names the last key segment and
    appears only for a string that spells a boolean). The accessors
    (`gpu_enabled`, `lbipam`, `no_cert`, `ntp_enabled`, …) croak with the same
    line, since `ocp update`, `ocp node add` and `ocp status`' drift check read
    them without `validate`.
  - **An ssh pool's machines** (k322, `_ssh_pool_machines_errors`): `host`
    (one) or `nodes` (a list), not neither and not both. `nodes: []` passes and
    means "no machines yet"; a `host` Perl calls false (`0`, empty) counts as
    none. `host`, `server_type`, `location` and `image` must be strings, in a
    control plane and in a pool (`_not_a_string`).
  - **A hetzner pool's `server_type`** (k308, `_worker_lines`): required, a
    worker has no default type: `worker pool 'pool1': server_type required
    for hetzner -- a worker pool has no default; add one, e.g. server_type:
    cpx22` (the example is `%HETZNER_DEFAULTS{server_type}`). Untagged, like
    the control plane's `server_type required for hetzner`, so `spec_errors`
    (destroy, status, node ls) does not stop on it. A pool's type reaches
    each OCPNode's `spec.serverType` (`worker_ocpnodes`); the provider CR
    apply writes carries none, so this line is what keeps a pool from
    `create_server`'s refusal.
  - **Unknown keys under `gpu:` and `system:`, a `system:` that is no
    mapping, and `host:` on a hetzner or local pool** (k331). `gpu:` takes
    `enabled`, `driver`, `toolkit`, `amd`; `system:` takes `timezone`,
    `locale`, `ntp` (`_unknown_keys`, `_system_errors`; `gpu_config` and
    `system_config` croak on the same lines). `host:` is read for an ssh pool
    only (`_pool_host_error`, `_pool_takes_host`): beside any other known
    provider it is refused whatever it holds, and a pool that takes none adds
    no host to the service-network/pod-CIDR address checks.
  - **Unknown keys under `kubernetes:` and `ssh:`, and on an ssh pool's
    machine** (k355). `kubernetes:` takes `dist`, `version`; `ssh:` takes
    `private_key`, `public_key`; a mapping in an ssh pool's `nodes:` takes
    `host` only (`node_ip` there has its own line). validate refuses the rest
    (`_entry_unknown_keys`, `_kubernetes_unknown_keys`), so `ocp apply` stops;
    `kubernetes.distribution: k3s` (the Rex/robocop spelling) gets the hint
    `write kubernetes: { dist: k3s }`, only when the value is rke2 or k3s.
    `kubernetes.version` and a control plane's `name` must be strings
    (`_version_error`, `_not_a_string`); `kubernetes()` and `version()` croak
    on the same lines. The unknown keys of `ssh:` and of a pool machine are
    validate's alone (`ssh_config()` and `ocp destroy` do not refuse on them).
  - **`cilium:`** (k210, k292) takes `devices` (a non-empty list of interface
    names; the short form of `helm_values.devices`) and `helm_values` (a
    mapping of Helm values, deep-merged over what Rex::Rancher::Cilium
    generates). Setting `devices` and `helm_values.devices` both is refused, as
    is a `cilium:` that is no mapping and a key outside the two:
    `cilium.device: unknown key (must be devices or helm_values)`
    (`_validate_cilium`).
  - **At most 7 control planes** (`$OCP::Config::MAX_CONTROL_PLANE_NODES`):
    `control_planes.nodes` must be a whole number from 1 to 7, and the list
    form holds at most 7 entries ("must list at most 7 control planes"),
    since every control plane is an etcd member and etcd advises no more.
  - **`ocp apply` and `ocp apply --dry-run` call `validate` first** (k255),
    before a PIN, a file, a host or the cluster: every error at once on
    STDERR, one line each, then exit 1 with nothing done. `ocp status` does
    not gate on it: it has to show a cluster whose ocp.yaml has a mistake.

### gpu.amd — AMD GPU nodes (k249–k252)

- **Labels OCP sets.** When the host step accepts an AMD GPU, the node
  registers with `ocp.internal/amd-gpu.present=true`, the marker the AMD
  stack selects on. It also gets `ocp.internal/amd-gpu.gfx-target=<gfx>`
  once the driver reports one.
- **The per-node override.** `ocp.internal/amd-gpu.allocation`, with the
  same values as `gpu.amd.allocation`, overrides the default for that node.
  Set it with `ocp node add --label`. OCP itself never sets it.
- **Integrated GPUs** (a Ryzen iGPU or APU) are set up on a node joined with
  `ocp node add --gpu`, or on every node with `gpu.amd.integrated: true`
  (k253). A node gets the setting at its next install: the first control
  plane on the next `ocp apply`, a node that has already joined through an
  OCPNode (a worker, police2 and later) only when it is joined again.
- **The rest** (components, affinity, readiness, status, the full label
  table) is in skill `ocp-gpu` (`references/amd.md`).

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
- **A worker by name (`ocp node add --host NAME`, k236):** with robocop on, the
  name is resolved by robocop inside the cluster (CoreDNS, then the node's
  resolver), not by the CLI host. A name that only resolves here (`/etc/hosts`,
  a container's `--add-host`) is invisible to every pod, so the join fails.
  `ocp node add` says so on STDERR (not for an IP). A name that does not
  resolve is reported as that, never as a rejected key: "Name 'X' does not
  resolve … This is not a key problem" (host-probe warning, `OCP::SSH`
  `wait_for_ssh`/`learn_host_key`, robocop's `status.message`; recogniser
  `OCP::SSH->name_unresolved`). Recommendation: pass the IP, or a DNS entry the
  cluster knows.
  **Without robocop (CLI path, k238)** the name is checked BEFORE any cluster
  write: resolution on this machine, then (not with `--nowait`) the usual SSH
  probe with the join's wait (~120 s). Failure prints "Name 'X' does not
  resolve: the lookup failed on this machine …" or the SSH error on STDERR,
  exit 1, and no OCPNode or other object is created (nothing to clean up, no
  `node rm --keep-machine`). `--nowait` checks resolution only; IPs are never
  resolved. With robocop on, unchanged: OCPNode as request, STDERR warning,
  `Failed` with a message if the cluster cannot resolve it.
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
  `ocp inject-key`, `ocp deploy-robocop`, `ocp keys secure`, `ocp keys
  operator add|rm`, `ocp node rm` of an ssh node (not with `--keep-machine`),
  and `ocp destroy` when the node list contains an ssh machine. PIN1
  prompts whenever only `age.key.enc` exists. Read-only paths
  (`ocp status`, drift detection, `--dry-run`) never prompt. They use the
  Kubernetes API; the host probe for drift (legacy containerd template) opens
  a read-only SSH connection with a key that needs no prompt — one already in
  hand, an operator's `OCP_OPERATOR_KEY` (a Leitstand, k237; set but unusable →
  `[WARN]` once on STDERR), the project key, else the robo key — and is
  skipped with a `[WARN] host probes skipped` line when none exists. It prints
  no Rex output.
- **`--pins-stdin`** (k166), on every command after the command word: each
  PIN prompt of the run (PIN1, PIN2, a new PIN and its confirmation) reads
  the next line of STDIN instead of the terminal, in prompt order
  (`ocp apply --pins-stdin < <(pass show x)`). No line left → dies naming the
  PIN, never falls back to the terminal; it counts as a terminal for the
  no-terminal PIN2 refusal. There is no argv or env variant.
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
   report-only — a human decides. `ocp status` shows the same drift report,
   and its "N of M can be reconciled automatically" count (and `--json`
   `fixable`) is what `ocp apply` closes (k312): a remedy, a `self_healing`
   entry, or kind `missing`; unfound checks (kind `error`) are not counted.
2. **Hash-based components** (`.ocp/deployed.yaml`, MD5 of generated
   manifests): registry, NFD, GPU operator. cert-manager is tracked by
   component version, not manifest hash. NFD and the GPU Operator are also
   self-healing (k351): their step reads the image the drift probe reads
   (`OCP::Drift->version_against_pin`) and re-applies the manifest when the
   tag is off its pin, even at an unchanged hash; args and other fields are
   not compared. `--dry-run` says "would re-apply the NFD manifest" (or the
   GPU Operator's, under `gpu.enabled`).
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

For ssh providers the first CP is named after the host instead. On RKE2,
`control_planes[1..]` join as `police2`, `police3`, … (Pending OCPNodes with
role control-plane, k8). k3s builds only police1 and warns on STDERR.
