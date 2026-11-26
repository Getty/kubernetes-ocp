# OCP Command Reference

Read when: running or changing any ocp command, its flags, exit codes or output.

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

## Apply and robocop credentials

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
  - `--force` — overwrite existing config
- `ocp apply [--only control-planes|workers|NODE] [--dry-run] [--clean_cilium_residue]`
  — deploy/reconcile. `--clean_cilium_residue` clears Cilium datapath state
  left by an earlier cluster on a machine instead of refusing it (a host
  running RKE2/K3s is untouched; what remains still asks for a reboot);
  without it the install refuses such a host and the refusal names the
  switch. Only a refused first control plane is installed again by the next
  `ocp apply` (no kubeconfig.yaml was written, so it bootstraps again); a
  refused join (police2+, a worker) leaves a Failed OCPNode that no later
  `ocp apply` installs again: `ocp node rm NAME --keep_machine`, then
  `ocp node add NAME --clean_cilium_residue` with `--role control-plane` for
  a control plane and the `--provider`/`--host` `ocp node ls` shows for the
  node, as the refusal says. Not for robocop-joined nodes (reboot those).
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
  something was missing, and beside it `errors` (k431): the same message as
  an array, one entry per line (secrets masked, no Perl location, no
  indentation, leading `ERROR:` label off the first); the entries joined by
  one space equal `error`, and `errors` is present whenever `error` is. When
  drift detection dies, `error` and the first `errors` entry start `Cannot
  detect drift: `. Every `--json` command that fails carries the same pair
  (`OCP::ErrorLine::json_error`/`json_errors`; a command that dies before its
  object exists, e.g. an undecryptable kubeconfig, prints an object holding
  only `error` and `errors`, exit 1),
  `amd_gpu` only on a cluster with an AMD node (k258).
- `ocp health [--json]` — one pod scan through the API, no waiting, changes
  nothing (k230). Same classification as the health gate at the end of
  `ocp apply` (`OCP::Cmd::Apply::Health`): `critical` = durable fault in
  `kube-system`, `warning` = one elsewhere, `starting` = still coming up.
  Exit 1 on a critical pod or when the cluster cannot be reached, else 0.
  `--json`: `{fatal, healthy, pods: [{namespace, name, state, reason}]}`,
  pods by namespace then name, `healthy` true only with no pod listed;
  unreachable → `error` + `errors` (k431, one entry per line of the message,
  joined by a space equal to `error`) + empty `pods`, cause on STDERR. A long-stuck pod's
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
  [--node-ip IP] [--label K=V]... [--taint K=V:Effect]... [--nowait] [--clean_cilium_residue]`
  — create an OCPNode CR (`--no_wait` is kept as an alias, see above).
  `--clean_cilium_residue` is the same switch as on `ocp apply`; refused with
  `--nowait` (nothing would install) and when robocop does the join, both
  before anything is written. Failed is terminal: run again for a NAME whose
  OCPNode is Failed, it reads that OCPNode back and installs nothing, switch
  or not — `ocp node rm NAME --keep_machine` first, then add it again with
  the flags it was added with.
  On a hetzner provider `--server-type` is needed unless the OCPNodeProvider
  has `spec.hetzner.serverType` (the `hetzner-default` apply writes has none):
  with neither, `create_server` refuses and the node goes Failed, nothing
  ordered (k308; the cx32 fallback is gone).
  `--node-ip` becomes `spec.nodeIP` (see "node_ip" in schema.md). `--gpu` sets
  `spec.gpu: true` and opens the integrated-GPU gate (see "gpu.amd" in schema.md).
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
  for an `ocp node add` node). When the nodes cannot be listed (API
  unreachable or erroring, no ocp.yaml, no kubeconfig, a worker pool
  validate() refuses) STDOUT carries one object instead of the array,
  `{error, errors}` (k431: `errors` = the message one entry per line, joined
  by a space equal to `error`), exit 1, STDERR says it as without `--json`.
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
  in pin-recovery.md — there is no rotate/add subcommand for the admin/robo SSH keys)
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
- `ocp keys add-pin2` — put the PIN2 layer back on an admin key stored without
  it (k450; before k390 a PIN2 of `"0"` was read as none, so `ocp init` and
  `ocp keys secure` stored the admin key under PIN1 alone while saying
  "age+PIN2"; `OCP::Cmd::Keys::AddPin2`). Asks PIN1 if `age.key` is not already
  unlocked, finds every admin key in `keys.yaml` without the layer
  (`OCP::Keys::has_pin2_layer`), asks a new PIN2 twice, and re-encrypts each
  under age + PIN2 (`add_pin2_layer`, verifies before it writes). The key is
  the same key: no machine's `authorized_keys` changes. Commit `keys.yaml`
  afterwards. `--pins-stdin` feeds it (PIN1 if asked, PIN2, PIN2 again). Every
  admin key has the layer already → `[ok] … Nothing to do.`, exit 0. No
  `keys.yaml` (dev mode) or no admin key → dies; no terminal and no
  `--pins-stdin` → refuses, nothing written. Never changes an existing PIN2.
  Prompts and errors on STDERR, what was done on STDOUT.
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
