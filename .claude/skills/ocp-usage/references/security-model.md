# Security Model (PIN1/PIN2)

Read when: you need the full PIN1/PIN2 key model and which commands prompt.

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
  operator add|rm` (`ocp keys add-pin2` asks for a new PIN2 twice, not the
  existing one), `ocp node rm` of an ssh node (not with `--keep-machine`),
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
