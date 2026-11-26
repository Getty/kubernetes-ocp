# PIN Loss & Admin-Key Rotation

Read when: a PIN is lost, an admin key is locked out or must be replaced.

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
- **PIN2 never set (admin key stored without its layer)** → recoverable, unlike
  PIN2 lost. A PIN2 of `"0"` before k390 left the admin key under PIN1 alone,
  so no PIN2 opens it; with PIN1, `ocp keys add-pin2` re-encrypts the same key
  under age + a new PIN2 (k450) and nothing on the machines changes. It only
  touches keys without the layer: a key that has one, whose PIN2 is lost, is
  not helped by it, and it does not change an existing PIN2.
- **No rotation command exists.** `ocp keys` has `show`, `authorized-keys`,
  `recipients`, `operator`, `secure` and `add-pin2`, and none of them
  rotates an SSH key: `show` and `authorized-keys` print public halves;
  `recipients` is about age recipients, not SSH keys; `operator` registers
  or revokes a Leitstand's own key; `secure` only moves a dev-mode project
  that has no keys.yaml yet; `add-pin2` re-encrypts the same admin key under
  a missing PIN2 layer. `ocp init`, even
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
