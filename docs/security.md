# Security model — PIN1 and PIN2

OCP's premise is that a cluster project should be safe to commit to git,
including its secrets. That works because every secret is encrypted at rest
with age/SOPS, and two independent PINs stand in front of the key material.

Which mode a project uses is chosen once, at `ocp init`, and is not something
you flip later.

## Secure mode (the default)

Every secret — `age.key.enc`, `keys.yaml`, `secrets.yaml`, `kubeconfig.yaml` —
is encrypted and safe in a public repository. Two PINs protect it:

- **PIN1 unlocks `age.key.enc`**, the master key behind every encrypted file in
  the project. Without it nothing is readable. This is the outer gate, by
  design.
- **PIN2 unlocks the private half of the admin SSH key** inside `keys.yaml`.
  That admin key is the *only* key any `ocp` command uses to reach a machine —
  on Hetzner, over SSH, or locally; control plane or worker.

There is also a `robo-ssh` automation key, protected by PIN1 alone. It is
robocop's key: robocop joins and tears down workers with it. So its public
half **is** on machines, and it is a second way in: every worker carries it,
and on Hetzner the control plane does too, because OCP uploads it next to the
admin key and creates every server with both. Whoever has PIN1 can reach those
machines as root without PIN2. On the `ssh` provider you put it there
yourself, on the workers.

Which machine needs which public key, in secure mode:

| Machine | Needs | Why |
|---|---|---|
| control plane (`ssh`/`local`) | admin | every `ocp` command reaches it with the admin key |
| worker (`ssh` provider) | admin **and** robo | robocop joins and tears it down with robo; `ocp node rm`, `ocp ssh` and a join from the CLI use admin |
| any Hetzner server | admin and robo | uploaded through the API for you |

A worker with only one of the two works until the other one is needed: a
robocop join goes through on robo alone, then `ocp node rm` is refused and
leaves the node `Failed` with RKE2 still running on it.

Which commands prompt for what:

| Command | Prompts |
|---|---|
| `ocp status`, anything `--dry-run` | nothing — no SSH connection is opened |
| `ocp apply`, `ocp ssh`, `ocp update`, `ocp node add` | PIN2 (the admin key) |
| `ocp destroy` | PIN2 when an `ssh`/`local` node is involved |
| `ocp deploy-robocop` | PIN1 (credentials come out of the encrypted files) |

## Dev mode (`ocp init --nopassword`)

A single unencrypted SSH key at `.ocp/id_ed25519` and no PIN prompts, ever.
`kubeconfig.yaml` is still encrypted even in this mode. Use it for local
experiments and nothing you would mind losing.

A dev-mode project cannot currently be migrated into secure mode.

## What goes into git

**Commit these** — all encrypted, safe in a public repo:

```
ocp.yaml          keys.yaml         secrets.yaml
age.key.enc       kubeconfig.yaml
```

**Never commit `.ocp/`.** It is local, gitignored state: the decrypted key
cache and runtime status. `ocp init` sets the ignore rule up for you.

## Getting the public keys out

To authorise OCP on a machine you own (the `ssh` and `local` providers), put
its public keys into its `authorized_keys`. `ocp keys authorized-keys` prints
exactly those lines:

```bash
ocp keys authorized-keys                    # admin + robo: an ssh worker
ocp keys authorized-keys --purpose admin    # admin: a control plane
ocp keys authorized-keys --purpose automation   # robo alone
```

It puts **only** `authorized_keys` lines on STDOUT and every diagnostic (key
names, what each key is for) on STDERR, so it pipes cleanly:

```bash
ocp keys authorized-keys | ssh root@worker 'cat >> ~/.ssh/authorized_keys'
ocp keys authorized-keys --purpose admin | ssh root@controlplane 'cat >> ~/.ssh/authorized_keys'
```

It needs PIN1 at most, never PIN2, and works before any cluster exists. In a
`--nopassword` project it prints `.ocp/id_ed25519.pub`, the only key there is.
`ocp keys show --purpose admin` prints the admin key alone, as before.

When a machine refuses a key, the error names which one is missing and the
`ocp keys authorized-keys --purpose …` line that adds it.

## Losing a PIN

Stated plainly, because there is no support channel that can undo it:

- **Lost PIN1** — everything in the project is unreadable. No recovery inside
  OCP. By design.
- **Lost PIN2** — the admin key is gone, and with it SSH access to every
  machine in the cluster. No recovery inside OCP either; out-of-band console
  access (Hetzner's web console, a KVM) is the only way back onto the machines.
- **Lost `.ocp/`** — harmless. A fresh `git clone` plus PIN1 regenerates it.

## See also

- [`ocp.yaml` reference](configuration.md)
- [robocop](robocop.md) — how join token and automation key reach the controller
- ADRs [0005](adr/0005-commit-the-encrypted-files.md),
  [0006](adr/0006-two-tier-ssh-keys.md),
  [0027](adr/0027-one-admin-key-reaches-every-machine.md)
