# Security model — PIN1 and PIN2

OCP's premise is that a cluster project should be safe to commit to git,
including its secrets. That works because every secret is encrypted at rest
with age/SOPS, and two independent PINs stand in front of the key material.

Which mode a project uses is chosen at `ocp init`. A dev-mode project can be
moved into secure mode later with `ocp keys secure` (below); there is no way
back.

## Secure mode (the default)

Every secret — `age.key.enc`, `keys.yaml`, `secrets.yaml`, `kubeconfig.yaml` —
is encrypted and safe in a public repository. Two PINs protect it:

- **PIN1 unlocks `age.key.enc`**, the master key behind every encrypted file in
  the project. Without it nothing is readable. This is the outer gate, by
  design.
- **PIN2 unlocks the private half of the admin SSH key** inside `keys.yaml`.
  That admin key is the *only* key any `ocp` command uses to reach a machine —
  on Hetzner, over SSH, or locally; control plane or worker. The one exception
  is a registered operator (a Leitstand, below), which brings an age identity
  and an SSH key of its own and runs without either PIN.

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
| `ocp keys secure` | sets PIN1 and PIN2 (each twice); PIN2 once when it continues, or for `--drop-bootstrap` on a secure project |
| `ocp keys operator add` / `rm` | PIN1, and PIN2 when there are machines to reach |
| anything, as an operator (`SOPS_AGE_KEY_FILE` + `OCP_OPERATOR_KEY`) | nothing — see below |

## Dev mode (`ocp init --nopassword`)

A single unencrypted SSH key at `.ocp/id_ed25519` and no PIN prompts, ever.
`kubeconfig.yaml` is still encrypted even in this mode. Use it for local
experiments and nothing you would mind losing.

## From dev mode to secure mode (`ocp keys secure`)

A dev-mode project's machines trust `.ocp/id_ed25519` and nothing else, and
secure mode never offers that key. Creating `keys.yaml` by hand would
therefore lock OCP out of every machine. `ocp keys secure` makes the switch in
the one order that cannot:

1. It sets PIN1 (unless `age.key.enc` exists already) and PIN2, and generates
   the admin and robo keys into `.ocp/keys.yaml.pending` — not `keys.yaml`,
   because `keys.yaml` is what makes a project secure for every other command.
2. It appends both public keys to `/root/.ssh/authorized_keys` on every
   machine of the cluster, logged in with the bootstrap key that still works:
   the control planes, and every worker an OCPNode names. A key that is
   already there is not added twice.
3. It logs in to every machine with the admin key, and with nothing else.
4. Only when every machine passed: `age.key.enc` and `keys.yaml` are written.
   Commit both.

```bash
ocp keys secure                     # PIN1, PIN1, PIN2, PIN2
ocp keys secure --drop-bootstrap    # and remove the bootstrap key afterwards
```

If a machine fails, the command names it on STDERR and exits 1; the project
stays in dev mode, the staged keys stay in `.ocp/`. Fix the machine and run it
again: it continues with the same keys (PIN2 once, to unlock them).

After the switch it does what `ocp apply` would: on Hetzner it stores both
public keys in the project under `ocp-<name>-admin` / `ocp-<name>-robo`, where
dev mode had stored the bootstrap key, so servers created later get them; and
with robocop enabled it writes robocop's credentials Secret with the new robo
key and restarts a running robocop. When there is no cluster yet, robocop gets
them with the first `ocp apply`.

Workers listed in `ocp.yaml` that have not joined yet are not machines yet:
the command names them, and they need both keys before they join
(`ocp keys authorized-keys`).

The bootstrap key stays in `authorized_keys` until you remove it:
`ocp keys secure --drop-bootstrap` deletes its lines on every machine, logged
in with the admin key, and only where the admin key has just been accepted.
It never deletes `.ocp/id_ed25519` itself — it tells you when nothing it
reaches still trusts the key, and the rest is yours.

## A Leitstand: an operator that runs `ocp apply` unattended

A Leitstand — a control machine that reconciles the cluster on its own — cannot
answer a PIN prompt. It runs as an **operator** with two keys of its own, and
hands over only their public halves:

- an **age identity**, which it decrypts the project's SOPS files with. OCP
  reads it from `SOPS_AGE_KEY_FILE`, as sops does;
- an **SSH key**, which every machine of the cluster trusts and which OCP
  reaches them with when the run's age identity is the operator's. OCP reads
  the private half from the file `OCP_OPERATOR_KEY` names.

The human with the project key registers it once:

```bash
# on the Leitstand
age-keygen -o ~/.config/ocp/age.key          # prints its recipient, age1...
ssh-keygen -t ed25519 -f ~/.ssh/ocp-leitstand

# where the project key is (PIN1, PIN2)
ocp keys operator add --name leitstand \
    --ssh-pubkey ocp-leitstand.pub --age age1...
```

`add` first appends the SSH public key to `/root/.ssh/authorized_keys` on every
machine of the cluster — the control planes and every worker an OCPNode names —
logged in with the admin key. Only when every machine took it does it record
the operator: an entry in `keys.yaml` (purpose `operator`, the public key and
the age recipient, **no private key**) and the age recipient in `.sops.yaml`,
with `keys.yaml`, `secrets.yaml` and `kubeconfig.yaml` re-encrypted for it. A
machine that refuses is named and nothing is recorded; run the same command
again once it is fixed — it adds nothing twice. Commit the result.

From then on the Leitstand runs without a prompt:

```bash
SOPS_AGE_KEY_FILE=~/.config/ocp/age.key \
OCP_OPERATOR_KEY=~/.ssh/ocp-leitstand \
ocp apply
```

What changes under `SOPS_AGE_KEY_FILE` (set and not empty):

- That file is the age identity of every decrypt. PIN1 is never asked, and
  nothing lands in `.ocp/`: the identity is not copied to `.ocp/age.key`, and
  `.ocp/age.pub` is never derived from it. `age.key.enc` stays the project
  key behind PIN1. A missing or unreadable file is an error naming the
  variable.
- What OCP writes stays encrypted for the project key. Without `.ocp/age.pub`
  it reads the project's recipient off the committed files; when they cannot
  tell (several recipients, none of them known as an operator's), the write
  stops and says so — put the project's recipient (the first line of
  `ocp keys recipients ls` where the project key is) into `.ocp/age.pub`.
- With an operator's identity, `OCP_OPERATOR_KEY` must be set and hold the
  private half of exactly the key `keys.yaml` has for that operator; otherwise
  the run stops by name. An identity that is a recipient but no operator is
  refused when a machine has to be reached.

What an operator **cannot** do, by design:

- open the admin or robo private key: their inner age layer belongs to the
  project key alone. It reads `keys.yaml`, not the keys inside;
- give the PIN2 approval of `robocop.security_level: secret_approved` or
  `ocp inject-key` — refused, never prompted;
- make the first `ocp apply` of a cluster (no `kubeconfig.yaml` yet) — that
  one builds the machines with the admin and robo keys and is the project key
  holder's;
- write robocop's credentials Secret for the `secret` levels (it holds the
  robo private key). An existing Secret is left as it is with a `[WARN]`; a
  missing one fails the run until the project key holder runs `ocp apply` or
  `ocp deploy-robocop` once. `security_level: inject` needs only the public
  half and works as usual.

New machines: `ocp keys authorized-keys` (`all`) prints the operator keys
with the admin and robo key, so an `ssh`-provider host set up from it admits
the operators too. Hetzner servers created later get the admin and robo keys
only — run `ocp keys operator add` with the same arguments again after they
joined.

### Revoking an operator

```bash
ocp keys operator rm leitstand        # PIN1, PIN2
```

It removes every `authorized_keys` line carrying the operator's SSH key from
every machine, logged in with the admin key, then the `keys.yaml` entry and
the age recipient, and re-encrypts the files — and, like
`ocp keys recipients rm`, says on STDERR what the operator could read until
now and what to rotate. A machine that cannot be reached does not hold up the
revocation: it is named, with the line to remove there by hand, the exit code
is 1, and the entry and the recipient go anyway.

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
ocp keys authorized-keys --purpose operator     # the operators' keys alone
```

`all` includes every operator key (see the Leitstand section above); a
project without operators is complete without them.

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
