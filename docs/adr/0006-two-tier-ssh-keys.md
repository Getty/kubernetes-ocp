# 0006. Split SSH access into a robo-key and a PIN-protected admin-key

Date: 2026-08-12
Status: accepted

## Context

Two very different actors need SSH into cluster machines.

Automation — the reconciler that installs an agent on a freshly created worker —
must run unattended. It cannot prompt for anything, and if it lives in the
cluster (ADR 0001) its key is only as safe as the cluster.

A human doing `ocp ssh` into a control plane is the opposite: interactive by
definition, and holding the keys to the machine that holds the cluster.

One key for both means either automation prompts (it cannot) or control-plane
access is unattended (it must not be). The repository itself is not the
boundary, because the encrypted files are deliberately committed (ADR 0005):
anyone with repository access already holds the ciphertext.

## Decision

Two keys in `keys.yaml`, with two encryption strengths matching two threat
models:

- **robo-ssh** (`purpose: automation`) — age-encrypted only, decryptable with
  the age key alone, no second factor. This is the key automation may hold.
- **admin-ssh** (`purpose: admin`) — double-encrypted: a password layer
  (PBKDF2 + AES-256-GCM, PIN2) inside the age layer. Decrypting it requires a
  human at a prompt.

The age key itself is the outer gate: `age.key` is encrypted with PIN1 into
`age.key.enc`, so possessing the repository yields nothing on its own.

PIN2 is prompted exactly where a human is present and control-plane access is
being used: `ocp apply` in secure mode, and `ocp ssh`. `destroy`, `update` and
the `node` commands do not prompt. `--nopassword` dev mode drops to a single
unencrypted key and no prompts, and is detected by the absence of `keys.yaml`.

By intent, the robo-key does not reach control planes.

### Alternatives rejected

- **One key for everything** — either automation blocks on a prompt or the
  control plane is reachable unattended from wherever automation runs.
- **No PIN, rely on repository access control** — the ciphertext is committed
  on purpose, so repository access is not a boundary.
- **Keys outside the repository** — see ADR 0005; the project would stop being
  self-contained.

## Consequences

- The "robo-key cannot reach control planes" property is a convention enforced
  by which public key is authorised where, not by cryptography. Nothing stops
  someone authorising the robo-key on a control plane.
- The robo-key is currently never deployed at all: `ocp inject-key` is
  disabled because it needs a port-forward that the Kubernetes client does not
  provide (karr #2, and ADR 0021). The two-tier model is therefore in force
  in the key store and not yet in the cluster.
- Two encryption paths mean two decryption paths, and a key's type must be
  detected rather than assumed — `decrypt_key` sniffs the envelope.
- Losing PIN2 costs the admin key; losing PIN1 costs everything (ADR 0005).
