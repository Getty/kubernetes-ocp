# 0005. Commit the encrypted files; gitignore only the decrypted state

Date: 2026-08-12
Status: accepted

## Context

An OCP project is a git repository. If the secrets it needs — SSH keys, the age
key, the kubeconfig, provider tokens — live outside that repository, then
cloning it is not enough to operate the cluster, and "where is the key" becomes
a question answered by chat messages and USB sticks.

The usual reflex is the opposite: anything that looks like a key goes into
`.gitignore`. That reflex is right for plaintext and wrong for ciphertext, and
applying it uniformly here silently breaks the model — a project that clones
without `keys.yaml` cannot reach its own machines.

## Decision

Encrypted files are meant to be committed. Decrypted state is not, and the
directory boundary carries the distinction:

| Committed (encrypted)                                   | Gitignored (`.ocp/`)                            |
|---------------------------------------------------------|-------------------------------------------------|
| `keys.yaml`, `secrets.yaml`, `age.key.enc`, `kubeconfig.yaml` | `age.key`, `age.pub`, `id_ed25519`, `keys/`, `status.yaml`, `deployed.yaml` |

Every plaintext artefact lives under `.ocp/`; every encrypted one lives in the
project root. `.gitignore` therefore needs exactly one project-specific entry —
`.ocp/` — and any pattern broader than that is a bug.

`kubeconfig.yaml` stays encrypted even in `--nopassword` dev mode, and
`ocp apply` reads it from the encrypted store rather than from any plaintext
copy that happens to be lying around.

There is no project-local `.kube/`: `ocp kubeconfig -e` merges into
`$KUBECONFIG` or `~/.kube/config`.

### Alternatives rejected

- **Secrets outside the repository** — the repository alone can then no longer
  operate the cluster, which is the property this whole layout exists to have.
- **Plaintext in the repository with a `.gitignore` guard** — one missed
  pattern is a permanent leak; here a missed pattern is at worst an
  inconvenience.
- **Asserting the `.gitignore` text in tests** — an over-broad pattern of a
  shape nobody predicted still passes. karr #7 asserts on `git check-ignore`
  instead: the four encrypted names must produce no match, `.ocp/age.key` must.

## Consequences

- Losing the age key (or PIN1) loses the project's operability. There is no
  side channel by design.
- The failure mode of a wrong `.gitignore` is invisible until someone else
  clones the project, which is why both the generated file and
  `_gitignore_content` carry a comment saying why only `.ocp/` belongs there.
- Anyone with repository access holds the ciphertext. The security boundary is
  the age key and PIN1, not repository access — which is exactly why the admin
  key gets a second factor (ADR 0006).
- Anything new that is written to the project root must be classified before it
  is written; the default answer for plaintext is "put it under `.ocp/`".
