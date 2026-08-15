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
`age.key.enc`, so possessing the repository yields no *access* on its own. It
does yield the project's *identity*: every SOPS file OCP writes names its age
recipient in plaintext, so any checkout can answer "which key does this project
belong to" without holding one. That distinction is load-bearing —
`OCP::Secrets::age_key_bindings` reads it, and `generate_age_key` refuses to
mint a new key while anything is bound to a recipient.

PIN2 is prompted at the point where a human is present and control-plane access
is actually being used — never earlier, and never once per component *(amended
2026-08-15, see below)*.

`--nopassword` dev mode has no `keys.yaml` and therefore no admin key at all, so
a single unencrypted key stands in and nothing prompts; the absence of
`keys.yaml` is how dev mode is detected. Which key reaches which machine in
secure mode is settled by ADR 0027, and `OCP::ClusterKey` is the single place
that answers it for every command that asks.

Three rules govern the prompt itself:

- **At the point of use.** The key is obtained where an SSH connection is about
  to be opened, not at the top of the command. A reconciling `ocp apply` that
  finds nothing to repair never prompts; only a Rex remedy that is actually due
  does. `ocp apply --dry-run`, `ocp status` and drift *detection* never prompt,
  because they never open an SSH connection at all.
- **Once per command.** `OCP::Role::Cmd::cluster_ssh_key` caches the key per
  project, so an `ocp update` walking three components asks once, not three
  times, and the temp file lives exactly as long as the command that needed it.
- **Never where nobody can answer.** Without a terminal — a piped or scheduled
  run — the admin key is refused with a message naming what it wanted, rather
  than blocking on an invisible password prompt. On the reconcile path that
  refusal becomes a declined remedy which is reported, not an exception that
  ends the run.

So on a secure-mode cluster, `ocp ssh`, `ocp update`, `ocp node add` and the
first deploy of `ocp apply` prompt; a reconciling `ocp apply` prompts only when
a repair is actually due *(amended 2026-08-15, see below)*.

`ocp destroy` is the hard case, and ADR 0027 carries it: teardown is best-effort
per node, with every delete in its own `eval` so a host that is already gone is
a warning rather than the end of the run — and a PIN2 lookup that can die must
not be allowed to abort that loop and strand paid servers.

By intent, the robo-key does not reach control planes.

### Alternatives rejected

- **One key for everything** — either automation blocks on a prompt or the
  control plane is reachable unattended from wherever automation runs.
- **No PIN, rely on repository access control** — the ciphertext is committed
  on purpose, so repository access is not a boundary.
- **Keys outside the repository** — see ADR 0005; the project would stop being
  self-contained.
- **Keeping the decrypted admin key on disk so the non-interactive paths can
  read it without PIN2** — the third way karr #87 weighed. It removes the second
  factor while leaving its name in place: the artefact it produces is precisely
  the one the password layer exists to prevent.
- **Leaving `ocp update`, `ocp node add` and drift remediation unusable on
  secure-mode clusters and documenting that** — the interim state karr #87
  recorded. It makes the most security-conscious configuration the least
  operable one, which is a reliable way to get people to stop choosing it.

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
- A secure-mode cluster cannot be updated or extended unattended. No flag,
  environment variable or file supplies PIN2 to `ocp update` or `ocp node add`;
  a human at a terminal is the mechanism. That is the deliberate price of the
  second factor, and it means CI cannot own those commands. ADR 0027 widens this
  from "clusters OCP created" to every secure-mode cluster.
- The admin key exists in cleartext on disk for as long as a command needs it:
  Rex and ssh read a key from a file, and Rex additionally expects
  `key_file.pub` beside it. `OCP::ClusterKey` owns both files and removes them
  when it goes away, including while Perl unwinds out of a `die` — but the
  window is real, and any new consumer of the key must go through that object
  instead of writing its own copy.
- A reconcile can now find drift and decline to repair it *for a key reason*.
  That outcome has to be reported rather than folded into the count, which is
  why `ocp apply` says the run did not bring the cluster back to spec instead of
  "all components up to date" (ADR 0017).
- The teardown path cannot simply call `cluster_ssh_key`: a lookup that may
  prompt and may die has to be hoisted out of the per-node `eval` loop, or a
  missing key stops OCP from deleting servers that cost money. ADR 0027 makes
  this an obligation rather than an avoidable one, and records what a partial
  teardown then has to report.
- `ocp ssh` and `ocp apply`'s first-deploy prompt sit outside the rules above:
  both reach for the admin key unconditionally, in every mode and on every
  provider. In `--nopassword` dev mode there is no admin key to find, so
  `ocp ssh` cannot work there at all. Tracked as karr #94, and largely dissolved
  by ADR 0027 — once the admin key is the only secure-mode credential,
  unconditional is the right behaviour for secure mode and only dev mode is left
  to handle.

## Amendment 2026-08-15

This ADR used to say, under `## Decision`:

> PIN2 is prompted exactly where a human is present and control-plane access is
> being used: `ocp apply` in secure mode, and `ocp ssh`. `destroy`, `update` and
> the `node` commands do not prompt.

The sentence before the colon is the decision, and it stands. The list after it
was wrong on the day it was written, and wrong in the way that is hardest to
see: every entry was an accurate report of what the commands did, and three of
them did it for a reason that had nothing to do with this decision.

`ocp update`, `ocp node add` and the reconcile path's Rex remedy did not prompt
because they never got that far. All three handed Rex
`$config->ssh_private_key_path` — `.ocp/id_ed25519` — as the key to log in with.
On a machine OCP created, that key was never distributed: the admin public key
goes up through the provider API before the server exists, and `ocp init` does
not create a bootstrap key for that combination at all (karr #85). So on a
secure-mode Hetzner cluster `ocp update` died with "cannot read SSH key",
`ocp node add` could not fetch the join token, and drift remediation declined
every finding it made. The missing prompt was breakage, and this ADR recorded it
as policy — which is the specific failure the record exists to prevent, because
"these commands need no second factor" reads as a licence to keep them that way.

Nothing about the decision moved, and this is not a reversal. `OCP::ClusterKey`
(karr #87) gathered the question into one place and made the decision apply
consistently, so three commands now prompt where they used to fail — the
decision doing its work rather than a change of mind. The particular selection
rule #87 arrived at, *who created the machine decides which key it trusts*, was
itself short-lived and is settled instead by ADR 0027, which removes the
unencrypted third credential the rule existed to choose.

`ocp destroy` was the only entry on the old list that was ever a decision rather
than a bug: its SSH branch is gated on the *node's own* provider, and nothing on
the teardown path may be able to die, because a key lookup outside the per-node
`eval` would abort the loop and strand paid servers. ADR 0027 brings it under
the admin key too and keeps that constraint as an obligation on how the key is
acquired, not as a reason to exempt the command.

Added in the same pass, not corrected: the three rules governing when the prompt
fires (point of use, once per command, never without a terminal) had never been
written down anywhere, and the wrong enumeration is what stood in for them. The
PIN1 paragraph gained the distinction between access and identity — possessing
the repository still yields no access, but it does yield the recipient that
every SOPS file names in plaintext. That is not a weakening of the outer gate;
it is the fact `ocp init` failed to consult when it minted a fresh age key over
a clone's committed material and orphaned it (karr #86). Recorded under karr #87
and #86.

This ADR keeps `Status: accepted`. Its decision — two keys in `keys.yaml`, two
encryption strengths, two threat models — is untouched by ADR 0027; what 0027
removes is the unencrypted third credential that had grown up beside those two
without ever being decided here.
