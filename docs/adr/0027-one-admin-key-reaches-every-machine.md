# 0027. Reach every machine with the admin key, and keep the bootstrap key to dev mode

Date: 2026-08-15
Status: accepted

## Context

ADR 0006 describes two keys: **robo-ssh** for unattended automation, **admin-ssh**
behind PIN2 for humans. A third credential grew up beside them without ever being
decided: `.ocp/id_ed25519`, the *bootstrap key* — unencrypted, no second factor,
created by `ocp init` and used by `ocp apply` to reach a machine before the
cluster exists.

It arrived as plumbing, not as policy. karr #85 made `ocp init` create it for
`provider: ssh` in secure mode too, because a secure-mode ssh project otherwise
had nothing to authenticate with; karr #87 then wrote the resulting rule into
`OCP::ClusterKey` — *who created the machine decides which key it trusts*, with
`provider: ssh` overriding the mode rather than following it. Both changes were
right about the bug in front of them. Together they made the key model three
tiers deep, and the third tier is the one with no password on it.

Looking at what the code actually does dissolves most of the justification:

- **On Hetzner the admin key is already the bootstrap credential.** `ocp apply`
  uploads `$admin_key->{public}` through the provider API and passes
  `ssh_keys => [$key_name]` at server creation, before the machine exists. The
  bootstrap key does not appear on that path at all — a Hetzner control plane has
  never trusted it.
- **On the ssh provider the only difference is which public key a human pastes.**
  OCP cannot write `authorized_keys` on a pre-existing machine either way —
  `upload_ssh_key` is implemented for Hetzner and is a no-op everywhere else. The
  operator copies a line by hand, and since karr #84 `ocp keys show --purpose
  admin` prints exactly that line.
- **Bootstrapping is rare, interactive and human-triggered.** It is not the
  unattended path; robocop joining a worker is. A PIN2 prompt during a bootstrap
  is correct, not an obstacle.

So the third tier bought nothing on Hetzner, and on the ssh provider it bought
only the choice of which key to paste — at the price of an unencrypted private
key on the operator's disk that opens root on every node it was pasted onto.

## Decision

Two tiers, and only two, in secure mode:

- **robo** (`purpose: automation`, age-encrypted, no PIN2) — unattended
  automation. Robocop joining workers.
- **admin** (`purpose: admin`, age + PIN2) — everything a human does: bootstrap,
  `ocp update`, `ocp node add`, `ocp destroy`, `ocp ssh`.

`.ocp/id_ed25519` is removed from secure mode. `ocp init` stops creating it there,
and `OCP::ClusterKey` stops selecting it there — which retires the
"who created the machine decides" rule karr #87 introduced. Which key a machine
trusts no longer depends on its provider; in secure mode it is the admin key,
everywhere.

The bootstrap key survives in `--nopassword` dev mode alone, and not as a special
case: dev mode has no `keys.yaml`, therefore no robo key and no admin key, so
`.ocp/id_ed25519` is not a third tier there but the *only* key material there is.
That is a different mode, not an exception to this one.

The PIN2 policy this relies on is the one karr #87 already built (ADR 0006): the
key is obtained **at the point of use**, so a reconcile with nothing to repair
never prompts; **once per command**, because `OCP::Role::Cmd::cluster_ssh_key`
caches it; and **never where nobody can answer** — without a terminal the key is
refused with a message naming what it wanted, and the reconcile path turns that
refusal into a declined remedy that points at `ocp update --component X` instead
of blocking on an invisible prompt. Without those three properties this decision
would put a password prompt in front of routine work, and would not be worth
making.

### Alternatives rejected

- **Upload both public keys to Hetzner** — the obvious way to keep the bootstrap
  key working everywhere. It is the worst option available: it would turn a key
  that sits unencrypted on the operator's disk into root access on every node in
  the cluster, which is precisely what the PIN2 layer exists to prevent. Rejected
  outright.
- **Keep the third tier and document it** — the status quo after karr #85/#87. It
  leaves the most security-conscious configuration with an unprotected key that
  opens its machines, and leaves two rules ("who created the machine" and "which
  mode am I in") to be kept in agreement by hand at every new call site. Four call
  sites had already fallen out of agreement once; that was karr #87.
- **Give the bootstrap key its own weaker second factor** — a third secret to
  hold, remember and rotate, protecting a key whose entire purpose was to need no
  prompt. It would keep the tier and lose its only advantage.

## Consequences

- **Every existing `provider: ssh` machine must be given the admin public key
  before it is upgraded, or it becomes unreachable.** Those machines carry the
  *bootstrap* public key in `authorized_keys` today — that is what `ocp init`
  printed and what the operator pasted; the admin key was mentioned afterwards as
  something `ocp ssh` would want, so it may well not be there. After this change
  OCP presents the admin key and nothing else. The order is therefore mandatory
  and not a footnote:

      ocp keys show --purpose admin        # on every existing ssh machine:
      #   >> ~/.ssh/authorized_keys        # paste, verify, THEN upgrade OCP

  Verify before upgrading, not after. A cluster upgraded first and distributed
  second cannot be reached by the tool that would fix it.
- **The failure mode of skipping the migration is illegible by default**, and the
  decision therefore owes a diagnosis. An unmigrated machine refuses the admin key
  like any other stranger: an SSH authentication timeout, a network-shaped message
  for what is really "that machine has never heard of this key". This is exactly
  the illegibility karr #85 removed in the other direction. A bootstrap key still
  lying in a secure-mode project is the recognisable signature of a cluster
  authorised before this decision, and OCP has to say so by name when a connection
  fails. Note what that is and is not: a hint after the fact, not a preflight —
  nothing asks whether a host will accept the admin key *before* OCP starts
  changing things, so the operator is still told after the door has shut.
- **Falling back to the bootstrap key when the admin key is refused is
  forbidden.** It is the obvious way to make the migration painless and it would
  quietly restore the third tier through the back door, on exactly the machines
  this decision is trying to get rid of it on.
- **`ocp init` must name the admin key as the one to distribute.** For
  `provider: ssh` it historically printed `.ocp/id_ed25519.pub` as the key to
  install and mentioned the admin key only as a follow-up for `ocp ssh`. Unless
  that is inverted, every *new* secure-mode ssh project is born with the same
  lockout this decision creates for existing ones.
- **`ocp destroy` is an open problem, not a solved one.** Its SSH branch used to
  trust the bootstrap key, which cost nothing; under this decision it needs the
  admin key, hence PIN2, hence a lookup that can prompt and can die — while every
  delete deliberately sits in its own `eval` so that a host which is already gone
  is a warning rather than the end of the run. A failing lookup *inside* that loop
  would abort it and strand paid Hetzner servers on a mixed cluster, so the key
  must be acquired **once, before the loop**, and its absence must not be fatal.
  That keeps the API deletions working, but the honest outcome is then a *partial*
  teardown — Hetzner servers removed through the API, ssh nodes left running with
  RKE2 on them — and a teardown that did not finish may never report as one that
  did (ADR 0017). This decision creates that obligation; it does not discharge it.
- **The last unattended way back in is gone.** The bootstrap key was, in effect, a
  second door: an operator who lost PIN2 could still reach an ssh-provider machine
  with it. Now losing PIN2 means losing SSH to every machine in the project, and
  rotating the admin key locks the operator out of every `provider: ssh` machine
  until the new public half has been distributed by hand. Rotation stops being a
  local operation.
- **`ocp keys show --purpose admin` becomes load-bearing.** It is no longer a
  convenience; it is the only supported way to make a pre-existing machine
  reachable. karr #84 is a dependency of this decision, not an unrelated nicety.
- **A dev-mode project cannot become a secure-mode project by itself.** Its
  machines trust `.ocp/id_ed25519` and there is no path that hands them the admin
  key — the same manual distribution, with no command that performs it.
- **What is now forbidden:** reaching a secure-mode machine with anything but the
  admin key, and any new call site that reads `$config->ssh_private_key_path`
  directly. `OCP::ClusterKey` is the only place that answers which key to use, and
  in secure mode it has exactly one answer.

## Provenance

This ADR was written the day the decision was taken and ahead of the code that
carries it out, because the migration above had to exist in writing before a
running cluster met it — six machines are affected as this is written. It is
therefore a record of a decision, not a report on a finished change: the two
places that have to move are `OCP::ClusterKey`, which selected the bootstrap key
whenever the provider was `ssh`, and `OCP::Cmd::Init::_ensure_bootstrap_key`,
whose gate was `$no_password_mode || $provider eq 'ssh'` and becomes
`--nopassword` alone. Anything still reading `$config->ssh_private_key_path`
outside dev mode is the same bug under another name.
