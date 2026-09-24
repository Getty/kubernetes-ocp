# 0030. Trust a machine's host key on first use, record it in a local known_hosts, and verify it on every later connection

Date: 2026-09-24
Status: accepted

## Context

OCP reaches every machine over two SSH clients:

- **`OCP::SSH`** runs the OpenSSH client as a subprocess. It handles readiness
  checks, helper commands and uninstalls.
- **`OCP::Rex`** runs `share/Rexfile` in a child process. The Rexfile uses
  `Rex::Interface::Connection::LibSSH`, which is libssh in-process through
  `Net::LibSSH`. It does the RKE2/K3s install.

Until k168 neither client checked host keys. `OCP::SSH` passed
`StrictHostKeyChecking=no` with `/dev/null` as the known_hosts file. It
accepted any key and recorded nothing. The Rexfile carried a comment saying
checking was disabled, and the libssh stack of that time did not enforce it.

Commit 80f3b36 (2026-09-23, k133) regenerated `cpanfile.snapshot` and brought
in `Rex::LibSSH` / `Net::LibSSH` 0.004. That release is an upstream fix for
CWE-322 (key exchange without entity authentication). It made libssh verify
the server's host key by default and refuse a host it cannot find in
known_hosts. libssh only verifies. It has no accept-new mode, so it cannot
record a key the first time it sees a host.

The effect showed up live on 2026-09-24 (k168). A fresh `provider: ssh`
project on an image built from main passed the `OCP::SSH` readiness check.
Then Rex failed in `install_rke2_server` with `host key is not in known_hosts
and strict_hostkeycheck is on`. The container is `--rm` and has no
known_hosts, so every machine OCP installs through Rex was affected:

- control planes;
- workers on the CLI fallback path;
- workers reached by robocop from inside its pod.

The card first blamed k139, the removal of the local
`Rex::Interface::Exec::LibSSH` overlay. The cause was the snapshot bump.

There were therefore two questions:

- **Which key does OCP trust?** An empty file breaks everything. A disabled
  check means an attacker on the path receives the join token and the
  cluster's SSH session.
- **Where does the trusted key live?** Three places run OCP:
  - a laptop with a project directory;
  - a CI job that checks the repository out fresh and never commits back;
  - a robocop pod that has no project directory at all.

Two facts shaped the answer to the second question:

- **A host key is nothing the user could have set.** By the test in ADR 0004
  that makes it local state, not spec.
- **Hetzner reuses addresses.** A key recorded for an IP says nothing about
  the next server that gets the same IP.

## Decision

Host keys are **trusted on first use (TOFU)** and verified on every
connection after that, over both clients and against one file (k168, commit
b658a13).

- **OpenSSH records, libssh verifies.** `OCP::SSH` runs ssh with these
  options:
  - `StrictHostKeyChecking=accept-new`;
  - `UserKnownHostsFile=<OCP's file>`;
  - `GlobalKnownHostsFile=/dev/null`, so the answer does not depend on the
    machine OCP runs on;
  - `HashKnownHosts=no`, so `OCP::KnownHosts` and a human can read the file.

  The first successful contact records the key. `OCP::Rex` checks the file
  before each task. If the host is not in it, `OCP::Rex` calls
  `OCP::SSH->learn_host_key` once and only then starts Rex. The Rexfile gets
  the path as `OCP_KNOWN_HOSTS` and sets `StrictHostKeyChecking=yes` against
  it. The check stays on, in the client that cannot record.
- **`OCP::KnownHosts` never writes a key.** It owns everything around the
  file:
  - where the file is;
  - whether a host is in it;
  - the SHA256 fingerprint that `OCP::SSH` logs on STDERR at first contact;
  - removing entries;
  - the `ssh-keygen -R` hint.

  Recording stays with OpenSSH, so the file is always in a format both
  clients read.
- **A changed key stops the run loudly.** `OCP::SSH` and `OCP::Rex` both die.
  The message says that the recorded key no longer matches, names the two
  possible causes (the machine was reinstalled or replaced, or something is
  intercepting the connection) and prints the exact `ssh-keygen -R` command.
  OCP never replaces a recorded key on its own.
- **The CLI's file is `.ocp/known_hosts`, local and not committed.** `OCP`'s
  `BUILD` exports it as `OCP_KNOWN_HOSTS` for a CLI run. This happens only for
  the `MooX::Cmd` construction, and an explicit `OCP_KNOWN_HOSTS` from the
  caller wins. The file sits next to `status.yaml` under the gitignored
  `.ocp/`. A fresh clone learns the keys again on its first contact.
- **Entries are managed per machine, not per cluster.** `OCP::Provider::Hetzner`
  forgets an address's keys at two points:
  - in `wait_for_running`, the moment a server receives its address, before
    anything has connected to it;
  - in `delete_server` when it is given the host, which is the path through
    `OCP::Node->teardown`.

  `ocp destroy` does not clear the file. This is a deliberate departure from
  ADR 0004's rule that cluster status dies with the cluster. See Consequences.
- **robocop does TOFU per pod.** robocop has no project directory, so
  `OCP::KnownHosts->default_file` falls back to
  `$TMPDIR/ocp-known_hosts-<uid>`. In the pod that path is on the `/tmp`
  `emptyDir`, which has three properties:
  - the forked reconcile children share it (ADR 0029, k159);
  - it survives container restarts;
  - it is gone when the pod is gone.

  A new pod trusts each worker again on its first contact, and the fingerprint
  goes to robocop's log. Pinning fingerprints in `OCPNode` status, so that a
  new pod verifies instead of trusting, is k171.

### Alternatives rejected

- **Turn strict checking off, in libssh as it already was in OpenSSH.** This
  was the obvious one-line fix for k168. It would undo, on purpose, the
  upstream CWE-322 fix that caused the break. OCP sends the cluster join token
  and runs root installs over these connections. An unauthenticated key
  exchange hands both to whoever sits on the path. TOFU costs one extra
  connection per new host.
- **Commit known_hosts next to the encrypted files.** A host key fails the
  ADR 0004 test: the user could not have set it. ADR 0005 commits what cannot
  be re-derived, and a host key is re-derived by connecting. Committing it
  also fails in two concrete ways:
  - Hetzner reuses addresses, so a committed entry becomes a false "host key
    changed" alarm for the next cluster that gets the IP.
  - CI never commits back. Keys learned in a CI run would be lost anyway, and
    the committed file would go stale against a cluster that CI rebuilds.
- **Pin keys with `ssh-keyscan` at `ocp init` or before the first
  connection.** This is not stronger than TOFU. `ssh-keyscan` over the same
  network path trusts the same first answer, without authentication. It also
  adds a step and a second code path that writes the file. At `ocp init` there
  is often no machine yet: Hetzner servers do not exist until apply. Real
  pinning needs the key from an independent channel, such as Hetzner's
  console, cloud-init output or the `OCPNode` status in k171. OCP does not
  have such a channel yet.

## Consequences

- **The first contact is still unauthenticated.** TOFU protects every
  connection after the first, not the first. For robocop "the first" means
  per pod, so every reschedule opens a new trust-on-first-use window for every
  worker the pod reaches. The fingerprint in robocop's log is the only record
  of what was trusted until k171 lands.
- **A reinstalled machine at the same address stops the run.** This is by
  design, and it applies to every `provider: ssh` or `local` host that is
  reprovisioned. `ExistingHost`'s `delete_server` does not forget the key,
  because the machine keeps existing after OCP uninstalls from it. The
  operator reads the error, confirms that the rebuild was theirs, and runs the
  printed `ssh-keygen -R` command. OCP will not guess on the operator's behalf.
- **`.ocp/known_hosts` outlives `ocp destroy`.** ADR 0004 says a locally held
  fact about the cluster dies with it. This file is not a fact about the
  cluster. It is a fact about machines and addresses, and those have their own
  lifetimes:
  - On Hetzner, `wait_for_running` clears an address before its first use.
    So an entry left behind by a destroyed cluster never reaches the next
    server with that IP. `ocp destroy`'s own Hetzner delete passes only the
    server id, so it relies on this.
  - On `provider: ssh` the machine survives the destroy, so its key is still
    correct.

  A destroy cleanup would add a second place that removes entries and would
  still miss addresses that were deleted out of band. ADR 0004 is amended to
  name this exception.
- **Hetzner is the only provider that forgets entries.** A new provider that
  hands out addresses from a pool owes the same `forget` at the moment an
  address is assigned. If it is missing, the first connection fails as
  "changed". That is loud, not silent, but it is still a bug.
- **Every OCP connection must go through the one file.** A new SSH path that
  builds its own options, or a Rex run without `OCP_KNOWN_HOSTS`, either
  refuses every host or silently checks `~/.ssh/known_hosts`. When the
  Rexfile is run by hand without the variable, libssh checks
  `~/.ssh/known_hosts`, strictly.
- **Now forbidden:**
  - `StrictHostKeyChecking=no` or a `/dev/null` known_hosts in any OCP code
    path;
  - replacing a recorded key without an operator's action;
  - committing `.ocp/known_hosts`;
  - writing entries from anything other than OpenSSH's accept-new.
- **Verified:**
  - by the binding Docker suite (103 files, 1592 tests, `t/168-host-key-tofu.t`);
  - by an end-to-end run in the image against a throwaway sshd, covering four
    cases: first-use record, later verify, changed-key refusal, and recovery
    after running the printed hint.

  **Not yet verified** at the time of writing: the fix against a real `ocp
  apply` on the host that exposed k168, which waits for a new image, and
  robocop's per-pod path in a live cluster.
