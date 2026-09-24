# 0028. Inject the robo key into robocop in memory over a port-forward, and make a restart ask for it again

Date: 2026-09-24
Status: accepted

Supersedes ADR 0026.

## Context

ADR 0026 recorded a stub, not a design. `OCP::Robocop` checkpointed itself
through CRIU into `/dev/shm`, listened on `0.0.0.0:9999` for a key payload
that nothing could send, and then slept. `ocp inject-key`, the only producer,
had been removed from the CLI entirely (k59), and the port-forward it
needed did not exist in any client OCP could use. ADR 0026 said the stub would
be superseded once k1 made that port-forward available. k1 is done:
`Net::Async::Kubernetes` is in use and has `port_forward`.

Meanwhile k129 answered most of the question of how the robo key reaches the
cluster, without the port-forward. `robocop.security_level` has three values:

- `secret` — `ocp deploy-robocop` decrypts the robo key with PIN1 and writes it
  into the `robocop-credentials` Secret. A pod restart self-heals.
- `secret_approved` — the same, but writing the Secret is gated behind PIN2.
- `inject` — accepted by the config and refused at deploy time with "not yet
  available (k2)".

So the open question was not "Secret or port-forward". The body of k2
proposed a Secret on 2026-08-15, before k129 existed. Once k129 existed, a
Secret-based `inject` would have been `secret_approved` under a third name. What
`inject` still needed was the one property the Secret levels cannot have: the
private robo key is **never at rest** in the cluster. It is not in a Secret, not
in etcd, not in the pod's environment and not on the node's disk. This is the
original never-on-disk design that the `bin/robocop` POD had described since
before the stub.

The maintainer decided this on 2026-09-24 (k2): `inject` means port-forward
and never-on-disk. After a pod restart there is no CRIU restore. robocop
visibly needs a new injection, and the admin runs `ocp inject-key` again.

## Decision

Under `robocop.security_level: inject`, the private robo key reaches robocop
at runtime through a Kubernetes port-forward and lives only in the controller's
memory.

- **One protocol, defined once.** `OCP::Robocop::KeyInjection` holds both ends
  of the wire format:
  `OCP-INJECT-KEY 1 <length>\n<key>`, answered by `OK <fingerprint>\n` or
  `ERR <reason>\n`. The fingerprint has the `SHA256:` form that `ssh-keygen -l`
  prints, so the admin can compare it with `ocp keys show`.
- **Loopback only.** robocop listens on `127.0.0.1:9999`. A port-forward enters
  the pod's network namespace and dials localhost, so it is the only way in.
  No Service, no cluster-wide listener.
- **Only the expected key.** The Secret carries the robo key's *public* half
  (`robo-ssh-public-key`), and the Deployment exposes it as
  `ROBO_SSH_PUBLIC_KEY`. robocop accepts only an unencrypted OpenSSH private key
  whose public half matches. Someone who can port-forward into `ocp-system`
  still cannot plant a key of their own. In inject mode a `ROBO_SSH_KEY` in the
  environment is a fatal startup error, not a fallback.
- **In memory, and tmpfs where a file cannot be avoided.** Rex reads keys from
  files, so `OCP::Node` still writes a temp key (`OCP::TempKeyPair`). In the
  inject Deployment variant, `/tmp` is an `emptyDir` with `medium: Memory`, so
  that file never reaches the node's disk.
- **A missing key is visible.** A robocop in inject mode starts without a key
  and says so in three places:
  - In its log.
  - In its readiness. The probe tests `/tmp/robocop-key-ready`, which exists
    exactly while a key is held and is removed on start. Until then the pod
    is not Ready.
  - On every OCPNode in `Pending`, `Provisioning` or `Installing`, the phases
    whose next step needs SSH. These nodes are not handed to `OCP::Node`. They
    keep their phase and carry `SSHKeyAvailable=False` with reason
    `KeyInjectionRequired` and a message that names `ocp inject-key`. The phase
    stays as it is because the node has not failed. It is waiting, and the
    condition says what it is waiting for.

  When a key arrives, robocop schedules a reconcile of every OCPNode, because
  the held nodes get no further watch event.
- **No checkpoint, no restore.** A pod restart loses the key, and robocop
  reports the missing key as above. It does not try to recover the key.
- **Injection is an admin act.** `ocp inject-key` needs PIN1 (the age layer)
  and PIN2 as admin approval. The PIN2 gate is `require_admin_approval` in
  `OCP::Role::Cmd`, which `secret_approved` also uses. The robo key alone
  decrypts with PIN1, but putting it into a running controller has the same
  weight as `secret_approved`'s Secret write, so both acts share one gate. The
  command sends the key to every running robocop pod and exits 1 if any pod
  does not accept it.
- **One Deployment, shaped per level.** `OCP::Robocop::Manifest` changes the
  shipped `share/robocop/deployment.yaml` for `inject`: it drops the private-key
  env, adds the level and the public key, sets `/tmp` to Memory and adds the
  readiness probe. `ocp deploy-robocop` and `ocp apply` both apply it through
  this one transform.

The CRIU/9999 stub in `OCP::Robocop` is removed. `bin/robocop` has one mode,
`controller`. Any other invocation prints usage to STDERR and exits 2.

### Alternatives rejected

- **Deliver the key through a Secret.** This was the proposal in the k2 body
  on 2026-08-15. `secret` and `secret_approved` (k129) already are this
  delivery, with and without an approval gate. A third Secret level would
  duplicate them and would give up the one property `inject` exists to offer:
  the key is never at rest in the cluster.
- **Survive restarts with a CRIU checkpoint.** This is the ADR 0026 stub. A
  checkpoint that holds the key is the key at rest under another name: it sits
  in `/dev/shm` and is only as safe as whatever can read that file. It also
  needs the `criu` binary and privileges the pod otherwise does not need. A
  restart that visibly asks for the key again is the honest price of
  never-on-disk.
- **Listen on all interfaces** (`0.0.0.0:9999`, as the stub did). This makes
  the injection port reachable from anywhere in the cluster network, when the
  only intended caller arrives through the port-forward on loopback anyway.
- **Accept whatever key arrives.** Port-forward permission in `ocp-system`
  would then be enough to swap robocop's identity for an attacker's key. The
  public-half match costs one environment variable.
- **A second `deployment.yaml` for inject.** Two files that differ in a handful
  of lines would drift apart. One transform applied by both deploy paths cannot
  drift.
- **Mark held nodes `Failed`.** `Failed` means retry with backoff, and nothing
  about the node is wrong. A condition plus an unchanged phase says what the
  node is waiting for without triggering a retry.

## Consequences

- **An `inject` cluster cannot recover unattended from a robocop restart.**
  Node rollover, eviction, OOM and image updates all stop worker provisioning
  until a human with PIN2 runs `ocp inject-key`. This is intended. `secret` is
  the default because an automation controller normally has to survive restarts
  on its own.
- While robocop is not Ready, `ocp apply` falls back to reconciling OCPNodes
  from the CLI after its 60-second wait. The two-trigger design in ADR 0003
  makes this safe, and it is the expected behaviour, not a failure.
- The readiness signal now means "holds a key", not "process is up". Anything
  that reads robocop's readiness as liveness will misread an inject cluster
  that is waiting for a key.
- The key is still in cleartext in memory and, for as long as Rex needs it, in
  a tmpfs file inside the pod. Anyone who can `exec` into the robocop pod or
  read its memory can take the key. Never-on-disk is not never-exposed.
- The Memory-backed `/tmp` counts against the pod's memory. It is small, but
  it is not free.
- The robo key must be in `authorized_keys` on every worker robocop reaches.
  On Hetzner the provider uploads it (`ocp-<name>-robo`, k101). On the ssh
  provider the operator installs it by hand, as with the admin key (ADR 0027).
- Dev mode (`--nopassword`) cannot use `inject`: there is no `keys.yaml` and
  therefore no robo key. `ocp inject-key` refuses and says why.
- **Now forbidden:**
  - Putting the private robo key into a Secret, the environment or a
    checkpoint under `inject`.
  - Reintroducing a listener that binds anything other than loopback.
  - Accepting an injected key without the public-half check.
- **Unverified at the time of writing.** The binding Docker suite is green
  (96 files, 1491 tests), but k2 stays in review until a real-cluster test
  confirms three things:
  - The kubelet accepts `Net::Async::Kubernetes`'s `v4.channel.k8s.io`
    port-forward, including the two-byte port header on each channel.
  - The websocket works with an RKE2 client-certificate kubeconfig.
  - The image contains `test` for the exec readiness probe.
- ADR 0021's consequence that `ocp inject-key` stays disabled, and ADR 0006's
  consequence that the robo key is never deployed, no longer hold. Both are
  amended to point here.
