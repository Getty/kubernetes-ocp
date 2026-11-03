# Part C: the ocp.yaml shape checked once, before the command runs — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking. In this repo "subagent" means an `ocp-*`
> team agent, never a built-in one.

**Goal:** Every command names the ocp.yaml key paths it reads, in one list next to the
command. `OCP::Role::Cmd` checks them once, before `execute`, and refuses with every line
`validate()` has there. No command crashes on a malformed shape, and none refuses over a
key it does not read.

**Architecture:**
- `OCP::Config::spec_errors` learns every section, not only `name`, `control_planes`, `gpu`
  and `workers`.
- A command declares its paths with `spec_paths($config)`.
- The role runs `refuse_spec_errors` before `execute` and refuses in one text. It replaces
  the three refusals that exist today: destroy's, the machines role's, and
  `node add --gpu`'s.
- A sweep test runs every command against t/296's malformed shapes. It also records which
  sections a command reads, so a command that forgets to declare one fails it.

**Tech stack:** Perl 5, Moo, MooX::Cmd / MooX::Options, Test::More, YAML::XS.

**Spec:** `docs/superpowers/specs/2026-10-31-one-place-per-concern-design.md`, Part C. Parts
A (k398) and B (k399) are on main. What this part builds on:
- `OCP::Config::spec_errors` and its tagged producers (k306 step 1, `7665c48`);
- the machines role's paths (k306 2b, `19fe5ba`);
- `node add --gpu` on `spec_errors('gpu')` (k306 2c, `5170476`);
- t/398's `run_ocp` and `leaf_commands`.

**Card:** k400. It absorbs the rest of k306 (closed with a pointer here) and k394, except
the one item named under "Not in this plan".

## Decisions this plan makes (the builder's calls in the spec, made here)

1. **The declaration is a method:** `spec_paths($config)` on the command, defined right
   after its options.
   - It returns the key paths in `spec_errors`' syntax.
   - It may read the command's options and the raw config. Node add's paths depend on
     `--gpu`, destroy's on each entry's provider.
   - It must never die on any YAML shape.
   - `OCP::Role::Cmd` supplies the default `()`, which means no check.
2. **The check is `refuse_spec_errors($config)`,** public on `OCP::Role::Cmd`. A
   `before execute` in the role runs it.
   - It is skipped when the ocp.yaml file does not exist. The command keeps its own
     "Config file … not found".
   - It is skipped when `spec_paths` returns nothing.
   - Otherwise it builds `OCP::Config->new(file => $self->ocp->config)` and dies with every
     line of `spec_errors(spec_paths)`.
   - An ocp.yaml that is empty or no mapping dies with that file's one line, as every
     reader does since k340.
3. **One refusal text,** exactly:
   ```
   <file> has <N> error<s>:
     - <line>
   Nothing was done: ocp <words> checks what it reads of <file> before it asks for a PIN or touches the cluster or a machine. Fix the line<s> above and run it again.
   ```
   - `<file>` is `$config->file`.
   - `<words>` are the command words as the user types them, spelled through
     `%OCP::COMMAND_ALIASES`: `deploy-robocop`, not `deployrobocop`.
   - Destroy's, the machines role's and `node add --gpu`'s own refusals go. Their lines and
     order stay; only the frame around them changes.
   - `ocp apply` keeps `refuse_invalid_config`, and `ocp keys secure` keeps its own full
     `validate()` refusal. Both declare nothing.
4. **validate() and spec_errors read one ordered list.** That list holds every producer's
   `[tag, line]` pairs in `validate()`'s order.
   - `validate()` is the lines of that list.
   - `spec_errors(@paths)` is the lines whose tag a path matches.
   - So the order cannot differ.
   - Path semantics stay exact, as today: `network` is the shape line of `network:`, not
     the lines under it.
5. **The new paths** (C1). A line's tag is the path whose value it is about:

   | Path | Lines |
   |---|---|
   | `kubernetes` | every line under `kubernetes:`: its shape, `dist`, `version`, an unknown key (the lines `kubernetes`, `distribution` and `version` refuse on) |
   | `network` | `network:`'s shape; an unknown key of `network:` |
   | `network.pod_cidr` | not a CIDR; host bits set; too small. **Not** the overlap lines |
   | `network.lb_pool`, `network.l2` | every line under that key |
   | `cilium`, `registry`, `ssl`, `system` | every line under that section (`system.ntp` included) |
   | `ssh` | `ssh:`'s shape; a path that is no string. **Not** an unknown key (k355) |
   | `robocop` | `robocop:`'s shape, `robocop.enabled`, an unknown key (the lines `robocop_enabled` refuses on) |
   | `robocop.security_level`, `robocop.image` | that key's line |
   | `lbipam`, `nocert` | that switch's line |
   | `workers[I].labels`, `workers[I].taints` | that pool's label and taint lines |

   - `gpu` stays as it is: every line under `gpu:`, its switches included.
   - These lines stay `validate()`'s alone:
     - the ones k306 left there (a missing name, a pool's missing name, a missing provider
       requirement, the control-plane bounds, every `node_ip`, unknown keys of an entry, a
       pool or a pool's machine, an ssh pool's both-or-neither, a host on a pool that takes
       none);
     - the pod CIDR's and the service network's overlap lines. They are about other
       sections' addresses, and a running cluster must not stop reporting over them;
     - an unknown key of `ssh:`.
6. **The accessors stay the safety net and say `validate()`'s words.** This covers k394's
   wording drift and shape gaps:
   - `gpu_config`, `gpu_driver`, `gpu_amd_config`, `_gpu_amd_choice` and
     `robocop_security_level` refuse with the line `validate()` has for the same value.
     They build it with the same producer.
   - `pod_cidr`, `pod_cidr_is_set`, `lb_pool_config` (so `lb_pool_blocks`) and `l2_config`
     (so `l2_node_selector`, `l2_interfaces`) refuse with
     `spec_errors('network.pod_cidr' | 'network.lb_pool' | 'network.l2')`, joined as
     `_refuse` joins.
7. **ClusterKey (ClusterKey.pm:213)** reads the first control plane's provider only when the
   entry is a mapping and the provider a string; otherwise it reads none. That provider is
   used only in messages, so no command has to declare it for ClusterKey's sake.
8. **The sweep comes first, not last.** Task 2 adds it (C3's test) with a `%NOT_YET` list of
   the commands not moved yet. Each task takes its commands off that list, which turns the
   sweep red for them first. Task 5 deletes the list. So every task has a red test.
9. **ocp status refuses on what it reads.** That is the maintainer's choice of 2026-11-01. It
   replaces k306's earlier per-section eval idea, and k394's "one drift entry for
   `network: foo`".
10. **Executor:** one `ocp-worker` runs Tasks 1–5 in order, as in Part B. The tasks span the
    choices, apply, destroy, status and secrets lanes. It writes one patch per task,
    `$S/w-ocp400/k400-N.patch`.

## Amendments during execution (2026-11-03, the orchestrator's calls)

The worker stopped before Task 1, because existing claims contradict Decisions 6 and 9.
These calls replace the plan text where they differ.

1. **Decision 6 is narrowed to the network accessors.**
   - `gpu_config`, `gpu_driver`, `gpu_amd_config`, `_gpu_amd_choice` and
     `robocop_security_level` keep their wording. t/296 claim 21 pins it on purpose
     (`s/^gpu: /gpu /`), and t/15, t/314, t/252, t/258 and t/379 pin it too.
   - The up-front check says `validate()`'s lines anyway, so the safety net's wording is
     not what a user meets first. k394's wording item closes as not needed, with this
     reason.
   - Task 1's accessor test covers only `pod_cidr`, `lb_pool_blocks` and `l2_interfaces`.
     The mutant "gpu_driver's old wording back" becomes "`l2_config` not refusing".
   - t/292-network-keys.t's source checks stand: the network accessors keep the source
     shapes it pins.
2. **Decision 9 is refined: a command that reads around a bad value on purpose keeps
   doing so.**
   - "Reads around" means: today the command exits 0 with a WARNING line or a drift entry,
     and a test pins that.
   - Such a command does not declare that path. A comment beside its `spec_paths` names
     the section and the pinning test.
   - t/400 holds the same in `%READS_AROUND` (class → sections), so the probe accepts the
     read.
   - For `ocp status` these are `gpu:` (the `gpu.amd.allocation` WARNING, t/252:330-333,
     t/258:343-347, t/379:372) and the switches (the k332 drift entry, t/332 claim 1).
   - Every other section status reads it declares, `network:` included (k394).
   - This is no loophole: an entry needs a claim that pins exit 0 with the warning or the
     drift entry, and each entry is named in its patch header.
3. **Claim changes allowed without a stop.** Name each in the patch header, old and new.
   - A claim that pins a refusal's old frame or old wording, where the role's refusal with
     `validate()`'s lines now comes first.
   - Task 3: t/379-section-shapes.t:312-325. `update` with `cilium: foo` or `network: foo`
     now refuses before any component runs, instead of "Failed to update cilium: …" after
     cert-manager (k394).
   - Task 3: t/379:329-350. `update` on `gpu: false` gets the role's frame and
     `validate()`'s `gpu:` line.

   Any other claim change still stops.

4. **The worker's second stop (Task 2) and its two Task 3 questions.**
   - **t/333-node-add-gpu-config.t:31-33 and `%ELSEWHERE` (:314).** The header said
     `node add --gpu` is not refused by a line outside `gpu:` "because node add does not read
     it". That is false for `control_planes`, `kubernetes`, `network` and `ssh`: node add
     reads them, so under Decision 9 it declares them and refuses their lines.
     - `%ELSEWHERE` keeps only the sections node add does not read: name, workers, cilium,
       system, robocop, lbipam and nocert.
     - The header becomes "Not refused: a line validate() has in a section node add does
       not read".
     - The sections it does read are covered by t/400's sweep.
     - The claim is not rewritten as `spec_errors(<node add's spec_paths>)`, because that
       would repeat the code's own list back to it.
   - **Destroy's private `OCP::Config::_*` calls (Task 3).** The calls inside the four
     checking helpers go, and the comment at Destroy.pm:502-505 is updated. The reading
     code stays:
     - `_spec_worker_entries`' `_pool_where` and `_pool_takes_host` (the k331 decision);
     - `_shown_value`;
     - `_control_planes_shared`.

     Part C is about where the shape is checked, not about how Destroy reads.
   - **Destroy and `ssh:` (Task 3).** Destroy reads around a bad `ssh:` on purpose.
     - It goes on with a `[!!]` line and skips the uninstall, which t/353:419-438 pins (k180).
       Its exit 1 there reports the skipped uninstall. It is not a refusal.
     - So Destroy does not declare `ssh`. This case extends amendment 2's "exit 0" to "goes
       on with a pinned warning line".
     - If t/400's probe sees the read, `%READS_AROUND{Destroy} = ['ssh']` goes in, named in
       the patch header.

## Global constraints

- No new CPAN dependencies; `cpanfile` stays unchanged.
- `validate()`'s lines and their order do not change (t/296, t/255 and t/306's differential
  stay green unchanged). Tasks add tags, never lines.
- `ocp apply` and `ocp keys secure` (default mode) refuse as today.
- Every claim in `t/` stays, except the ones a task names as changing on purpose.
  - A fixture that is malformed at a path its command now declares, in a test that is not
    about that shape, gets a valid value there.
  - The report lists each such fixture change, with file and line.
- The accessors' `_refuse` stays.
- `robocop` and `OCP::Drift` stay as they are.
- Tests run only through the guarded command:
  `DOCKER_BUILDKIT=0 timeout 1800 make test TESTS="<explicit list>" IMAGE=localhost/ocp-w400`.
  Never `t/`, never an empty list.
- Mutation checks only in Tasks 1 and 2, at most five mutants per run, plus an unmutated
  control. Load Rex first and assert `%INC`.
- One patch per task, no Changes hunk; the header holds the subject ending `(k400)`, the
  description and the proposed Changes bullet. The release manager runs ONE full suite on
  the stack and commits per task.

## Review focus

1. **An ocp.yaml that is empty or no mapping.** Every declaring command says the file's one
   line, once, and exits 1: not the N-errors frame, not twice. Task 2 pins it.
2. **Options change what is read.** `node add` without `--gpu`, or with `--nowait`, does not
   refuse over a bad `gpu:`. Task 2 pins it.
3. **A bad key a command does not read** (decision 1). `ocp status` and `ocp destroy` go on.
   Tasks 3 and 4 pin it per command; the sweep checks both.
4. **An existing cluster whose default pod CIDR overlaps a node address.** No path returns
   an overlap line, so `status` and `node add` do not refuse over it. Task 1 pins it.
5. **`--json` and the refusal.** `status --json` and `node ls --json` refused by the check
   print the one JSON error object (k398), STDOUT one document, exit 1. Tasks 4 and 5 pin
   it.

---

### Task 1 (C1a): every section answers spec_errors; the accessors say validate()'s words

**Files:**
- Modify: `lib/OCP/Config.pm`:
  - the producers, so every `validate()` block is a `[tag, line]` producer in one ordered
    list (Decision 4);
  - `validate` and `spec_errors` read that list;
  - `_spec_path` learns the new paths;
  - the `spec_errors` POD table;
  - the accessors of Decision 6.
- Create: `t/lib/OCPTest/Shapes.pm`. It holds `@SHAPES` and `@AT` from
  t/296-validate-malformed-shapes.t:338-436, moved verbatim, exported as `shapes()` and
  `at()`.
- Modify: `t/296-validate-malformed-shapes.t` (uses `OCPTest::Shapes`; claims unchanged),
  `t/306-spec-errors.t`.

**Interfaces:**
- Produces: `spec_errors(@paths)` answers every path of Decision 5, in addition to today's.
  An unknown path still croaks.
- Produces: `OCPTest::Shapes::shapes() -> ([shown, value], …)` and
  `at() -> ([path, sub { spec }], …)`.

- [ ] **Step 1: Write the failing tests** in t/306.
  - Claim 1 (the differential) is extended to every new path. Over every
    `at()` × `shapes()` config, `spec_errors(@ALL_PATHS)` equals `validate()` minus the
    validate-only lines. `@ALL_PATHS` takes entries with `*`, pools with `workers[*].labels`
    and `workers[*].taints`. The oracle names the validate-only lines of Decision 5 by
    regex.
  - Claim 2 changes on purpose: labels, taints and the new sections now have paths.
  - Claim 4 changes on purpose: `lbipam` and `nocert` are at their own paths; `gpu` still
    returns no other switch.
  - Examples, each asserting `spec_errors(P)` is exactly the `validate()` lines that start
    `"P:"` (or `"P."` for a section's unknown key):
    - `kubernetes` with `kubernetes: { dist: rke3 }`;
    - `network.pod_cidr` with `pod_cidr: [ a ]`;
    - `network.lb_pool` with `lb_pool: foo`;
    - `cilium` with `cilium: { devise: [ eth0 ] }`;
    - `workers[1].taints` with `taints: foo`;
    - `robocop.image` with `image: [ a ]`.
  - Review focus 4: with a control plane `host: 10.42.0.5` and no `network:`, `validate()`
    has the overlap line, and `spec_errors('network', 'network.pod_cidr')` is empty.
  - `ssh: { privat_key: x }`: `validate()` has the unknown-key line, and
    `spec_errors('ssh')` is empty.
  - Accessors (Decision 6). Over `at()`'s entries at `gpu`, `gpu.driver`, `gpu.amd`,
    `gpu.amd.allocation`, `robocop.security_level` with every shape:
    - the accessor of that key dies with exactly the `validate()` line(s) for that value,
      joined by `'; '`, plus `"\n"`;
    - or it returns, when `validate()` has none there.
  - Over `at()`'s `network.pod_cidr`, `network.lb_pool.*` and `network.l2.*` entries:
    `pod_cidr`, `lb_pool_blocks` and `l2_interfaces` die with
    `join('; ', spec_errors(<their path>)) . "\n"`, or return as today when it is empty.
- [ ] **Step 2: Run them and see them fail.** Expected: `spec_errors: no key path 'kubernetes'`,
  plus the old wording in the gpu accessors.
- [ ] **Step 3: Implement** the list, the tags, the paths and the accessors.
- [ ] **Step 4: Run them green.** `TESTS="t/306-spec-errors.t t/296-validate-malformed-shapes.t
  t/255-apply-validates-config.t t/306-machines-spec-errors.t t/333-node-add-gpu-config.t"`,
  plus every test that names one of the changed accessors (`grep -l
  'gpu_config\|gpu_driver\|gpu_amd\|robocop_security_level\|pod_cidr\|lb_pool\|l2_' t/*.t`).
  Expected: PASS, with t/296 and t/255 unchanged.
- [ ] **Step 5: Mutation check.** Five mutants:
  - one new section left out of the ordered list;
  - the overlap lines tagged `network.pod_cidr`;
  - the ssh unknown-key line tagged `ssh`;
  - `gpu_driver`'s old wording back;
  - `lb_pool_config` not refusing.

  Each must turn a test red.
- [ ] **Step 6: Hand the patch over.** Subject, for example: "Answer every ocp.yaml section
  in spec_errors, and refuse gpu:, robocop.security_level and network: values in
  validate()'s words (k400)". The Changes bullet names the reworded refusals (k394) and that
  `network.pod_cidr`, `lb_pool` and `l2` of the wrong shape are refused where they are
  read, instead of dying inside Perl.

### Task 2 (C1b): the check in OCP::Role::Cmd; node add and the keys commands on it; the sweep

**Files:**
- Modify: `lib/OCP/Role/Cmd.pm` (`spec_paths` default, `refuse_spec_errors`,
  `before execute`, POD).
- Modify: `lib/OCP/Role/Cmd/Machines.pm`.
  - `_machines_spec_errors` becomes `machines_spec_paths($config)`. It returns the paths it
    asks for today, plus `workers[*].labels` and `workers[*].taints`, which `worker_ocpnodes`
    reads (CR.pm:610, NodeMeta.pm:85).
  - `_refuse_unreadable_machines` goes.
- Modify: `lib/OCP/Role/Cmd/Operator.pm`, `lib/OCP/Cmd/Keys/Operator/Add.pm`,
  `lib/OCP/Cmd/Keys/Operator/Rm.pm`, `lib/OCP/Cmd/Keys/Secure.pm` (`--drop-bootstrap` only).
- Modify: `lib/OCP/Cmd/Node/Add.pm`.
  - `_refuse_invalid_gpu_config` goes.
  - `spec_paths` declares everything node add reads, `gpu` only with `--gpu` and without
    `--nowait`.
- Modify: `lib/OCP/ClusterKey.pm:213` (Decision 7).
- Create: `t/lib/OCPTest/Cli.pm`. It holds `run_ocp`, `leaf_commands` and
  `required_options`, moved verbatim from t/398-one-error-renderer.t:146-263.
  `t/398-one-error-renderer.t` uses it; its claims are unchanged.
- Create: `t/400-one-shape-check.t`.
- Claims changed on purpose (the frame only; lines and order are asserted unchanged):
  - t/306-machines-spec-errors.t:231 and t/346-keys-machines-shapes.t:239: "Nothing was
    changed: … reads the machines" becomes Decision 3's text;
  - t/333-node-add-gpu-config.t:136, :220 and :283: "has N errors in its gpu: block"
    becomes "has N errors:".

**Interfaces:**
- Consumes: Task 1's paths and `OCPTest::Shapes`.
- Produces:
  - `$cmd->spec_paths($config) -> (path, …)`, default `()`;
  - `$cmd->refuse_spec_errors($config) -> 1` or dies with Decision 3's text;
  - `$self->machines_spec_paths($config) -> (path, …)`.
- Produces in `t/400`:
  - the sweep subtest;
  - `%NOT_YET`, every leaf not moved yet: after this task, all but `node add`,
    `keys operator add`, `keys operator rm`, `apply` and `keys secure`;
  - `%FULL`: `OCP::Cmd::Apply` and `OCP::Cmd::Keys::Secure`, which check all of
    `validate()`.

- [ ] **Step 1: Write the failing tests** in t/400. All of them run through `run_ocp`.
  - **The role.**
    - `node add w1 --gpu` with `gpu: { driver: oprator }`: STDERR is exactly Decision 3's
      text with the one `gpu.driver` line and `ocp node add` as the words; exit 1.
    - `node add w1` without `--gpu`, and `node add w1 --gpu --nowait`, on the same file: no
      refusal over `gpu:` (Review focus 2).
    - An empty ocp.yaml: STDERR is `Error: <file> is empty: it must be a mapping (name,
      control_planes and the other settings)\n`, once; exit 1 (Review focus 1).
    - No ocp.yaml: node add's own not-found text, unchanged.
    - `keys operator add` with `workers: [ { name: w, provider: ssh, host: w.k400.invalid,
      taints: foo } ]`: refused with the taints line before any PIN prompt. Today it
      croaks with a Perl location after PIN1.
    - `keys operator add` with `control_planes: [ { provider: [ a ], host: … } ]`: no
      `ARRAY(0x` anywhere (Decision 7).
  - **The sweep.** For every leaf of `leaf_commands()` not in `%NOT_YET`, with
    `required_options` and `--json` where the command has it, in a child whose setup
    replaces every way out with a die of `"sweep: outside\n"`:
    - the ways out: `OCP::Rex::run_task`, `OCP::SSH::run`, `OCP::Exec::capture_command`,
      `OCP::Provider::for_spec`, `OCP::Kubernetes::new`,
      `OCP::Role::Cmd::cluster_api` and `connect_cluster_api`,
      `OCP::Password::prompt_password`, `prompt_new_pin` and `_read_stdin_line`;
    - plus any other network client a run reaches, added to the list and named there;
    - `alarm 60`, so a hang fails, naming the command.

    The claims:
    - (a) **The valid base:** `name: k400`; one ssh control plane at `cp.k400.invalid`; one
      ssh pool `w` at `w.k400.invalid`.
      - No `internal error`, no ` at \S+ line \d+`, no `(?:ARRAY|HASH)\(0x`.
      - Unless the command is in `%FULL`: every top-level key it reads after the check is a
        section it declares a path in. Recorded by wrapping `OCP::Config::_load_spec` so
        the spec hash records each top-level key read. Reads inside `refuse_spec_errors`
        do not count; the test wraps it to mark them.
    - (b) **Every malformed path:** for each `at()` path, the first `shapes()` value
      `validate()` refuses there.
      - No signal; exit 0 or 1; nothing of (a)'s three patterns.
      - If STDERR is Decision 3's frame, its lines are an in-order sub-list of
        `validate()`'s on that config, and `N` is their count.
      - For `%FULL`, they are all of `validate()`'s, in `refuse_invalid_config`'s or keys
        secure's frame.
    - Time: `note` the sweep's run time. Above 600 s in the guarded run, (b) runs only the
      paths in sections the command declares, plus the first path of each other top-level
      section. Say so in the report.
- [ ] **Step 2: Run them and see them fail.** Expected:
  - `Can't locate object method "refuse_spec_errors"`;
  - the taints croak;
  - the old frames.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them green.** `TESTS="t/400-one-shape-check.t t/398-one-error-renderer.t
  t/306-machines-spec-errors.t t/346-keys-machines-shapes.t t/333-node-add-gpu-config.t
  t/96-keys-secure.t t/306-spec-errors.t"`, plus every test that names node add, keys
  operator or ClusterKey (`grep -l`). Expected: PASS; only the named claims change.
- [ ] **Step 5: Mutation check.** Five mutants:
  - the check not skipping a missing file;
  - `spec_paths` ignored (the check asks nothing);
  - node add declaring `gpu` without `--gpu`;
  - `machines_spec_paths` without `workers[*].taints`;
  - the probe's exemption made global.

  Each must turn a test red.
- [ ] **Step 6: Hand the patch over.** Subject, for example: "Check the ocp.yaml paths a
  command reads once, in OCP::Role::Cmd, and move node add and the keys commands onto it
  (k400)". The Changes bullet:
  - a bad pool taint or label now stops the keys commands before PIN1, in `validate()`'s
    words;
  - the refusal of node add `--gpu` and of the keys commands reads as one text.

### Task 3 (C1c): destroy and update on the check

**Files:**
- Modify: `lib/OCP/Cmd/Destroy.pm`.
  - `_spec_name_errors`, `_spec_control_plane_errors`, `_spec_worker_errors` and
    `_host_error` go, and with them every call of a private `OCP::Config::_*` function
    (Destroy.pm:502-747).
  - `spec_paths` computes the same selection:
    - `name`;
    - `control_planes`, `control_planes[*]`;
    - per entry `I`, counted as `validate()` counts it (nodes: N once), whose provider is
      known and not hetzner: `control_planes[I].host`, and `control_planes[I].public_ip`
      when that entry has no host and is local;
    - `workers`, `workers[*]`;
    - per pool `I` with a known provider: `workers[I].nodes` when `nodes` is a list, else
      `workers[I].host` when the pool takes a host.
- Modify: `lib/OCP/Cmd/Update.pm`: `spec_paths` declares what update reads, `cilium`,
  `network` and `network.pod_cidr` among them.
- Modify: `t/400-one-shape-check.t` (`destroy` and `update` leave `%NOT_YET`).
- Claims changed on purpose: the frame only, in t/323-destroy-pool-nodes.t:150,
  t/326-destroy-spec-shapes.t:178, t/335-destroy-name-host.t:200 and
  t/353-destroy-said-lines.t:381. "Nothing was deleted: ocp destroy reads the cluster's
  name and …" becomes Decision 3's text. Every line and its order is asserted unchanged.

**Interfaces:**
- Consumes: `spec_paths`, `refuse_spec_errors` (Task 2).

- [ ] **Step 1: Write the failing tests** in t/400.
  - `update` with `cilium: foo`, and separately `network: foo`.
    - Status file at an older `ocpVersion`.
    - The test replaces `OCP::Cmd::Update::_update_component` with a recorder.
    - Expected: refused with the one line; exit 1; the recorder saw nothing. Today it
      upgrades cert-manager first (k394).
  - `destroy` on a config malformed only at `cilium: foo`: STDERR has no Decision 3 frame
    (Review focus 3).
  - Take `destroy` and `update` off `%NOT_YET`.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them green.** `TESTS="t/400-one-shape-check.t t/323-destroy-pool-nodes.t
  t/326-destroy-spec-shapes.t t/335-destroy-name-host.t t/353-destroy-said-lines.t
  t/382-destroy-wrong-pin1.t t/94-update-component-outcomes.t"`, plus every test that names
  destroy or update (`grep -l`). Expected: PASS; only the named claims change.
- [ ] **Step 5: Hand the patch over.** Subject, for example: "Check what ocp destroy and ocp
  update read of ocp.yaml before they run, so update no longer upgrades cert-manager before
  it refuses a bad cilium: or network: (k400)". The Changes bullet names update's order and
  destroy's new frame.

### Task 4 (C2a): status and version on the check

**Files:**
- Modify: `lib/OCP/Cmd/Status.pm` (one `spec_paths` for the text and the `--json` path),
  `lib/OCP/Cmd/Version.pm`, `t/400-one-shape-check.t`.
- Claim changed on purpose: t/230-status-json.t:48 and :92 (k339). The ssh pool's
  `nodes: 2` becomes `nodes: [ w1.k230.invalid, w2.k230.invalid ]`. Status no longer shows
  a count that apply would not make.

- [ ] **Step 1: Write the failing tests** in t/400.
  - `status` with `network: foo`: refused with `network: must be a mapping` up front, not a
    failed drift (k394, Status.pm:301).
  - `status --json` on the same file: STDOUT is one JSON object `{ "error": … }`; exit 1
    (Review focus 5).
  - `status` on a config malformed only in a top-level section status does not declare:
    no refusal (Review focus 3). The test picks that section from `spec_paths` and asserts
    one exists.
  - Take `status` and `version` off `%NOT_YET`.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them green.** `TESTS="t/400-one-shape-check.t t/230-status-json.t
  t/11-status-command.t t/370-clone-read-unlocks.t t/384-api-unreachable.t"`, plus every test that
  names status or version (`grep -l`). Expected: PASS; only t/230 changes.
- [ ] **Step 5: Hand the patch over.** Subject, for example: "Check what ocp status and ocp
  version read of ocp.yaml before they run (k400)". The Changes bullet: `status` refuses a
  bad key it reads with `validate()`'s line instead of a half report, and still reports
  over a bad key it does not read.

### Task 5 (C2b, C3): every remaining command declares; the sweep complete

**Files:**
- Modify the remaining leaves, each with its `spec_paths`. A command that reads nothing
  declares nothing, and the sweep's probe proves it reads nothing.
  - `lib/OCP/Cmd/DeployImage.pm`, `DeployRobocop.pm`, `InjectKey.pm`, `Init.pm`,
    `Health.pm`, `Kubeconfig.pm`, `SSH.pm`;
  - `lib/OCP/Cmd/Hetzner/List.pm`;
  - `lib/OCP/Cmd/Keys/AuthorizedKeys.pm`, `Keys/Show.pm`, and `Keys/Recipients/*` through
    `lib/OCP/Role/Cmd/Recipients.pm`;
  - `lib/OCP/Cmd/Node/Ls.pm`, `Node/Rm.pm`, `Node/TrustHost.pm`;
  - `lib/OCP/Cmd/Provider/Add.pm`, `Provider/Ls.pm`, `Provider/Rm.pm`.
- Modify: `t/400-one-shape-check.t`: `%NOT_YET` goes.

- [ ] **Step 1: Write the failing tests** in t/400.
  - Delete `%NOT_YET`. The sweep is now red for every command that reads a section it does
    not declare, or that crashes.
  - Plus these, named by the card history:
    - `provider add` with `name: [ a ]` is refused with the name line. Today it writes
      `clusterName ARRAY(0x…)`, k306 F5.
    - `deploy-robocop` with `network: { pod_cidr: [ a ] }` is refused, with
      `ocp deploy-robocop` as the words.
    - `node ls --json` with a pool `taints: foo` gives the JSON error object, not a crash
      (Review focus 5).
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement** the declarations.
- [ ] **Step 4: Run them green.** `TESTS="t/400-one-shape-check.t t/398-one-error-renderer.t
  t/399-one-way-into-the-cluster.t"`, plus every test that names one of the commands
  (`grep -l`). Expected: PASS; only fixture fixes, each listed.
- [ ] **Step 5: Hand the patch over.** Subject, for example: "Check what every other ocp
  command reads of ocp.yaml before it runs, and sweep every command over the malformed
  shapes (k400)". The Changes bullet: no ocp command dies inside Perl on a malformed
  ocp.yaml; each refuses with `validate()`'s line for what it reads.

## Not in this plan

- **k394's unknown-key lines for `registry:` and `ssl:`.** They would change what `ocp apply`
  validates, which the spec rules out. They stay on k394, which goes back to backlog with
  only that item.
- An upper bound for a pool's `nodes: N` (k306 F1). That is the maintainer's number.
- Drift (Part D), robocop, and Part B's leftovers: status and ssh reaching into the role's
  `_cluster_kubernetes`; the unused `use OCP::Kubernetes`.

## Done when

- The sweep is green over every leaf, with no `%NOT_YET`.
- t/296, t/255 and t/306's differential are unchanged.
- One full guarded suite on the stack is green.
- Five commits on main, each naming its behaviour change.
- k400 is done. k306 is already closed with a pointer here. k394 carries a note and stays
  in backlog with the registry/ssl item.
