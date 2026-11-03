# 0031. Render errors, reach the cluster and check the ocp.yaml shape in one place each, not per command

Date: 2026-11-03
Status: accepted

## Context

From k296 to k397 the board took 102 cards. Most of them fixed the same few bug
classes again and again, one command at a time. A rough count of the card
titles (the groups overlap):

- about 29 were an ocp.yaml value read in a shape nobody had checked
  (k296 → k305 → … → k379 → k306);
- about 21 were an error shown as "internal error", raw, or not at all;
- five were the cluster API failing differently per command
  (k384 → k387 → k388 → k389 → k395);
- about 13 were status, the dry-run and apply disagreeing about drift.

The cards kept coming because each concern was decided at every site that met
it:

- **Errors.** `OCP::_report_error` called an error internal when its message
  ended in ` at FILE line N.`. Every `croak` (107 in `lib/` and `bin/`) that
  reached the top therefore read "This is an internal error", even when the
  cause was the user's file, PIN or network. Each fix was a local wrapper:
  `OCP::Config::_refuse` (k379), `one_line` (k342), `cluster_api_error`
  (k387), token masking in the Hetzner adapter (k373), and a JSON error object
  per `--json` command.
- **The cluster.** Sixteen files under `lib/` built a Kubernetes client, in two
  ways. Each read kubeconfig.yaml itself and decided itself whether to unlock
  age.key.enc first (k370, k375, k382). Three of them checked the API before
  their first call.
- **The ocp.yaml shape.** Only `ocp apply` and `ocp keys secure` ran the full
  `validate()`. Every other reader took the raw value. It died inside Perl, or
  carried `ARRAY(0x…)` on as a value (`ocp provider add` wrote one into an
  OCPNodeProvider, k306), or refused after it had acted (`ocp update` upgraded
  cert-manager, then refused a bad `cilium:`, k394). Destroy, the keys
  commands' machines role and `node add --gpu` each kept their own copy of
  validate()'s lines (k323/k326, k346, k333).

The maintainer asked whether that much work had been necessary, and whether
components could be optimised and abstracted instead. In that form it had not
been necessary: each card fixed one symptom at one site, and the next command
had the same bug.

The answer is the design in
`docs/superpowers/specs/2026-10-31-one-place-per-concern-design.md`. The
maintainer approved it on 2026-11-01. It was built in order as k398 (Part A),
k399 (Part B) and k400 (Part C), and their plans in `docs/superpowers/plans/`
record the calls made during execution. The design's section "Decided by the
maintainer" names two choices as the maintainer's own. The other choices were
the orchestrator's calls, approved with the design as a whole.

## Decision

Each concern has one place in the code, and a bug in its class is fixed there.
A command gets the behaviour from `OCP.pm` and `OCP::Role::Cmd` without code of
its own.

**Errors are rendered once, in `OCP::_report_error` (k398).** User errors keep
the `die "…\n"` convention. One translator, `OCP::ErrorLine::user_line`, sits in
front of the old rule and handles the foreign exceptions OCP knows:

- a `Kubernetes::REST::APIError` becomes the one cluster-API line
  (`api_error_line`) and names the server;
- a `Path::Tiny::Error` becomes "cannot read (or write) FILE: reason".

Anything else is still an internal error. When a command run with `--json`
fails, it prints one `{"error": …}` object on STDOUT (k388's shape, moved out of
`node ls`). Every secret the process has read is masked in whatever is printed,
`--verbose` included. The secrets sit in a process-wide registry
(`add_secret`), which the code that reads a Hetzner token adds to. Values
shorter than eight characters are ignored, so a "0" does not mask every number.

**The cluster is reached through one method, `OCP::Role::Cmd::cluster_api`
(k399).** It runs four steps:

1. It reads kubeconfig.yaml outside any eval. A key problem (a wrong PIN1, a
   key the project is not bound to, no key at all) therefore stops the command
   in `OCP::Secrets`' words, and never passes for an unreachable cluster
   (k382).
2. It builds the client through `OCP::Kubernetes`, so the CRD providers are
   registered in one place (ADR 0024).
3. It sends one `GET /version`.
4. It keeps the client on the command object.

The build step alone is `connect_cluster_api`, and it sends nothing. `ocp
apply` and `ocp update` use it with bootstrap's in-memory kubeconfig: right
after bootstrap the API may not answer yet, and apply waits for it itself.

`destroy`, `status` and `ssh` call `cluster_api` with `optional => 1`. A missing
kubeconfig.yaml answers `(undef, undef)`. A client that cannot be built, or an
API that does not answer, answers `(undef, line)`. Each command then does what
it did before without a cluster: destroy goes on tearing down, status keeps
its partial report and exits 1, and ssh falls back to the host name.

`OCP::ErrorLine` holds the server of the last client built, for the whole
process. When `execute` dies, the renderer has no command object to ask. So an
API error that escapes any command names the server.

**The ocp.yaml shape is checked once, before the command runs, at the paths
that command reads (k400).**

- `validate()` and `OCP::Config::spec_errors(@paths)` read one ordered list of
  `[tag, line]` pairs, so their words and their order cannot differ.
- Each command declares the key paths it reads in `spec_paths($config)`, next
  to its options. The paths may depend on an option: `node add` declares
  `gpu:` only with `--gpu` and without `--nowait`. They may also depend on the
  file: destroy's paths follow each entry's provider.
- A `before execute` in `OCP::Role::Cmd` runs `refuse_spec_errors`. It refuses
  with every line at those paths, in validate()'s order, in one text: "Nothing
  was done: ocp <words> checks what it reads of <file> before it asks for a PIN
  or touches the cluster or a machine."
- Without an ocp.yaml it checks nothing, and the command says its own "not
  found".
- The refusals that destroy, the machines role and `node add --gpu` had of
  their own went into this one.

Four rules bound the check:

- **A command checks only what it reads.** This is the maintainer's choice of
  2026-11-01, so `ocp status` and `ocp destroy` keep working on an ocp.yaml
  with a bad key elsewhere.
- **`ocp apply` keeps the full `validate()`.** So does `ocp keys secure` where
  it switches a project to secure mode.
- **A command that reads around a bad value on purpose keeps doing so.** This
  covers a command that goes on with a warning line or a drift entry, where a
  test pins that. It does not declare the path, and a comment beside its
  `spec_paths` says why; t/400's `%READS_AROUND` lists the ones the sweep sees.
  `ocp status` reads around `gpu:` and `nocert`, and `ocp destroy` reads
  around `ssh:` (k180). This rule was the orchestrator's call during Part C.
  The plan's first reading broke claims the tests pin on purpose.
- **Some lines stay validate()'s alone.** These are:
  - required keys;
  - unknown keys;
  - the control-plane bounds;
  - `node_ip`;
  - where the pod CIDR or the service network overlaps an address. A running
    cluster whose default pod CIDR overlaps a node address must not stop
    every command that reads `network:`.

The accessors keep `_refuse` as a safety net. The network accessors now refuse
in spec_errors' lines. The gpu and robocop accessors keep their own wording,
which t/296 pins, because the check up front says validate()'s line first.

**Drift is not decided here.** The design deferred its Part D, "one desired
state per component", and the maintainer approved the design with that
deferral in it. There were two reasons. The Corefile, the component with the
most disagreement cards (k338, k348, k393), already shares `corefile_*` and
`OCP::Corefile` between apply and status, so a pilot there would prove little.
And Part D is the largest part: Drift.pm alone has 1822 lines. It gets a design
of its own only if the class keeps producing cards. Until then k393 and k369
are ordinary cards.

### Alternatives rejected

- **Keep fixing each card at its site.** The maintainer questioned this
  practice, and the counts in Context are its result.
- **A validate-first gate on every command.** k306 asked whether a gate was too
  strict for read-only commands on a half-edited file, and its design pass
  ruled out a gate for commands that only read. The maintainer chose "only what
  it reads". A gate would stop `ocp destroy` over a typo in a section destroy
  never reads. Destroy.pm's comment names the cost: it would "keep paid servers
  running until someone edits a line that has nothing to do with them".
- **Let the accessors refuse, with no check up front.** This was k306's other
  option, and the pattern k379 used. A refusal where a value is reached comes
  after the command has acted: after PIN1 (a pool's taints in the keys
  commands), after cert-manager was upgraded (k394), after an OCPNodeProvider
  was written (k306). The accessors stay, as the net.
- **Read each section in an eval and go on.** This was the k306 design pass's
  plan for `ocp status`, and k394's "one drift entry for `network: foo`". The
  maintainer's choice replaced it: status refuses what it reads before the
  report.
- **A schema library, or docs generated from a schema.** The design made this
  a non-goal: the hand-written validators stay, and the design allowed no new
  CPAN dependency.
- **An exception class in place of `die "…\n"`.** The design left this to the
  builder. Part A kept the convention and put the translator in front of it,
  so no site that raises an error had to change.
- **`GET /version` inside the build step.** The design put it there. Part B
  moved it out, so that `ocp apply` gets no fatal check right after bootstrap.

## Consequences

- **A bug in one of these classes needs one fix.** A new command inherits error
  rendering, its client and the shape check, as long as it declares its
  `spec_paths`. The work landed as 16 code commits on main, each green and
  each naming its behaviour change. k389 and k306 are closed, and k394 keeps
  only the `registry:`/`ssl:` unknown-key item.
- **Users see deliberate changes:**
  - an unreachable API, or a file OCP cannot read or write, is one line, not
    an internal error;
  - `ocp update` refuses a bad `cilium:` before any component runs;
  - `ocp status` refuses a bad key it reads before the report, where it used
    to warn under a report half printed.
- **Now forbidden, and guarded:**
  - building a Kubernetes::REST client outside `OCP::Kubernetes` (t/399's
    source guard over `lib/` and `bin/`, robocop included);
  - a command that reads an ocp.yaml section it does not declare, as far as
    t/400's sweep sees;
  - a per-command copy of validate()'s lines, or a per-command JSON error
    wrapper.
- **t/400 takes about eight minutes.** Its sweep runs all 28 leaf commands,
  each in a child. Each command runs once on a valid ocp.yaml, then once per
  malformed key path. The sweep took 406–494 s in the guarded runs, 494 s of
  them in the full suite of 2074 s. If it ever passes 600 s, the plan's
  fallback is to sweep only the declared sections, plus one path of each other
  section. The fallback has not been needed.
- **The path lists are written by hand.** A command's `spec_paths` can fall
  behind its readers. The first control plane's read set (what
  `cluster_status` and `cluster_ssh_key` read) is spelled out in `node add`,
  `update` and `deploy-robocop`, and in variants in `status` and `ssh`. k401
  (backlog) proposes one helper beside `machines_spec_paths`, so a change to
  `cluster_status` cannot leave a declaration behind.
- **The sweep sees only reads before a command's first way out.** In the sweep,
  every way off the machine dies: SSH, Rex, a provider, the cluster API, a PIN
  prompt. So the probe misses any read after that point. t/400's
  `@BEHIND_A_WAY_OUT` pins eleven such runs by hand, and a new read behind a
  way out needs a new row there. Behind that, the accessors are the only net,
  and not every raw reader has one. k401 names two: `ocp init --force` on a
  bad control plane, and `spec_taints` silently dropping a string for readers
  outside the CLI.
- **`%READS_AROUND` is an exemption list.** Each entry needs a test that pins
  the warning, and the commit that adds it must name it. Without that
  discipline it becomes the way back to per-command decisions.
- **Not everything moved into the one place:**
  - Wrappers that add something stay. The Hetzner adapter's mask also guards
    robocop's OCPNode status, which never passes through `run_cli`.
    `cluster_api_call` in `node ls` and `provider ls` is now redundant, but
    harmless.
  - robocop (ADR 0029) and `ocp inject-key` (ADR 0028) build their own
    `Net::Async::Kubernetes` client.
  - What k395 and k396 still hold stays on them. That includes LWP's full text
    in `one_line`, and the raw error in a drift entry.
- **Verified by the suite only.** It runs network-free, with the ways out faked
  or dying. The cards record no live run.

ADR 0024 is unchanged, and its premise that `OCP::Kubernetes` is "the single
typed Kubernetes helper the CLI shares" now holds for every client the CLI
builds. ADR 0007 is untouched. This decision narrows it to one build site.
