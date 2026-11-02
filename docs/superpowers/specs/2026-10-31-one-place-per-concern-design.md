# One place per concern: errors, cluster access, ocp.yaml shape, drift — design

Date: 2026-10-31 · Status: approved by the maintainer on 2026-11-01 · Cards: k398 (Part A),
k399 (Part B), k400 (Part C)

## Intent

From k296 to k397 the board took 102 cards. Most of them fixed the same few bug classes
again and again, one command at a time. The maintainer asked whether the work was
necessary and whether components could be abstracted instead ("das ist aber echt viel
arbeit was da passiert, war das nötig? … können wir nicht schauen ob wir hier komponenten
optimieren und abstrahieren können?"). It was not necessary in that form: each card fixed
one symptom at one site, and the next command had the same bug.

This design gives each of four recurring concerns **one place in the code**. A bug in one
of these classes is then fixed once, and a new command gets the right behaviour without
anyone remembering to add it.

A rough keyword count of the card titles since k296 (the groups overlap):

| Concern | Cards | Chain, for example |
|---|---|---|
| ocp.yaml read in a shape nobody checked | ~29 | k296 → k305 → k315 → k320 → k322 → k323 → k347 → k355 → k379 → k306 |
| an error shown as "internal error", raw, or not at all | ~21 | k342, k353, k370, k373, k375, k382 |
| the cluster API failing per command | ~5 (all recent) | k384 → k387 → k388 → k389 → k395 |
| status, dry-run and apply disagreeing about drift | ~13 | k312, k332, k338 → k348 → k393, k369 |

## Gate 0 — all earlier work is on main first

The maintainer's condition: **no change from this design starts before every earlier piece
of work is merged.** This gate is checked and reported before Part A gets a card.

| Item | State on 2026-10-31 | To pass the gate |
|---|---|---|
| Batches 5–8 (25 commits, up to k387 `5935cc5`) | on main, full suite green (270 files, 4079 tests) | done |
| Batch 9: k353, k388, k306 step 2b, k380, k382 | on main up to `8e79854`, full suite green (274 files, 4124 tests) | done |
| k306 (validation without validate()) | steps 1, 2c and 2b on main (`7665c48`, `5170476`, `19fe5ba`) | the rest (step 2a, step 3) is not started: it becomes part of Part C, and k306 closes with a pointer to Part C's card *(call)* |
| k337 (docs after k327/k328) | in-progress; one POD bullet left (Network.pm `corefile_*`, the new OCP::Corefile POD). Its ADR 0022 note is backlog card k392 | the POD bullet finished by ocp-doc-writer and committed: it is earlier work, half done |
| k369 (NFD drift probe) | todo; an unreviewed WIP diff is in the scratchpad | not earlier work: it never passed review. It stays in todo, unworked, and the WIP diff is dropped *(call)* |
| k248 (AMD GPU workers) | OCP code on main; depends on sibling branches `rex-gpu` `worktree-k1-amd-driver` and `rex-rancher` `worktree-k95-amd-gpu`, which are not merged into their main | does not block (maintainer, 2026-11-01: Parts A–C touch no AMD code). The sibling merges stay the maintainer's separate decision |
| k134 (.cicd build script) | review; waits on simpici#2/#4, excluded by the maintainer earlier | does not block, for the same reason: it touches no file of Parts A–C *(call)* |

The gate passes when: `git status` is clean on main, `karr list --status review` shows
nothing but excluded cards, no patch is left in the queue, and one full `make test` on main
is green. The gate report names that commit.

**Baseline.** The "Today" sections below describe main at `8e79854`, batch 9 included.

## Goals

- A bug in one of the four classes is fixed in one module, not per command.
- A new command gets error rendering, cluster access and the shape check from
  `OCP::Role::Cmd`, without code of its own.
- The open cards of these classes (k389, k394, k395, the API parts of k396, the rest of
  k306) are closed by the parts, not one by one.

## Non-goals

- robocop (in-cluster, Net::Async::Kubernetes, ADR 0029) stays as it is.
- No schema library and no generated docs from a schema. The hand-written validators stay.
- No new error wording beyond what a step needs to fix a known card.
- No change to what `ocp apply` validates (it keeps the full `validate()`).

## Anti-goals (a failure even if it works)

- A big-bang rewrite or a long-lived branch. Every step lands on main on its own, green.
- Another flood of cards. A finding outside the current step goes to the backlog and waits.
- A user-visible behaviour change that is not named in its commit message.
- New CPAN dependencies.

## Part A — errors rendered in one place

**Today.** `OCP::run_cli` → `_report_error` (lib/OCP.pm:243) decides whether an error is
"internal" by one test: does the message end in ` at FILE line N.` (`_clean_message`,
lib/OCP.pm:230). Every `croak` (107 in lib/ and bin/, in 24 files) and every `die` without
a trailing newline that reaches the top therefore reads "This is an internal error", even
when the cause is the user's file, PIN or network. Each fix so far was a local wrapper:
`die "…\n"`, `OCP::Config::_refuse` (k379), `OCP::ErrorLine::one_line` (k342),
`OCP::Role::Cmd::cluster_api_error` (k387), token masking in the Hetzner adapter (k373),
and a JSON error object per `--json` command (`status` and `health` each build their own;
`node ls` since k388).

**Target.** `_report_error` keeps the `die "…\n"` convention for user errors and gains
**one translator** for foreign exceptions it knows:

- `Kubernetes::REST::APIError`, with the wording of `cluster_api_error`
  (lib/OCP/Role/Cmd.pm:240). The endpoint must reach the renderer; see Part B.
- `Path::Tiny` errors become "cannot read/write FILE: reason".
- WWW::Hetzner errors are masked as in k373.
- Anything else stays an internal error, as today.

The same place renders a failure of a command run with `--json` as the JSON error object
k388 settled on. It also masks every secret the process has read, using a small registry
that the code reading a secret adds to (the registry's shape is the builder's call).

**Steps.**

- **A1.** Add the translator, the JSON rendering and masking. No call site changes. Tests
  that asserted "internal error" for one of these foreign types change their claim; the
  commit names each one.
- **A2.** Remove the per-site wrappers that A1 makes pure duplicates, and only those.

**Done when** a test that walks the command map (as t/383 does) feeds each command a known
foreign error and sees one line, never "internal error", and the JSON object under `--json`.

## Part B — one way into the cluster

**Today.** Sixteen files under lib/ build a Kubernetes client, in two ways:

- `Kubernetes::REST::Kubeconfig->new(…)->api` directly: Apply/K8s.pm:53, Provider/Add.pm:88,
  DeployImage.pm:463 and others;
- `OCP::Kubernetes->new(kubeconfig => …)`: Health.pm:56, Status.pm:98 and Status.pm:233.

Each one reads kubeconfig.yaml through `OCP::Secrets` itself and decides itself whether to
unlock age.key.enc first (k370, k375, k382). `Role/Cmd/Machines.pm:217` builds one too.

Only `health`, `node ls` and `provider ls` check the API once with `reach_cluster_api`
(Health.pm:57, Node/Ls.pm:48, Provider/Ls.pm:40). `status` works differently: it lists the
nodes, and on an API error it prints a partial report and returns 1 (Status.pm:98-113).

`ocp apply` gets its kubeconfig from bootstrap in memory and rebuilds its client whenever a
new kubeconfig is passed (Bootstrap.pm:628 → Apply/K8s.pm:38-66). `ocp destroy` must never
die over the cluster, because a half-down control plane is exactly when people run it
(Destroy.pm:105-109).

**Target.** One method in `OCP::Role::Cmd` (its name is the builder's call), cached per
command object. In order, it:

1. unlocks the project key by k370's rule;
2. reads kubeconfig.yaml;
3. builds the client through `OCP::Kubernetes`, so the CRD providers are registered in one
   place (ADR 0024);
4. sends one `GET /version` (`reach_cluster_api`);
5. returns the client.

Steps 3–5 form an inner function that takes kubeconfig content. The role method runs steps
1–2 and then calls it. `ocp apply` calls the inner function with bootstrap's in-memory
kubeconfig and keeps its rebuild on a new one *(call)*.

**Optional mode** *(call)*: `destroy` and `status` ask for the cluster as optional. When
there is no kubeconfig.yaml, or the API does not answer, they get undef plus the one-line
reason and go on as they do today:

- `destroy` keeps tearing down;
- `status` keeps its partial report and exit 1.

A key problem still stops the command, as k382 settled: a wrong PIN1, or a broken
SOPS_AGE_KEY_FILE.

The client is remembered on the command object, so Part A's renderer can name the endpoint.

**Steps.**

- **B1.** Add the method and the inner function. Move `health`, `node ls` and `provider ls`
  onto them (they already check the API once).
- **B2.** Move the remaining commands, one commit per small group. `status` keeps its
  partial report and its STDOUT.

**Done when** only lib/OCP/Kubernetes.pm builds through `Kubernetes::REST::Kubeconfig`
(robocop excluded; `Role/Cmd/Machines.pm` included), and a sweep of the command map against
an unreachable API sees one line per command. **Absorbs:** k389, k395, the API parts of
k396.

## Part C — the ocp.yaml shape checked once, before the command runs

**Today.** The full `validate()` (lib/OCP/Config.pm:1215) runs in `ocp apply`
(Apply/Validate.pm:38) and `ocp keys secure` (Keys/Secure.pm:211) only. k306 step 1 added
`spec_errors(@paths)` (Config.pm:1341): validate()'s lines, asked per key path. It answers
only `name`, `control_planes`, `gpu` and `workers`; any other path croaks (Config.pm:1305-1331,
`_spec_path` at :1369). Two callers use it: `node add --gpu` (k306 2c) and
`OCP::Role::Cmd::Machines` (k306 2b). Since k379
the accessors refuse what they read with validate()'s words. Readers that still take the
raw shape:

- ClusterKey.pm:213 (a provider given as a list);
- CR.pm:610 and NodeMeta.pm:85 (taints);
- Update.pm, which upgrades cert-manager before it refuses (k394);
- parts of Destroy.pm.

**Target** (maintainer, 2026-11-01: check what the command reads, not the whole file). Each
command declares the key paths it reads, in one list next to the command.
`OCP::Role::Cmd` checks `spec_errors(<that list>)` once, before `execute`, and refuses with
every line. `ocp apply` keeps the full `validate()`. The accessors' `_refuse` stays as the
safety net.

**Steps.**

- **C1.** Extend `spec_errors` to every section a command reads (labels and taints,
  `cilium:`, `network:` and the others), as more tagged producers in k306's pattern. k394's
  shape gaps and wording drift are in scope, because they are exactly where the accessors and
  validate() disagree *(call)*. Then add the declaration and the check in the role, and move
  the commands whose readers are listed above.
- **C2.** Declare the paths for every remaining command (k306 step 3).
- **C3.** Add a sweep test.

**Done when** the sweep (every command × the malformed shapes from t/296) shows no command
crashing or reporting an internal error over an ocp.yaml shape; each refuses with
validate()'s line. **Absorbs:** the rest of k306, k394.

## Part D — drift: deferred, not part of this work *(call)*

**Today.** `OCP::Drift::detect` (lib/OCP/Drift.pm:559) collects spec, component, GPU CRD,
OCP CRD, registry DNS, pod CIDR and host-probe drift. `ocp status` and the dry-run read it.
The writers decide on their own what they write: Apply/Network.pm (Corefile),
Apply/Workloads.pm, Apply/AMDGPU.pm and Apply/CR.pm. They share pieces with Drift case by
case (`@COMPONENT_PROBES`, `version_against_pin`, `resolve_address`, `corefile_*`).

**Why deferred.** The component with the most disagreement cards (Corefile: k338, k348,
k393) already shares `corefile_*` and `OCP::Corefile` between apply and status since k348.
A pilot there would prove little. This part is also the largest (Drift.pm alone has 1822
lines).

So "one desired state per component" is reconsidered after Part C. It gets a short design
of its own only if this class keeps producing cards. Until then k393 and k369 stay ordinary
cards.

## Order and why

**A → B → C.** A is the smallest change with the widest effect: one module, no call site
changes, and B and C need no wrappers of their own because of it. B builds on A. C touches
the most commands, so it comes once A and B have shrunk them.

The parts touch shared files (`OCP::Role::Cmd`, `OCP.pm`), so they run **one after
another**, never in parallel.

## Process (the lean rules the maintainer chose)

- **Cards and workers:**
  - one card per part; the steps are notes on it;
  - one worker per step, at most two at a time when their files do not overlap;
  - no chaining of cards per worker.
- **Testing and commits:**
  - each step writes the red test first, gets one full suite through the release manager,
    and gets one commit;
  - every behaviour change is named in that commit;
  - mutation checks only for non-trivial logic in lib/, at most five mutants per run.
- **Findings outside the step** go to the backlog only.
- **Reporting:**
  - after each part: a short report to the maintainer (what changed for the user, which
    cards closed) before the next part starts;
  - once approved: one ADR for the decision "one place per concern" (ocp-adr-auditor).

## Left to the builder

- names of the new methods and of the secret registry;
- how the endpoint reaches the renderer (an attribute on the command object, or carried on
  the error);
- how the commands are grouped into the commits of B2 and C2;
- whether a small exception class turns out to be simpler than the `die "…\n"` convention
  plus translator. If it is, say so in the step's report; do not switch silently.

## Decided by the maintainer (2026-11-01)

1. **Part C checks per command:** each command checks the paths it reads, so `ocp status`
   and `ocp destroy` keep working on an ocp.yaml with a bad key elsewhere. The full
   `validate()` stays with `ocp apply`.
2. **The sibling AMD branches do not block Gate 0.** Merging them stays a separate decision.
