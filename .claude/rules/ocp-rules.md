# OCP House Rules

Apply to every task in this repository unless explicitly overridden. Bias: caution over
speed on non-trivial work. Loaded automatically at launch (same priority as `CLAUDE.md`).
Subagents get their conventions from the skills force-loaded via `briefing.skills` — this
file is for the orchestrating agent.

## Engineering discipline

1. **Think before coding** — State assumptions; ask rather than guess. Push back when a
   simpler approach exists. Stop when confused; name what's unclear.
2. **Simplicity first, surgically applied** — Minimum code that solves the problem,
   nothing speculative. Touch only what you must; don't "improve" adjacent code.
3. **Goal-driven execution** — Define success criteria, loop until verified.
4. **Surface conflicts, don't average them** — Contradicting patterns: pick one (more
   recent / more tested), explain why, flag the other. Don't blend.
5. **Read before you write** — Before new code, read `OCP::Config`, `OCP::Node` and the
   provider role you're about to touch. Spec/status, the state machine and the lease
   mechanics are one mechanism; "looks orthogonal" is dangerous here.
6. **Tests verify intent, not just behavior** — Reproduce a bug before fixing it; leave
   the regression test behind.
7. **A red test is a claim before it is a failure** — Before changing code to turn a test
   green, say what the test asserts and whether your fix keeps that claim or replaces it.
8. **Checkpoint and fail loud** — Summarize done / verified / left after each significant
   step. "Done" is wrong if anything was skipped silently.
9. **Match the codebase's conventions, even if you disagree** — Conformance > taste.

## Delegation

Depends on whether the Agent/Task tool is available to you.

- **You can spawn subagents** (orchestrating main agent): Do NOT touch behavior-relevant
  code yourself — delegate. Your lane: coordinate, inspect, plan, review diffs, run
  tests, manage git, edit `Changes`/`README`. When in doubt, delegate. Why: only the
  `ocp-*` agents get their skills force-loaded via `briefing.skills`; you get no briefing
  and would touch the spec/status seam with too little context.

  | Task | Agent |
  |---|---|
  | Input validation, `OCP::Choices`, `option(...)`, `_validate_*` | `ocp-choices-worker` |
  | Secrets/Keys: `OCP::Secrets`, `OCP::Keys`, `OCP::ClusterKey`, age/SOPS/PIN | `ocp-secrets-worker` |
  | State machine: `OCP::Config`, `OCP::Drift`, `OCP::Node`, `OCP::Versions` | `ocp-state-worker` |
  | Provider base + roles, Hetzner/Local/SSH provisioning, `OCP::Rex` | `ocp-provider-worker` |
  | `ocp init/apply/update/deploy-image/deploy-robocop`, `OCP::Cmd::Apply/*`, `bin/ocp` dispatcher | `ocp-apply-worker` |
  | `ocp destroy`, `OCP::Cmd::Destroy.pm` | `ocp-destroy-worker` |
  | `ocp status`/`ocp version`, `OCP::Cmd::Status.pm`, `OCP::Cmd::Version.pm` | `ocp-status-worker` |
  | robocop controller, IO::Async, reconciliation loop | `ocp-robocop-worker` |
  | share/, Rexfile, Cilium/RKE2/registry/GPU stack | `ocp-infra-worker` |
  | Cross-cutting or not assignable elsewhere | `ocp-worker` (default) |
  | Write or extend tests in `t/` | `ocp-test-writer` |
  | POD and prose docs | `ocp-doc-writer` |
  | Pre-release audit | `ocp-release-checker` |
  | ADR backfill/audit in `docs/adr/` | `ocp-adr-auditor` |

- **You cannot spawn subagents** (you ARE an `ocp-*` agent): the lock does not apply —
  implement, refactor, debug and test per these rules.

Behavior-relevant = everything under `lib/` and `bin/`, `share/`
(templates + Rexfile), and the tests. Prose in `README.md` and `Changes` bullets are not.

## Coordination — karr board (always in scope)

Ticket coordination is the orchestrating agent's job, so `karr` is always in scope —
don't invoke the skill first, just use it. Git-native kanban; state lives in
`refs/karr/*` in this repo. Sibling distributions (io-k8s-p5, kubernetes-rest, …) have
their own boards — cross-repo work is a ticket on the other repo's board, never a direct
edit there.

- `karr list --compact` / `karr board` — open work · `karr show ID` — detail
- `karr create "Title" --priority high --tags a,b --body '…'` · `karr edit ID -a "note"`
  · `karr move ID in-progress --claim NAME` — full surface: skill `karr`

**Serialize board mutations when fanning out** — parallel implementation is fine, but
collect results and then loop `karr move`/`handoff`/`sync` sequentially.

## Release & publish — never without permission

`make test` / `make build` / `dzil build` are fine anytime. STRICTLY forbidden without
the maintainer's explicit go-ahead: `dzil release`, `make docker-push`,
`make docker-release` — even if a plan lists "release" as the next step.

## Hazards specific to this repo

- **`make smoke` bootstraps against a REAL machine and wipes its cluster**
  (`xt/smoke.sh`, needs `SMOKE_HOST`). Human-triggered only — never run it, never move
  its concerns into `t/`.
- **`ocp apply`/`ocp destroy` against a real project dir touches real infrastructure**
  (creates/deletes paid Hetzner servers). Only ever run `ocp` inside tests' temp dirs or
  on explicit instruction with a named target.
- **Toolchain is Docker-first**: never `carton install`/`cpm` on the host — snapshot via
  `make snapshot`, missing Docker targets get added, not worked around. Host runs
  pollute host CPAN state and produce inconsistent results.
- **No kubectl in any code path** — K8s access is Kubernetes::REST/IO::K8s only; kubectl
  in the image is for human debugging.
- **Encrypted files are meant to be committed** (`keys.yaml`, `secrets.yaml`,
  `age.key.enc`, `kubeconfig.yaml` — SOPS/age). `.ocp/` (decrypted state) is gitignored
  and must stay out.

## Output channels — STDOUT vs STDERR

Jedes `ocp`-Kommando hat zwei Ausgabekanäle mit getrennten Aufgaben. Wer mischt,
macht die Pipe kaputt — die Regel existiert genau dafür.

- **STDOUT ist die Nutzlast** (Ergebnis) oder der **Fortschrittsbericht** (Rollout,
  Apply-Erzählung), den ein Mensch liest oder eine Maschine weiterverarbeitet.
- **STDERR ist alles, was schiefging**, samt Diagnose. Eine Fehlermeldung ohne
  Diagnose verstößt ebenso wie eine Diagnose ohne Fehler (Wartungsrauschen auf
  STDOUT).
- **Maschinenlesbare Kommandos** (`keys show`, `kubeconfig`, künftige
  Maschinen-Schnittstellen) geben **ausschließlich** die Nutzlast auf STDOUT aus.
  Diagnose strikt auf STDERR. Anders lässt sich nicht sauber nach `authorized_keys`
  oder in einen Parser pipen.

Präzedenzfall: `ocp keys show` trennt seit #84 bewusst — Schlüsselmaterial auf
STDOUT, alles andere auf STDERR. Diese Regel ist die Verallgemeinerung dessen.

Ausnahmen und Streitfälle gehören ins Issue, nicht in eine stillschweigende
Ausnahme. Jede Abweichung kostet Begründung.

## Perl specifics — reference, don't restate

Module loading, Moo patterns, cpanfile pinning and house style live in skills
`perl-core` / `perl-moo` (force-loaded for `ocp-*` agents). Do not duplicate here.
