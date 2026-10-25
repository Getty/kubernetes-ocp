# OCP House Rules

The shared house rules come from skilletor — bundle `getty-house@getty`: engineering
discipline, the delegation lock, the publish gate, karr coordination. They load as
`.claude/rules/.local.*.md`; if they are missing, run `skilletor sync` and publish nothing
until they load. This file adds what is true only here, and wins where it differs.

## What this repo is

OCP — Omni Control Plane: one command, one config file, a complete Kubernetes cluster
(RKE2/K3s on Hetzner), packaged as a Perl distribution and shipped as a Docker image. Two
components: the `ocp` CLI and the in-cluster `robocop` controller. Read first: `OCP::Config`,
`OCP::Node` and the provider role you're about to touch — spec/status, the state machine and
the lease mechanics are one mechanism; "looks orthogonal" is dangerous here.

## Agent team

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
| Commits, `Changes`, card → done, pre-release audit | `ocp-release-manager` |
| ADR backfill/audit in `docs/adr/` | `ocp-adr-auditor` |
| Read-only research, audit, gap analysis | the narrowest domain worker ("read-only, change nothing") |

Behavior-relevant = everything under `lib/` and `bin/`, `share/` (templates + Rexfile), and
the tests. Prose in `README.md` and `Changes` bullets are not.

## Release

`make test` / `make build` / `dzil build` are fine anytime. The release commands that need the
maintainer's go-ahead here: the dzil release, `make docker-push`, `make docker-release` — even
if a plan lists "release" as the next step.

## Deviations from the house rules

- **Load skill `kanban-issues-karr-coordination` before you write anything to a card or a
  commit** — the conventions live only there. Routine reads (`karr list`, `karr show`) need no
  ceremony.
- **A karr id is written `kNN`, never a bare `#NN`** — in commit subjects, card bodies,
  anywhere the text travels; a Git forge resolves `#NN` against its own issue tracker.

## Hazards specific to this repo

- **`make smoke` bootstraps against a REAL machine and wipes its cluster** (`xt/smoke.sh`,
  needs `SMOKE_HOST`). Human-triggered only — never run it, never move its concerns into `t/`.
- **`ocp apply`/`ocp destroy` against a real project dir touches real infrastructure**
  (creates/deletes paid Hetzner servers). Only ever run `ocp` inside tests' temp dirs or on
  explicit instruction with a named target.
- **Toolchain is Docker-first** — never `carton install`/`cpm` on the host; snapshot via
  `make snapshot`, missing Docker targets get added, not worked around. Host runs pollute host
  CPAN state and produce inconsistent results.
- **No kubectl in any code path** — K8s access is Kubernetes::REST/IO::K8s only; kubectl in the
  image is for human debugging.
- **Encrypted files are meant to be committed** (`keys.yaml`, `secrets.yaml`, `age.key.enc`,
  `kubeconfig.yaml` — SOPS/age). `.ocp/` (decrypted state) is gitignored and must stay out.

Both invariants behind the middle two bullets are written down in skill `ocp-core` ("Hard
invariants").

## Output channels — STDOUT vs STDERR

Every `ocp` command has two output channels with separate jobs. Mixing them breaks the pipe —
that is exactly why the rule exists.

- **STDOUT is the payload** (the result) or the **progress report** (rollout, apply narrative)
  that a human reads or a machine processes further.
- **STDERR is everything that went wrong**, with its diagnosis. An error message without a
  diagnosis violates the rule just as much as a diagnosis without an error (maintenance noise
  on STDOUT).
- **Machine-readable commands** (`keys show`, `kubeconfig`, future machine interfaces) print
  **only** the payload on STDOUT; diagnostics strictly on STDERR. Otherwise the output cannot be
  piped cleanly into `authorized_keys` or a parser.

Precedent: since k84 `ocp keys show` deliberately separates them — key material on STDOUT,
everything else on STDERR. This rule generalizes that.

Exceptions and disputed cases belong in a ticket, not in a silent exception. Every deviation
needs a justification.

## Perl specifics — reference, don't restate

Module loading, Moo patterns, cpanfile pinning and house style live in skills `getty-perl-core`
/ `getty-perl-moo` (force-loaded for `ocp-*` agents). The split between the CLI and robocop,
the stack decisions and the hard invariants live in skill `ocp-core`. Do not duplicate that
content here.
