# OCP Core Realignment Design

## Context

`kubernetes-ocp` has accumulated bootstrap logic, cluster reconciliation, controller ideas, and optional platform concerns in the same code paths. The current CLI works for parts of the workflow, but too much behavior still depends on ad-hoc shell commands, `kubectl`, and large command modules such as `OCP::Cmd::Apply`.

The release goal is not "more features". The release goal is a smaller, more reliable core:

- Docker-first `ocp` client
- in-cluster `robocop` controller
- typed Kubernetes access through `IO::K8s`
- async controller runtime through `Net::Async::Kubernetes`
- explicit, testable procedures for bootstrap, reconciliation, updates, and repair

## Product Boundary

OCP core is responsible for:

- registry/bootstrap trust integration
- RKE2/K3s bootstrap without bundled network layer
- Cilium installation and verification
- node lifecycle
- GPU/NFD lifecycle
- cluster health, planning, repair, and update orchestration

OCP core is not responsible for:

- cert-manager as a required default
- application deployment concerns
- workload-specific GPU platforms such as non-node Vast.ai container workflows

Vast.ai only belongs in OCP when it is modeled as a real node provider, effectively via VM-capable instances.

## Runtime Model

Normal operation:

1. `ocp` bootstraps the first control plane.
2. `ocp` installs CRDs and `robocop`.
3. `robocop` runs continuously in-cluster and owns reconciliation.
4. `ocp` becomes the external bootstrap, spec-writing, planning, update, and repair client.

Recovery operation:

- `ocp repair` or equivalent may restore `robocop` or re-apply core manifests.
- Recovery must stay limited. It must not reintroduce the CLI as the permanent orchestrator.

## Architecture

### Layer 1: CLI

`ocp` remains thin:

- local project/config handling
- bootstrap of first cluster
- writing desired cluster resources
- dry-run and health/reporting
- explicit repair/update entry points

### Layer 2: Controller

`robocop` becomes the real control plane for OCP state inside the cluster:

- watches OCP resources
- computes diffs
- runs targeted procedures
- writes back status and conditions

`robocop` is intentionally small. It should orchestrate, not contain every host/bootstrap detail inline.

### Layer 3: Shared OCP library

Reusable Perl modules own the real work:

- provider operations
- SSH/host operations
- registry trust/bootstrap
- RKE2/K3s procedures
- Cilium procedures
- GPU/NFD procedures
- Kubernetes discovery/apply/verify helpers

Both `ocp` and `robocop` call the same library code. `robocop` must never shell out to the `ocp` CLI to do its work.

## Kubernetes API Direction

The project should move steadily from shell/`kubectl` access toward typed Perl access:

- `IO::K8s` for resource objects and resource-aware manipulation
- `Kubernetes::REST`/`Kubernetes::REST::Kubeconfig` for synchronous typed API access in CLI/library code
- `Net::Async::Kubernetes` for async watches and controller runtime

`kubectl` remains allowed only as:

- operator/debug tool
- last-resort fallback where no typed path exists yet

It should not remain a primary code path.

## Controller Runtime Direction

The controller runtime should be added to `p5-net-async-kubernetes` as `Net::Async::Kubernetes::Controller`.

That runtime should provide:

- watch registration
- reconcile dispatch
- status patch helpers
- retries/backoff hooks
- queueing and deduplication

It should stay minimal and reusable. Higher-level sugar belongs later, if at all.

## Resource Model

Current CRDs:

- `OCPNodeProvider`
- `OCPNode`

Target model:

- `OCPCluster`
  - core distribution config
  - version/channel intent
  - registry/bootstrap intent
  - Cilium intent
  - GPU/NFD intent
  - component conditions/status
- `OCPNodeProvider`
  - provider credentials/defaults
- `OCPNodePool`
  - desired capacity and class of nodes
- `OCPNode`
  - concrete node instances and observed status

For the first release-oriented cleanup, the repository does not need all target CRDs immediately. It does need code boundaries that make this model reachable.

## Update Model

Updates should follow one deterministic flow:

1. observe
2. diff
3. plan
4. execute
5. verify

`apply` and `update` should eventually share the same engine. `--dry-run` should show the planned component-level actions before execution.

Each core component needs explicit procedures for:

- discover
- plan
- apply
- verify

## Initial Refactoring Priorities

### Phase 1: Release-oriented cleanup in this repo

- introduce shared Kubernetes client helpers in Perl
- replace selected `kubectl`-based paths with typed API access
- start splitting `OCP::Cmd::Apply` into reusable service/component modules
- reduce duplicated manifest/share-dir lookup logic
- make Docker-first operation explicit in docs/help

### Phase 2: Controller foundation

- evolve `robocop` to call shared OCP library code
- add controller runtime support in `p5-net-async-kubernetes`
- tighten CRD status handling and reconcile boundaries

### Phase 3: Resource model expansion

- add `OCPCluster`
- add `OCPNodePool`
- move desired core component state into cluster resources

## First Concrete Code Changes

The first implementation slice should stay small and high-value:

1. Add a shared `OCP::Kubernetes` helper for typed cluster access.
2. Refactor `ocp status` to stop depending on `kubectl`.
3. Use tests to lock behavior around node summaries and output.
4. Use the new helper as the seed for broader CLI and controller cleanup.

## Implementation Notes

- Docker remains the primary release artifact for `ocp`.
- `robocop` should also be shipped as a dedicated image.
- Existing dirty workspace state should not be overwritten or normalized casually during this cleanup.
- Worktree isolation is preferred, but the current workspace may be used when the user explicitly asks to continue in place.
