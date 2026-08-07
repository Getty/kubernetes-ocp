# Node Lifecycle & Reconcile Unification

Date: 2026-04-14
Scope: Node and Provider lifecycle via CRs. Shared reconcile. Robocop as opt-in wrapper.

## Problem

Three parallel code paths currently produce and install nodes:

- `ocp apply → _deploy_workers` (150+ lines in `lib/OCP/Cmd/Apply.pm`)
- `OCP::Robocop::Controller->reconcile_node` (reconciliation state machine)
- `bin/robocop-test-join` (ad hoc harness)

Each path re-implements the same work (create host, wait SSH, install RKE2/K3s agent, join, verify). `OCP::Robocop::Controller` is the closest thing to shared logic, but it lives under `Robocop/` which implies Robocop owns the work. It does not. Robocop is a wrapper. The function is shared.

`ocp` also has no imperative node/provider commands. Nodes can only be declared in `ocp.yaml` and reconciled by `ocp apply`. There is no way to add a node without committing it to git. There is no way to manage providers as CRs. And 13 `kubectl` shell-outs remain across `lib/OCP/Cmd/*.pm` that predate the move to `Kubernetes::REST`.

## Goals

1. Single `OCP::Node` class owns node reconcile. CLI and Robocop both call it.
2. OCPNode and OCPNodeProvider CRs are single source of truth. CRDs always installed.
3. `ocp node add|rm|ls` and `ocp provider add|rm|ls` commands — imperative CR management.
4. `_deploy_workers` deleted. `ocp apply` writes CRs and drives reconcile through `OCP::Node`.
5. Robocop is opt-in. Default off. Auto-on when hetzner provider used. When off, CLI fully owns reconcile; when on, CLI defers to Robocop once its Deployment reports ready.
6. No `kubectl` in any code path touched by this work. All access via `Kubernetes::REST` (1.104+, has `ensure`).

## Non-Goals

- CP-failover via Robocop (CP bootstrap stays imperative for now).
- `OCPCluster` or `OCPNodePool` CRDs from the broader realignment spec.
- Finalizers on OCPNodeProvider/OCPNode (CLI-side precheck only, K8s finalizer pattern deferred until Robocop owns full lifecycle).
- Async (`--no-wait`) mode for apply (add later if needed).

## Architecture

```
Writers                              Reconciler core               Observers
───────────────────────              ──────────────────────        ─────────
ocp apply      ─┐                   OCP::Node                     k8s API
ocp node add   ─┼──► OCPNode CR ─►    ├─ reconcile               (via K::REST)
ocp provider   ─┘                     ├─ reconcile_until_ready       ▲
                                      ├─ teardown                    │
Trigger A: CLI one-shot ──────────────┘                              │
Trigger B: Robocop watch-loop ───► OCP::Node (same class) ───────────┘
```

Invariants:

- CRs are source of truth. `.ocp/status.yaml` retains CP-bootstrap transient state only.
- `OCP::Node` is trigger-neutral. No knowledge of whether CLI or Robocop invoked it.
- Robocop (when active) = thin watcher + dispatcher. Zero reconcile logic of its own.
- Robocop-present detection: `Deployment ocp-system/robocop` with `readyReplicas >= 1`.
  - Not ready → CLI reconciles.
  - Ready → CLI writes CR, waits for Robocop to bring phase to Ready (or Failed).
- All K8s reads/writes use `Kubernetes::REST`. No `kubectl` in any touched file.

### Mutual exclusion between reconcilers

The Robocop-detection gate still allows a race: CLI sees `readyReplicas=0`, Robocop's Deployment becomes ready mid-reconcile, Robocop's watch fires on the same CR. Two `_provision` calls = two Hetzner servers.

Rule: `_provision` (the only phase transition with irreversible side effects) is gated by a lease annotation on the CR:

```
ocp.internal/reconciler-lease: "<reconciler_id>@<RFC3339>@<ttl_seconds>"
```

**Acquisition mechanism:** full-resource `update()` (HTTP PUT) via `Kubernetes::REST`. PUT sends the object's `resourceVersion`; server returns 409 on mismatch. On 409, caller re-reads CR, aborts if lease holder is someone else AND lease is still live, otherwise retries. `patch()` is not used here — the current `Kubernetes::REST::patch` does not take a precondition flag, and a JSON-Patch `test` op on `/metadata/resourceVersion` is more brittle than a simple PUT.

**TTL:** default 300s. Expired leases can be stolen.

**Release:**
- On transition to `Installing` (durable — server exists, `_provision` will not run again): released.
- On `_provision` failure: **kept** until TTL expires. A partially-provisioned node (server created but SSH-wait timed out) must NOT be re-`_provision`ed by another reconciler, or a duplicate Hetzner server is created. Retry after TTL expiry is the responsibility of the provider's `create_server` implementation, which MUST check existing state (by label: `ocp.internal/node-name=<name>`) before creating — this is already required for `Hetzner.pm` idempotency.
- On `_verify` or later failures: released. By that point the server exists and idempotent recreation is safe.

Only `_provision` strictly needs the lease. Later transitions are idempotent (install is rerun-safe, wait_ready is read-only).

## Data Model

### `ocp.yaml` additions

```yaml
robocop: true|false   # optional; default false, auto-true when any hetzner provider referenced
```

Resolution lives in `OCP::Config`:

```perl
sub robocop_enabled {
    my $self = shift;
    return $self->{robocop} if defined $self->{robocop};
    return 1 if $self->_any_hetzner_provider;
    return 0;
}
```

### OCPNode CR

Existing schema (`manifests/robocop/crds/ocpnode.yaml`) covers spec. Two status fields added:

```yaml
status:
  phase: ...                  # existing: Pending|Provisioning|Installing|Joining|Ready|Failed|Terminating
  lastReconcileTime: ...      # NEW — timestamp, set by whoever reconciled
  reconciler: cli|robocop     # NEW — purely informational
```

**CRD schema update required.** The existing CRD uses strict `openAPIV3Schema` with closed `status.properties`. Adding unknown fields will fail validation. Choose one:

1. Extend `status.properties` in `manifests/robocop/crds/ocpnode.yaml` to declare `lastReconcileTime` (string, `format: date-time`) and `reconciler` (string, enum: `cli`, `robocop`). **Preferred.**
2. Add `x-kubernetes-preserve-unknown-fields: true` under `status`. Looser but future-proof.

The lease annotation (`ocp.internal/reconciler-lease`, see Architecture) lives in `metadata.annotations` and needs no schema change.

### OCPNodeProvider CR

Existing schema stays. No changes.

### Token storage

`ocp provider add --token-file FILE` writes:

- K8s `Secret` `ocp-system/ocp-provider-<name>-token`, data key `token`
- `OCPNodeProvider` with `spec.hetzner.tokenSecretRef: { name: ocp-provider-<name>-token, key: token }`

Atomic: secret first, then CR. If CR write fails, secret is left (overwritten on retry).

### Control Plane as OCPNode

After CP bootstrap completes in `ocp apply`, a CR `OCPNode/cp-1` with `role: control-plane, status.phase: Ready` is written. `ocp node ls` sees CP and workers uniformly. CP reconcile is out of scope — CR is observational.

`providerRef` is required by the CRD. For the CP CR, it points at the same provider that bootstrapped it (resolved from `ocp.yaml`'s `controlPlanes.provider`). If the CP was bootstrapped via a provider that doesn't yet have a matching `OCPNodeProvider` CR (first-time apply), `ocp apply` writes the provider CR before writing the CP CR — the provider CR write is part of step 5 of the apply refactor, which precedes step 4 (CP CR write) in practice: **reorder apply flow so providers are written before the CP CR.** See updated Apply Refactor section.

## `OCP::Node` Module

### Attributes (Moo)

```perl
has cr            => (is => 'ro', required => 1);
has k8s           => (is => 'ro', required => 1);  # Kubernetes::REST
has provider      => (is => 'ro');                 # OCP::Provider::* — required for reconcile, not for observe-only
has ssh_key       => (is => 'ro');                 # required for _provision/_install
has server_url    => (is => 'ro');                 # https://cp:9345 — required for _install (worker)
has join_token    => (is => 'ro');                 # RKE2/K3s join token — required for _install (worker)
has distribution  => (is => 'ro', default => sub { 'rke2' });
has registry_cfg  => (is => 'ro');                 # passthrough to Rex install
has verbose       => (is => 'ro', default => 0);
has reconciler_id => (is => 'ro', default => sub { 'cli' });
```

Deps validation happens per phase transition (BUILD-time check only for `cr` and `k8s`). Calling `reconcile` on a worker CR without `join_token` dies with a clear message; observational CP construction (`from_cr` on a `role: control-plane` CR) only needs `cr` + `k8s` and cannot advance phases — `reconcile` is a no-op.

### Constructors

```perl
OCP::Node->new(%args);                         # raw
OCP::Node->from_cr($cr_hash_or_object, %deps); # reads role/host/gpu from CR
```

### Public methods

```perl
$node->reconcile;                              # one phase transition, idempotent
$node->reconcile_until_ready(timeout => 600);  # loop until Ready|Failed|timeout
$node->teardown;                               # drain + provider-destroy + clear
```

### Private (separately testable)

```perl
$node->_provision;          # Pending → Provisioning → Installing
$node->_install_kubernetes; # install server (CP) or agent (worker) via OCP::Rex
$node->_wait_ready;         # poll k8s Node object readiness
$node->_verify;             # final health check
$node->_patch_status(%);    # Kubernetes::REST patch on /status subresource
```

### Phase transitions

| From            | To              | Action                              |
| ---             | ---             | ---                                 |
| Pending         | Provisioning    | `provider->create_server`           |
| Provisioning    | Installing      | wait SSH, `_install_kubernetes`     |
| Installing      | Joining         | agent up, cert issued               |
| Joining         | Ready           | Node object in cluster, condition Ready |
| any             | Failed          | caught exception, `status.message`  |
| Ready           | Terminating     | `teardown` invoked                  |

Each transition in `eval`. Failure sets `phase: Failed`, records `message`, updates `conditions[].type: Progressing, status: False, reason: ...`. No automatic retry inside `reconcile` — retry is wrapper policy:

- CLI wrapper: `reconcile_until_ready` polls with short sleep + max attempts.
- Robocop wrapper: standard controller backoff via watch-requeue.

## Robocop as Wrapper

`OCP::Robocop::Controller` stripped to thin watcher:

- Watch `OCPNode` objects (via `Net::Async::Kubernetes`).
- On each event: build `OCP::Node->from_cr($cr, %deps, reconciler_id => 'robocop')` and call `->reconcile`.
- Deps (`k8s`, `ssh_key`, `join_token`, `server_url`, `distribution`, `reconciler_id`) come from the Controller's own initialization. `reconciler_id` is always `'robocop'` in this wrapper.
- Provider instance resolved from `spec.providerRef` → `OCPNodeProvider` CR → token Secret.

The reconcile state machine, provisioning logic, rex install, k8s checks — all moved to `OCP::Node`. Controller becomes event handler + dispatcher, ~80–120 lines.

`OCP::Robocop::Controller` is only loaded inside the in-cluster Deployment (separate entry binary `bin/robocop`). CLI does not load it.

## CLI Commands

### `ocp node add`

```
ocp node add [--name NAME] --host HOST [--role worker] [--provider NAME]
             [--gpu] [--server-type TYPE] [--location LOC] [--image IMG]
             [--no-wait]
```

Flag compatibility (validated before CR write):

| Flag             | `hetzner` | `ssh` | `local` |
| ---              | ---       | ---   | ---     |
| `--host`         | rejected  | req   | rejected|
| `--server-type`  | optional  | rej   | rej     |
| `--location`     | optional  | rej   | rej     |
| `--image`        | optional  | rej   | rej     |

Incompatible flag → exit 1 with explicit message naming the provider type.

Behavior:

1. Resolve provider (in order): explicit `--provider` → single provider in cluster → default-annotated provider → error "multiple providers, --provider required".
2. Validate flags against resolved provider's type. Build OCPNode spec.
3. `k8s->ensure($ocpnode_cr)` → Pending CR in cluster.
4. Detect Robocop: `k8s->get('Deployment', 'robocop', namespace => 'ocp-system')`, check `readyReplicas`.
5. If Robocop ready:
   - `--no-wait` → print CR name, exit 0.
   - Default → poll CR `.status.phase` until Ready/Failed/timeout.
6. If Robocop not ready:
   - Construct `OCP::Node->from_cr($cr, %deps)` (deps pulled from existing cluster state: join token from `.ocp/status.yaml`, server_url from first CP IP).
   - `$node->reconcile_until_ready(timeout => 600)`.
7. Exit status: 0 if Ready, 1 otherwise.

### `ocp node rm <name>`

1. Load CR. If missing: error.
2. Patch CR `phase: Terminating` first — this is the durable marker; every subsequent step is resumable.
3. Drain k8s Node (via `Kubernetes::REST` patch + eviction API). Skip if Node object doesn't exist.
4. Provider teardown (`$provider->delete_server`). Idempotent — skip if server already gone.
5. Delete k8s Node object. Skip if gone.
6. Delete OCPNode CR.

On any failure between 2 and 6: the CR stays at `phase: Terminating` with a condition describing the failed step; `ocp node rm <name>` is re-runnable and picks up where it left off (each step checks current reality before acting).

### `ocp node ls`

Lists OCPNodes with: name, role, phase, provider, public IP, age. Colored if TTY. Uses `k8s->list`.

### `ocp provider add`

```
ocp provider add --name NAME --type hetzner --token-file FILE
                 [--location LOC] [--server-type TYPE] [--image IMG]
                 [--default]
```

Writes Secret then OCPNodeProvider CR. Flag mapping:

- `--type hetzner` → `spec.type: hetzner`
- `--token-file FILE` contents → Secret `ocp-system/ocp-provider-<name>-token`, key `token`; CR gets `spec.hetzner.tokenSecretRef: {name, key}`
- `--location`, `--server-type`, `--image` → `spec.hetzner.{location, serverType, image}` (per CRD schema)
- `--default` → annotation `ocp.internal/default: "true"` (single default cluster-wide; if another provider already has it, strip it first)

### `ocp provider rm <name>`

Blocks if any `OCPNode.spec.providerRef == name`:

```
Error: provider 'hetzner-a' has 3 referencing nodes:
  worker-1 (Ready)
  worker-2 (Ready)
  gpu-1   (Provisioning)
Remove nodes first: ocp node rm worker-1 worker-2 gpu-1
```

Exit 1. No `--force`. Deletes Secret + CR on success.

### `ocp provider ls`

Lists OCPNodeProviders with: name, type, location, default-flag, referencing-node-count.

## `ocp apply` Refactor

New flow:

1. Bootstrap first control plane (unchanged, imperative).
2. Install Cilium (unchanged).
3. `k8s->ensure` CRDs from `manifests/robocop/crds/` — **always**, regardless of `robocop_enabled`.
4. For each provider in config → `k8s->ensure` OCPNodeProvider + Secret. **Must precede CP CR write** (next step) because CP CR's `providerRef` must resolve.
5. Write CP OCPNode CR with `phase: Ready` and `providerRef` pointing at the provider that bootstrapped it.
6. For each worker pool entry → `k8s->ensure` OCPNode CR (Pending).
7. If `config->robocop_enabled`:
   - `k8s->ensure` Robocop RBAC + Deployment.
   - Wait for `readyReplicas >= 1` (timeout 60s).
   - If ready: loop until all OCPNodes Ready (timeout 600s). Robocop does the work.
   - If not ready: fall back to CLI reconcile for workers (see below).
8. If `!config->robocop_enabled` OR fallback:
   - For each worker CR: `OCP::Node->from_cr($cr, %deps)->reconcile_until_ready`.
9. Final status report.

`_deploy_workers` deleted. All worker provisioning flows through `OCP::Node`.

## kubectl Removal

Audit result (grep `kubectl` under `lib/`):

**Actual code paths to remove:** none. `DeployRobocop.pm` and `InjectKey.pm` already had their kubectl shell-outs removed; only POD strings describing the history remain. No local `kubectl` process is spawned from Perl code.

**Remote kubectl-over-SSH (intentional, keep):**
- `lib/OCP/Cmd/Apply.pm:375` — `ssh->run("/var/lib/rancher/rke2/bin/kubectl ... get nodes")` on the freshly bootstrapped CP, before the API is reachable from the CLI host. Out of scope for this work; replace later once the CP-bootstrap flow can talk to the API directly.

**User-facing print strings (keep):** `Apply.pm:319/327/485`, `Kubeconfig.pm:85`, `Versions.pm:155`, `OCP.pm:169` — hints to the user ("run `kubectl ...`"), POD. Not code paths.

**Stubs to reimplement via `Kubernetes::REST`:**
- `InjectKey.pm` — was port-forward + exec. Needs verification that `Kubernetes::REST` exposes `exec`/`port-forward` primitives (the upgrade to SPDY/WebSocket is non-trivial over plain HTTP). If missing: add to `Kubernetes::REST` upstream before reimplementing here. Otherwise keep the current stub.
- `DeployRobocop.pm` — was `kubectl apply -k`. Already a stub; reimplement as sequential `k8s->ensure` over the manifests in `manifests/robocop/`. This is part of this spec (apply refactor step 7).

Goal 6 restated: **no new kubectl shell-outs; remove `Apply.pm:375` in a follow-up once an API-server path exists.**

## Testing

- Unit: `OCP::Node` state machine with mocked `provider`, `k8s`, `ssh`. `t/07-node.t`.
- Unit: `OCP::Config` `robocop_enabled` resolution. `t/08-config-robocop.t`.
- Integration: `bin/robocop-test-join` rewritten to use `OCP::Node` directly (no K8s).
- Command tests: `t/09-node-add.t`, `t/10-node-rm.t`, `t/11-provider.t` with mocked `Kubernetes::REST`.

All existing tests (`t/00-load.t`, `t/06-versions.t`, etc.) must still pass.

## Documentation

- `CLAUDE.md` — update "Implementierte Features" and "Commands" lists. Add node/provider command table.
- POD in new modules (`OCP::Node`, `OCP::Cmd::Node*`, `OCP::Cmd::Provider*`) per `@Author::GETTY` conventions.
- `README.md` — add quickstart for `ocp node add` workflow.

## Migration / Backwards Compat

- Existing clusters deployed with old `_deploy_workers` have k8s Nodes but no matching OCPNode CRs.
- One-shot reconciliation on first `ocp apply` after upgrade: for each k8s Node not already tracked by an OCPNode CR, create observational CR with `phase: Ready` and labels mapping from Node annotations/labels. CRs are assigned to the provider that the node's config section references (looked up by node name in `ocp.yaml`). For nodes with no resolvable provider (legacy SSH-only setups), write a synthetic `OCPNodeProvider/legacy` (type `ssh`, no credentials) and reference it — `ocp provider rm legacy` will block while any observational node still references it, which is the desired behavior (user explicitly adopts or removes each).
- CRD `OCPNode.spec.providerRef` stays required; the migration honors that by always writing a concrete ref.
- `ocp.yaml` still works; worker pool entries still produce the same nodes, just now via CRs.

## Risks

- Robocop ready-detection race: Deployment ready but watcher not yet dispatching. Mitigate with explicit 5s grace after `readyReplicas >= 1` before CLI assumes Robocop will handle it. On timeout, CLI takes over.
- CR / `.ocp/status.yaml` drift during transition: documented, accept for one release, remove status-file node tracking once CRs are canonical.
- `OCP::Node` attribute threading during apply: many deps (`ssh_key`, `join_token`, `server_url`) must be built once and reused. Factor a small `OCP::Node::Deps` builder, injected into each `from_cr`.

## Implementation Order

Grouped by dependency. Steps within a group are parallelizable; groups are sequential.

**Group A — independent cleanup / foundations:**

1. Add `robocop_enabled` + tests in `OCP::Config`.
2. CRD schema update: add `status.lastReconcileTime`/`reconciler` to `manifests/robocop/crds/ocpnode.yaml`.
3. `DeployRobocop.pm` reimplementation via `Kubernetes::REST->ensure` over `manifests/robocop/` (was a kubectl stub). `InjectKey.pm` only if `Kubernetes::REST` exposes exec/port-forward — otherwise deferred and noted.

**Group B — core module:**

4. Extract `OCP::Node` from `OCP::Robocop::Controller`. Port Controller to use it (thin watcher). Implement lease mechanism in `_provision`.

**Group C — CLI surface (depends on B):**

5. `OCP::Cmd::Provider::Add|Rm|Ls`.
6. `OCP::Cmd::Node::Add|Rm|Ls`.

**Group D — apply refactor (depends on B + C):**

7. Refactor `ocp apply` to write CRs + call `OCP::Node`. Delete `_deploy_workers`. Robocop deploy gate + fallback path. Migration path for legacy clusters (synthesize `OCPNodeProvider/legacy` where needed).

**Group E — docs + validation:**

8. Docs + POD updates (CLAUDE.md command table, README quickstart, per-module POD).
9. Full test suite in Docker; smoke-test `ocp node add` against a local cluster.
