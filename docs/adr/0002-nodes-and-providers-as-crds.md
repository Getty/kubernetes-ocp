# 0002. Model nodes and providers as CRDs and let the cluster hold node-lifecycle state

Date: 2026-08-12
Status: accepted

## Context

Two things need to agree on what nodes exist and what state each one is in: the
external CLI and the in-cluster controller (ADR 0001). They do not share a
filesystem. `.ocp/status.yaml` lives on the operator's laptop; robocop cannot
read it, cannot write it, and would have no way to tell the CLI that a node
moved from `Installing` to `Ready`.

The cluster already runs an API server with watch, optimistic concurrency,
RBAC, and a `kubectl`-shaped read path for humans. Inventing a second
coordination store next to it — a ConfigMap protocol, a lock file, a status
section in `ocp.yaml` — would mean reimplementing all of that badly.

`ocp.yaml` also cannot be the node inventory, because it is the *spec*
(ADR 0004): it says a worker pool should have three nodes, not that
`pool1-2` is currently `Failed` with a message.

## Decision

Define two CRDs in `ocp.internal/v1`, namespace `ocp-system`:

- **`OCPNodeProvider`** — infrastructure provider configuration
  (`type: hetzner|ssh`, location, server type, image, `tokenSecretRef` into a
  `Secret`).
- **`OCPNode`** — one node: `spec.role`, `spec.providerRef`, overrides; and a
  `status` carrying `phase`, `providerId`, `publicIP`, `kubernetesNodeName`,
  `reconciler` and the reconcile lease.

The worker flow is CR-first. `ocp apply` still reads the `workers:` list from
`ocp.yaml`, but it does not deploy from it — it turns each entry into a
`Pending` `OCPNode` CR and lets a reconciler take it from there. `ocp node
add/ls/rm` and `ocp provider add/ls/rm` operate on the CRs directly. The control
plane the CLI bootstrapped also gets an `OCPNode`, purely observational.

Provider credentials are referenced, never inlined: `OCP::Provider->from_cr`
resolves the `Secret` at reconcile time.

### Alternatives rejected

- **Keep worker state in `.ocp/status.yaml`** — unreachable from inside the
  cluster, so the controller could not exist.
- **Keep it in `ocp.yaml`** — mixes desired state with observed state and would
  put machine-generated churn into a git-tracked file the human edits.
- **A bespoke ConfigMap or annotation protocol** — same storage, none of the
  schema validation, subresources, printer columns or RBAC.

## Consequences

- The API server is a hard dependency for node commands. `ocp node ls` cannot
  answer without a reachable, decryptable cluster.
- Anything OCP wants to say about a node has to be expressible in the CRD
  schema, and the CRD has to be applied before the first CR — `_ensure_crds`
  runs on both the bootstrap and the reconcile path (ADR 0018).
- `status` is a subresource, which brings its own trap; see ADR 0009.
- Two writers on one object require arbitration; see ADR 0003.
- Legacy clusters that predate the CRs need migration, hence
  `_migrate_legacy_nodes`.
