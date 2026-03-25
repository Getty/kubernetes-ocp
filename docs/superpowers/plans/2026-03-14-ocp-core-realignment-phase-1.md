# OCP Core Realignment Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Start the release-oriented cleanup by introducing a shared typed Kubernetes access layer and moving `ocp status` off `kubectl`.

**Architecture:** Add a small reusable `OCP::Kubernetes` service that constructs a typed Kubernetes API client from kubeconfig content or path, exposes node listing, and centralizes resource-provider registration. Refactor `OCP::Cmd::Status` to use that service so the command is no longer shelling out to `kubectl` for its primary cluster read path.

**Tech Stack:** Perl, Moo, Kubernetes::REST::Kubeconfig, IO::K8s, Test::More

---

## Chunk 1: Typed Kubernetes Helper

### Task 1: Add failing tests for shared node inspection helpers

**Files:**
- Create: `t/10-kubernetes.t`
- Create: `lib/OCP/Kubernetes.pm`

- [ ] **Step 1: Write the failing test**

```perl
use Test::More;
use OCP::Kubernetes;

my $node = bless({...}, 'Fake::Node');
is(OCP::Kubernetes::node_ready($node), 1, 'ready node detected');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `prove -l t/10-kubernetes.t`
Expected: FAIL with missing module or missing helper methods.

- [ ] **Step 3: Write minimal implementation**

Add `lib/OCP/Kubernetes.pm` with:

- constructor accepting `kubeconfig` or `kubeconfig_path`
- lazy typed API construction
- helper methods:
  - `register_resource_providers`
  - `list_nodes`
  - `node_ready`
  - `node_roles`
  - `node_internal_ip`
  - `node_version`

- [ ] **Step 4: Run test to verify it passes**

Run: `prove -l t/10-kubernetes.t`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add t/10-kubernetes.t lib/OCP/Kubernetes.pm
git commit -m "feat: add shared typed kubernetes helper"
```

## Chunk 2: Refactor `ocp status`

### Task 2: Add failing status command regression tests

**Files:**
- Create: `t/11-status-command.t`
- Modify: `lib/OCP/Cmd/Status.pm`
- Modify: `lib/OCP/Kubernetes.pm`

- [ ] **Step 1: Write the failing test**

Cover:

- cluster absent path still reports "No cluster deployed yet"
- cluster present path uses `OCP::Kubernetes`
- node output still includes name, status, roles, version, and internal IP
- command reports connection errors without `kubectl` wording

- [ ] **Step 2: Run test to verify it fails**

Run: `prove -l t/11-status-command.t`
Expected: FAIL because `Status.pm` still shells out to `kubectl`.

- [ ] **Step 3: Write minimal implementation**

Refactor `lib/OCP/Cmd/Status.pm` to:

- decrypt kubeconfig as today
- initialize `OCP::Kubernetes`
- fetch nodes through typed API
- format output using shared helper methods
- remove direct `kubectl` execution from the primary path

- [ ] **Step 4: Run targeted tests**

Run: `prove -l t/10-kubernetes.t t/11-status-command.t`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add t/11-status-command.t lib/OCP/Cmd/Status.pm lib/OCP/Kubernetes.pm
git commit -m "refactor: use typed kubernetes access in status command"
```

## Chunk 3: Project-level verification

### Task 3: Verify no regression in current lightweight suite

**Files:**
- Modify: `Changes`

- [ ] **Step 1: Update unreleased changes entry**

Add a short note describing the new typed Kubernetes helper and the `status` command refactor.

- [ ] **Step 2: Run focused regression suite**

Run: `prove -l t/00-load.t t/04-config.t t/09-config-system.t t/10-kubernetes.t t/11-status-command.t`
Expected: PASS

- [ ] **Step 3: Run broader suite if local environment allows**

Run: `prove -l t`
Expected: PASS, or document unrelated pre-existing failures.

- [ ] **Step 4: Commit**

```bash
git add Changes
git commit -m "test: cover typed kubernetes status path"
```

## Execution Notes

- This first slice intentionally does not tackle CRD redesign yet.
- Keep scope tight: shared typed client + one real consumer.
- If `Kubernetes::REST::Kubeconfig` provider registration needs adjustment, keep it inside `OCP::Kubernetes` rather than re-spreading it into command modules.
- The workspace currently appears dirty; do not revert unrelated user changes.
