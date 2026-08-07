# Node Lifecycle & Reconcile Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unify three parallel node-reconcile paths into one `OCP::Node` class; add CR-based imperative CLI commands for nodes and providers; make Robocop opt-in; complete migration away from kubectl shell-outs.

**Architecture:** New `OCP::Node` (Moo, trigger-neutral) owns the Pending→Provisioning→Installing→Joining→Ready state machine. Both `ocp apply` (CLI one-shot) and `OCP::Robocop::Controller` (in-cluster watch-loop) build instances of it from OCPNode CRs. CRs (OCPNode, OCPNodeProvider) are the single source of truth; `.ocp/status.yaml` retains only CP-bootstrap transient state. Robocop is installed only when opted in (`robocop: true` in `ocp.yaml`) or when a hetzner provider is used.

**Tech Stack:** Perl (Moo), `Kubernetes::REST` 1.104+ (has `ensure()`), `IO::K8s` (typed objects), `Net::Async::Kubernetes` (watches in Robocop), `Rex` (RKE2/K3s install over SSH), `WWW::Hetzner` (Hetzner provider). All work done inside Docker (`make test`, `make snapshot`).

**Spec:** `docs/superpowers/specs/2026-04-14-node-lifecycle-design.md`

---

## Ground Rules

- **Docker-only:** run all tests via `make test` (which runs `prove -l t/` inside the image). Never `carton install` or `prove` on host.
- **No kubectl in code:** every K8s API call goes through `Kubernetes::REST`. Print-strings telling users to run kubectl are fine; spawning kubectl from Perl is not.
- **`ensure()` over manual get/create/update:** for idempotent CR writes, use `Kubernetes::REST->ensure`.
- **Commit after each task.** Commit messages are prefixed by the task ID (e.g. `A1:`, `B4:`) for easy bisect.
- **Tests first.** Each task has a failing test before code.
- **TDD scope:** unit tests use mocked `Kubernetes::REST` / mocked providers. No cluster needed until task E2.

---

## File Structure

**New files:**

- `lib/OCP/Node.pm` — the trigger-neutral reconcile class (extracted from Controller.pm)
- `lib/OCP/Cmd/Node.pm` — `ocp node` parent command (MooX::Cmd dispatch)
- `lib/OCP/Cmd/Node/Add.pm`
- `lib/OCP/Cmd/Node/Rm.pm`
- `lib/OCP/Cmd/Node/Ls.pm`
- `lib/OCP/Cmd/Provider.pm` — `ocp provider` parent command
- `lib/OCP/Cmd/Provider/Add.pm`
- `lib/OCP/Cmd/Provider/Rm.pm`
- `lib/OCP/Cmd/Provider/Ls.pm`
- `t/16-node.t` — `OCP::Node` state machine
- `t/17-config-robocop.t` — `robocop_enabled` resolution
- `t/18-node.t` — `ocp node` command suite (add, rm, ls)
- `t/19-provider.t` — provider add/rm/ls
- `t/20-apply-refactor.t` — apply flow CR-writing integration

**Modified files:**

- `lib/OCP/Config.pm` — add `robocop_enabled` method
- `lib/OCP/Robocop/Controller.pm` — strip state-machine logic, keep watcher + dispatcher (~80–120 lines)
- `lib/OCP/Cmd/Apply.pm` — delete `_deploy_workers` (line ~1937), write CRs, call `OCP::Node`, Robocop gate + fallback
- `lib/OCP/Cmd/DeployRobocop.pm` — reimplement via `Kubernetes::REST->ensure` over `manifests/robocop/`
- `manifests/robocop/crds/ocpnode.yaml` — add `status.lastReconcileTime` and `status.reconciler`
- `bin/robocop-test-join` — rewrite to use `OCP::Node` directly
- `CLAUDE.md` — update "Implementierte Features" and "Commands" lists
- `README.md` — quickstart for `ocp node add`

---

## Group A — Independent Foundations (parallelizable)

### Task A1: `robocop_enabled` in `OCP::Config`

**Files:**
- Modify: `lib/OCP/Config.pm`
- Test: `t/17-config-robocop.t`

- [ ] **Step 1: Write failing tests**

```perl
# t/17-config-robocop.t
use strict; use warnings; use Test::More;
use Path::Tiny;
use OCP::Config;

my $tmp = Path::Tiny->tempdir;

subtest 'explicit robocop: true' => sub {
    $tmp->child('ocp.yaml')->spew(<<'YAML');
name: test
robocop: true
controlPlanes: { provider: ssh, host: 1.2.3.4 }
YAML
    my $cfg = OCP::Config->new(project_dir => "$tmp");
    ok $cfg->robocop_enabled, 'explicit true';
};

subtest 'explicit robocop: false' => sub {
    $tmp->child('ocp.yaml')->spew(<<'YAML');
name: test
robocop: false
controlPlanes: { provider: hetzner, location: fsn1 }
YAML
    my $cfg = OCP::Config->new(project_dir => "$tmp");
    ok !$cfg->robocop_enabled, 'explicit false wins over hetzner auto-enable';
};

subtest 'auto-on with hetzner provider' => sub {
    $tmp->child('ocp.yaml')->spew(<<'YAML');
name: test
controlPlanes: { provider: hetzner, location: fsn1 }
YAML
    my $cfg = OCP::Config->new(project_dir => "$tmp");
    ok $cfg->robocop_enabled, 'hetzner triggers auto-on';
};

subtest 'default off for ssh-only' => sub {
    $tmp->child('ocp.yaml')->spew(<<'YAML');
name: test
controlPlanes: { provider: ssh, host: 1.2.3.4 }
YAML
    my $cfg = OCP::Config->new(project_dir => "$tmp");
    ok !$cfg->robocop_enabled, 'ssh-only stays off';
};

done_testing;
```

- [ ] **Step 2: Run — expect FAIL** (`make test` → `t/17-config-robocop.t` fails: `robocop_enabled` not defined)

- [ ] **Step 3: Implement in `lib/OCP/Config.pm`**

```perl
sub robocop_enabled {
    my $self = shift;
    return $self->{robocop} if defined $self->{robocop};
    return 1 if $self->_any_hetzner_provider;
    return 0;
}

sub _any_hetzner_provider {
    my $self = shift;
    return 1 if ($self->{controlPlanes}{provider} // '') eq 'hetzner';
    for my $pool (@{$self->{workers} || []}) {
        return 1 if ($pool->{provider} // '') eq 'hetzner';
    }
    return 0;
}
```

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add lib/OCP/Config.pm t/17-config-robocop.t
git commit -m "A1: add robocop_enabled to OCP::Config"
```

---

### Task A2: CRD schema update — `status.lastReconcileTime` + `status.reconciler`

**Files:**
- Modify: `manifests/robocop/crds/ocpnode.yaml` (insert under `status.properties` around line 98)

- [ ] **Step 1: Add two properties under `status.properties` in `ocpnode.yaml`:**

```yaml
              lastReconcileTime:
                type: string
                format: date-time
                description: "Timestamp of last reconcile action"
              reconciler:
                type: string
                enum:
                - cli
                - robocop
                description: "Which reconciler last acted on this node"
```

- [ ] **Step 2: Add a printer column for `reconciler` (optional, improves `kubectl get ocpnodes`):**

```yaml
    - name: Reconciler
      type: string
      jsonPath: .status.reconciler
```

- [ ] **Step 3: Validate YAML syntax**

Run: `docker run --rm -v $(pwd):/w -w /w perl:5.42 perl -MYAML::XS=LoadFile -e 'LoadFile("manifests/robocop/crds/ocpnode.yaml"); print "ok\n"'`
Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add manifests/robocop/crds/ocpnode.yaml
git commit -m "A2: add lastReconcileTime/reconciler to OCPNode CRD status"
```

---

### Task A3: Reimplement `OCP::Cmd::DeployRobocop` via `Kubernetes::REST->ensure`

**Files:**
- Modify: `lib/OCP/Cmd/DeployRobocop.pm`

**Current state:** stub (kubectl removal already happened). Needs full reimplementation.

- [ ] **Step 1: Read the existing manifests** (`manifests/robocop/crds/*.yaml`, `manifests/robocop/rbac.yaml`, `manifests/robocop/deployment.yaml`). Each is a single YAML doc. Some files contain `---` separators — `YAML::XS::LoadFile` with list context handles multi-doc.

- [ ] **Step 2: Write the reimplemented `execute` method**

```perl
sub execute {
    my ($self) = @_;
    my $k8s = $self->_build_k8s;  # existing helper or new — uses OCP::Config kubeconfig
    my $manifest_dir = path($self->_share_dir, 'robocop');

    for my $file (sort $manifest_dir->children(qr/\.yaml$/)) {
        next if $file->basename eq 'kustomization.yaml';
        for my $doc (YAML::XS::LoadFile($file)) {
            next unless $doc && ref $doc eq 'HASH';
            $k8s->ensure($doc);
            printf "  [ok] ensured %s/%s\n", $doc->{kind}, $doc->{metadata}{name};
        }
    }
    print "Robocop deployed.\n";
}
```

- [ ] **Step 3: Handle CRDs separately** — CRDs live under `crds/`. `ensure` works for any resource but CRDs must land before anything that references them (OCPNode/OCPNodeProvider CRs). Iterate CRDs first, then rest.

- [ ] **Step 4: Manual smoke test** (deferred to Group E — no unit test here since this hits a live cluster)

- [ ] **Step 5: Commit**

```bash
git add lib/OCP/Cmd/DeployRobocop.pm
git commit -m "A3: reimplement deploy-robocop via Kubernetes::REST->ensure"
```

---

## Group B — Core `OCP::Node` Extraction

### Task B1: Write failing test for `OCP::Node` construction

**Files:**
- Create: `t/16-node.t`

- [ ] **Step 1: Write test for `new` + `from_cr`**

```perl
# t/16-node.t
use strict; use warnings; use Test::More;
use OCP::Node;

my $cr = {
    apiVersion => 'ocp.internal/v1',
    kind => 'OCPNode',
    metadata => { name => 'worker-1', namespace => 'ocp-system' },
    spec => { role => 'worker', providerRef => 'hetzner-a' },
    status => { phase => 'Pending' },
};

my $fake_k8s = bless {}, 'FakeK8s';
my $fake_prov = bless {}, 'FakeProvider';

my $node = OCP::Node->from_cr(
    $cr,
    k8s => $fake_k8s,
    provider => $fake_prov,
    ssh_key => 'KEY',
    server_url => 'https://cp:9345',
    join_token => 'TOKEN',
);

is $node->cr->{metadata}{name}, 'worker-1', 'cr stored';
is $node->phase, 'Pending', 'phase delegated to cr.status.phase';
is $node->role, 'worker', 'role delegated to cr.spec.role';
is $node->reconciler_id, 'cli', 'default reconciler_id is cli';

done_testing;
```

- [ ] **Step 2: Run — FAIL** (module missing)

- [ ] **Step 3: Create `lib/OCP/Node.pm` skeleton**

```perl
package OCP::Node;
# ABSTRACT: Trigger-neutral node reconcile state machine
use Moo;
use Types::Standard qw(Str HashRef InstanceOf);
use namespace::clean;

has cr            => (is => 'ro', required => 1);
has k8s           => (is => 'ro', required => 1);
has provider      => (is => 'ro');
has ssh_key       => (is => 'ro');
has server_url    => (is => 'ro');
has join_token    => (is => 'ro');
has distribution  => (is => 'ro', default => sub { 'rke2' });
has registry_cfg  => (is => 'ro');
has verbose       => (is => 'ro', default => 0);
has reconciler_id => (is => 'ro', default => sub { 'cli' });

sub phase { $_[0]->cr->{status}{phase} // 'Pending' }
sub role  { $_[0]->cr->{spec}{role} }
sub name  { $_[0]->cr->{metadata}{name} }

sub from_cr {
    my ($class, $cr, %deps) = @_;
    return $class->new(cr => $cr, %deps);
}

1;
```

- [ ] **Step 4: Run — PASS**

- [ ] **Step 5: Commit**

```bash
git add lib/OCP/Node.pm t/16-node.t
git commit -m "B1: OCP::Node skeleton with from_cr constructor"
```

---

### Task B2: Port `_provision` from Controller.pm with lease

**Files:**
- Modify: `lib/OCP/Node.pm` (add `_provision`, `_acquire_lease`, `_release_lease`, `_patch_status`)
- Modify: `t/16-node.t` (add lease + provisioning tests)

- [ ] **Step 1: Read current impl** in `lib/OCP/Robocop/Controller.pm` (`provision_node` method and nearby). Understand the Hetzner-label-based idempotency path — provider's `create_server` already checks by label `ocp.internal/node-name=<name>`.

- [ ] **Step 2: Add mock helpers at top of `t/16-node.t`**

```perl
package FakeK8s {
    sub new { my ($c, %a) = @_; bless { calls => [], %a }, $c }
    sub get    { my ($s, @a) = @_; push @{$s->{calls}}, [get    => \@a]; $s->{cr_cb}    ? $s->{cr_cb}->(@a)    : $s->{cr} }
    sub update { my ($s, $o) = @_;  push @{$s->{calls}}, [update => $o];  $s->{update_cb} ? $s->{update_cb}->($o) : $o }
    sub patch  { my ($s, @a) = @_; push @{$s->{calls}}, [patch  => \@a]; $s->{patch_cb}  ? $s->{patch_cb}->(@a)  : {} }
    sub ensure { my ($s, $o) = @_;  push @{$s->{calls}}, [ensure => $o];  $o }
    sub delete { my ($s, @a) = @_; push @{$s->{calls}}, [delete => \@a]; {} }
    sub list   { my ($s, @a) = @_; push @{$s->{calls}}, [list   => \@a]; $s->{list} // { items => [] } }
}
package FakeProvider {
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub create_server { my ($s, %a) = @_; $s->{create_cb} ? $s->{create_cb}->(%a) : { id => 'SRV1', ipv4 => '1.2.3.4' } }
    sub delete_server { my ($s, @a) = @_; $s->{delete_cb} ? $s->{delete_cb}->(@a) : 1 }
}
```

- [ ] **Step 3: Write failing tests for lease + provision**

```perl
subtest 'lease acquisition stamps annotation and PUTs with resourceVersion' => sub {
    my $cr = { apiVersion => 'ocp.internal/v1', kind => 'OCPNode',
        metadata => { name => 'w1', namespace => 'ocp-system', resourceVersion => '100' },
        spec => { role => 'worker', providerRef => 'p' }, status => { phase => 'Pending' } };
    my $k = FakeK8s->new(cr => $cr);
    my $node = OCP::Node->from_cr($cr, k8s => $k, provider => FakeProvider->new,
        ssh_key => 'K', server_url => 'U', join_token => 'T');
    $node->_acquire_lease;
    my ($update) = grep { $_->[0] eq 'update' } @{$k->{calls}};
    ok $update, 'update called';
    like $update->[1]{metadata}{annotations}{'ocp.internal/reconciler-lease'},
         qr/^cli\@.+\@300$/, 'lease annotation written';
};

subtest 'lease held by another reconciler dies' => sub {
    my $cr = { metadata => { annotations => { 'ocp.internal/reconciler-lease' =>
        'robocop@' . _rfc3339_now() . '@300' } } };
    my $node = OCP::Node->from_cr($cr, k8s => FakeK8s->new(cr => $cr), ...);
    eval { $node->_acquire_lease };
    like $@, qr/lease held/, 'refuses to steal live lease';
};

subtest '_provision calls provider->create_server and transitions to Installing' => sub {
    my $called;
    my $prov = FakeProvider->new(create_cb => sub { $called = { @_ };
        { id => 'SRV1', ipv4 => '1.2.3.4' } });
    # ... build node, invoke _provision, assert phase transitioned, assert $called contains node-name label
};
```

- [ ] **Step 4: Define lease helpers inline or as small private subs in `OCP::Node`**

```perl
use Time::Piece ();
sub _rfc3339_now { Time::Piece::gmtime->strftime('%Y-%m-%dT%H:%M:%SZ') }

sub _lease_parse {
    my $v = shift or return;
    $v =~ /^([^@]+)\@([^@]+)\@(\d+)$/ or return;
    return { holder => $1, ts => $2, ttl => $3 };
}

sub _lease_live {
    my $l = _lease_parse(shift) or return 0;
    my $t = Time::Piece->strptime($l->{ts}, '%Y-%m-%dT%H:%M:%SZ')->epoch;
    return time - $t < $l->{ttl};
}

sub _lease_mine {
    my ($v, $id) = @_;
    my $l = _lease_parse($v) or return 0;
    return $l->{holder} eq $id;
}
```

- [ ] **Step 5: Run — FAIL** (`_acquire_lease` / `_provision` not defined)

- [ ] **Step 6: Port `_provision` + lease helpers to `lib/OCP/Node.pm`**

Key design:
- `_acquire_lease` — reads CR, sets `metadata.annotations.{ocp.internal/reconciler-lease}` to `"<reconciler_id>@<now>@300"`, calls `k8s->update($cr)` (full PUT). On 409: re-read, check lease holder, retry or abort.
- `_provision` — checks `phase == Pending`, acquires lease, calls `provider->create_server`, patches status to `Provisioning` with `providerId` + `publicIP`, then transitions to `Installing`. Releases lease on successful transition.
- `_release_lease` — called on successful transition to `Installing` (NOT on `_provision` failure — see spec).
- `_patch_status` — uses `k8s->patch` with JSON-patch type to update `/status` subresource.

Reference code (sketch):

```perl
sub _acquire_lease {
    my $self = shift;
    my $cr = $self->k8s->get($self->_api, $self->_kind, $self->name, namespace => $self->namespace);
    my $ann = $cr->{metadata}{annotations} //= {};
    my $existing = $ann->{'ocp.internal/reconciler-lease'};
    if ($existing && _lease_live($existing) && !_lease_mine($existing, $self->reconciler_id)) {
        die "lease held by another reconciler: $existing\n";
    }
    $ann->{'ocp.internal/reconciler-lease'} = sprintf "%s@%s@%d",
        $self->reconciler_id, _rfc3339_now(), 300;
    return $self->k8s->update($cr);  # PUT, sends resourceVersion
}
```

- [ ] **Step 7: Run — PASS**

- [ ] **Step 8: Commit**

```bash
git add lib/OCP/Node.pm t/16-node.t
git commit -m "B2: port _provision with reconciler lease to OCP::Node"
```

---

### Task B3: Port `_install_kubernetes`, `_wait_ready`, `_verify`

**Files:**
- Modify: `lib/OCP/Node.pm`
- Modify: `t/16-node.t`

- [ ] **Step 1: Read `install_kubernetes` and `wait_for_node_ready` in Controller.pm** — understand the `OCP::Rex` call shape and the `k8s->get('Node', ...)` condition polling.

- [ ] **Step 2: Write failing tests** (mock `OCP::Rex`, mock `k8s->get('Node', ...)` returning a Node with `Ready=True`).

- [ ] **Step 3: Port the three methods.**

- [ ] **Step 4: Run — PASS**

- [ ] **Step 5: Commit**

```bash
git add lib/OCP/Node.pm t/16-node.t
git commit -m "B3: port _install_kubernetes, _wait_ready, _verify"
```

---

### Task B4: Public `reconcile` + `reconcile_until_ready` + `teardown`

**Files:**
- Modify: `lib/OCP/Node.pm`
- Modify: `t/16-node.t`

- [ ] **Step 1: Write tests**

```perl
subtest 'reconcile_until_ready terminates on Ready' => sub {
    # node starts Pending, mocked provider/ssh/k8s advance phases each call
    # assert reconcile_until_ready returns true within max_attempts
};
subtest 'reconcile_until_ready returns false on Failed' => sub { ... };
subtest 'teardown drains, calls provider->delete_server, deletes Node + CR' => sub { ... };
```

- [ ] **Step 2: Run — FAIL**

- [ ] **Step 3: Implement**

```perl
sub reconcile {
    my $self = shift;
    my $p = $self->phase;
    eval {
        if    ($p eq 'Pending')      { $self->_provision }
        elsif ($p eq 'Provisioning') { $self->_install_kubernetes }
        elsif ($p eq 'Installing')   { $self->_wait_ready }
        elsif ($p eq 'Joining')      { $self->_verify }
        # Ready / Failed / Terminating: no-op
    };
    if ($@) {
        $self->_patch_status(phase => 'Failed', message => "$@");
        return 0;
    }
    $self->_patch_status(lastReconcileTime => _rfc3339_now(), reconciler => $self->reconciler_id);
    return 1;
}

sub reconcile_until_ready {
    my ($self, %opt) = @_;
    my $timeout = $opt{timeout} // 600;
    my $deadline = time + $timeout;
    while (time < $deadline) {
        $self->reconcile;
        # re-read CR
        $self->_refresh;
        return 1 if $self->phase eq 'Ready';
        return 0 if $self->phase eq 'Failed';
        sleep 5;
    }
    return 0;
}

sub teardown { ... }  # drain Node, provider->delete_server, delete Node + CR
```

- [ ] **Step 4: Run — PASS**

- [ ] **Step 5: Commit**

```bash
git add lib/OCP/Node.pm t/16-node.t
git commit -m "B4: OCP::Node public reconcile + teardown API"
```

---

### Task B5: `OCP::Provider->from_cr` factory

**Files:**
- Modify: `lib/OCP/Provider.pm` (add `from_cr` class method)
- Extend: `t/12-provider.t` (existing)

- [ ] **Step 1: Write failing test** — given an `OCPNodeProvider` CR with `spec.type: hetzner` and a `spec.hetzner.tokenSecretRef`, `OCP::Provider->from_cr($cr, k8s => $fake_k8s)` returns an `OCP::Provider::Hetzner` instance with the token resolved from the Secret.

- [ ] **Step 2: Implement**

```perl
sub from_cr {
    my ($class, $cr, %deps) = @_;
    my $type = $cr->{spec}{type};
    my $impl_class = "OCP::Provider::\u$type";
    # dispatch: hetzner reads spec.hetzner.tokenSecretRef and resolves Secret via $deps{k8s}
    # ssh reads spec.ssh.*; local takes no args
    ...
}
```

- [ ] **Step 3: Run — PASS**

- [ ] **Step 4: Commit**

```bash
git add lib/OCP/Provider.pm t/12-provider.t
git commit -m "B5: OCP::Provider->from_cr factory"
```

---

### Task B6: Port `OCP::Robocop::Controller` to thin wrapper

**Files:**
- Modify: `lib/OCP/Robocop/Controller.pm` (strip to ~80–120 lines)

- [ ] **Step 1: Identify watcher code** (probably uses `Net::Async::Kubernetes`). The state-machine methods (`reconcile_node`, `provision_node`, `install_kubernetes`, `wait_for_node_ready`) must be deleted — they moved to `OCP::Node`.

- [ ] **Step 2: Rewrite on-event handler**

```perl
sub _handle_event {
    my ($self, $event) = @_;
    my $cr = $event->{object};
    my $prov_cr = $self->kube->get('ocp.internal/v1', 'OCPNodeProvider',
        $cr->{spec}{providerRef}, namespace => $self->namespace);
    my $provider = OCP::Provider->from_cr($prov_cr, k8s => $self->kube);
    my $node = OCP::Node->from_cr($cr,
        k8s => $self->kube,
        provider => $provider,
        ssh_key => $self->ssh_key,
        server_url => $self->server_url,
        join_token => $self->join_token,
        distribution => $self->distribution,
        reconciler_id => 'robocop',
    );
    $node->reconcile;
}
```

*(`OCP::Provider->from_cr` is introduced in B5.)*

- [ ] **Step 3: Run existing Controller tests** (if any) — expect compile-and-smoke to succeed.

- [ ] **Step 4: Commit**

```bash
git add lib/OCP/Robocop/Controller.pm lib/OCP/Provider.pm
git commit -m "B6: Robocop Controller becomes thin watcher over OCP::Node"
```

---

### Task B7: Rewrite `bin/robocop-test-join` to use `OCP::Node` directly

**Files:**
- Modify: `bin/robocop-test-join`

- [ ] **Step 1: Strip the ad-hoc harness** — replace with:

```perl
#!/usr/bin/env perl
use OCP::Config; use OCP::Node; use OCP::Provider::Hetzner; use Kubernetes::REST;
# ... build deps from args/env, construct a synthetic CR hash, call ->reconcile_until_ready
```

- [ ] **Step 2: Manual run against a throwaway Hetzner server** (document in commit message if tested)

- [ ] **Step 3: Commit**

```bash
git add bin/robocop-test-join
git commit -m "B7: robocop-test-join uses OCP::Node directly"
```

---

## Group C — CLI Surface

### Task C1: `OCP::Cmd::Provider` parent + `Provider::Ls`

**Files:**
- Create: `lib/OCP/Cmd/Provider.pm`, `lib/OCP/Cmd/Provider/Ls.pm`
- Create: `t/19-provider.t`

- [ ] **Step 1: Write failing test for `ls` output** (mock `k8s->list` returning two provider CRs, assert table contains names/types/ref counts)

- [ ] **Step 2: Wire MooX::Cmd dispatch in `lib/OCP/Cmd/Provider.pm`**

- [ ] **Step 3: Implement `Ls` — lists OCPNodeProviders, counts referencing OCPNodes per provider.**

- [ ] **Step 4: Run — PASS**

- [ ] **Step 5: No manual registration needed** — `lib/OCP.pm` uses `MooX::Cmd`'s auto-discovery, so `lib/OCP/Cmd/Provider.pm` is picked up automatically. Verify: `docker run --rm -v $(pwd):/w -w /w ocp perl -Ilib bin/ocp --help` lists `provider`.

- [ ] **Step 6: Commit**

```bash
git add lib/OCP/Cmd/Provider.pm lib/OCP/Cmd/Provider/Ls.pm t/19-provider.t
git commit -m "C1: ocp provider + ocp provider ls"
```

---

### Task C2: `Provider::Add`

**Files:**
- Create: `lib/OCP/Cmd/Provider/Add.pm`
- Extend: `t/19-provider.t`

- [ ] **Step 1: Write test** — mock `k8s->ensure`, call `ocp provider add --name hetzner-a --type hetzner --token-file /tmp/t` (writing to tmpfile), assert two `ensure` calls (Secret then OCPNodeProvider) with correct payloads.

- [ ] **Step 2: Implement**

Flag→body mapping (from spec):
- `--type hetzner` → `spec.type: hetzner`
- token file contents → `Secret` `ocp-system/ocp-provider-<name>-token`, key `token`
- `spec.hetzner.tokenSecretRef: {name, key}` on the CR
- `--location`, `--server-type`, `--image` → `spec.hetzner.{location, serverType, image}`
- `--default` → annotation `ocp.internal/default: "true"` (strip from any other provider first)

- [ ] **Step 3: Run — PASS**

- [ ] **Step 4: Commit**

```bash
git add lib/OCP/Cmd/Provider/Add.pm t/19-provider.t
git commit -m "C2: ocp provider add"
```

---

### Task C3: `Provider::Rm` with referencing-node precheck

**Files:**
- Create: `lib/OCP/Cmd/Provider/Rm.pm`
- Extend: `t/19-provider.t`

- [ ] **Step 1: Write tests**

```perl
subtest 'blocks when nodes reference provider' => sub {
    # mock k8s->list OCPNode returning 3 CRs with providerRef=hetzner-a
    # run `ocp provider rm hetzner-a`, assert exit 1, output mentions each node
};
subtest 'deletes Secret + CR when no refs' => sub {
    # mock empty list, assert k8s->delete called twice
};
```

- [ ] **Step 2: Implement**

No `--force` flag exists. Failure message:

```
Error: provider 'hetzner-a' has 3 referencing nodes:
  worker-1 (Ready)
  worker-2 (Ready)
  gpu-1   (Provisioning)
Remove nodes first: ocp node rm worker-1 worker-2 gpu-1
```

- [ ] **Step 3: Run — PASS**

- [ ] **Step 4: Commit**

```bash
git add lib/OCP/Cmd/Provider/Rm.pm t/19-provider.t
git commit -m "C3: ocp provider rm with referencing-node precheck"
```

---

### Task C4: `OCP::Cmd::Node` parent + `Node::Ls`

**Files:**
- Create: `lib/OCP/Cmd/Node.pm`, `lib/OCP/Cmd/Node/Ls.pm`
- Create: `t/18-node.t` (shared with later tasks; start with ls test here for registration smoke)

- [ ] **Step 1: Write failing test** — mock `k8s->list` OCPNode, assert columns: name, role, phase, provider, public IP, age.

- [ ] **Step 2: Implement Ls + parent dispatch** — `OCP::Cmd::Node` is auto-registered via `MooX::Cmd`'s discovery in `lib/OCP.pm`, no `bin/ocp` edit needed.

- [ ] **Step 3: Run — PASS**

- [ ] **Step 4: Commit**

```bash
git add lib/OCP/Cmd/Node.pm lib/OCP/Cmd/Node/Ls.pm t/18-node.t
git commit -m "C4: ocp node + ocp node ls"
```

---

### Task C5: `Node::Add` with provider resolution + flag validation

**Files:**
- Create: `lib/OCP/Cmd/Node/Add.pm`
- Extend: `t/18-node.t`

- [ ] **Step 1: Write tests for each resolution case and the flag matrix**

```perl
subtest 'resolves single provider implicitly' => sub { ... };
subtest 'errors on multiple providers without --provider' => sub { ... };
subtest 'uses default-annotated provider when multiple' => sub { ... };
subtest 'rejects --host for hetzner provider' => sub { ... };
subtest 'rejects --server-type for ssh provider' => sub { ... };
subtest 'writes OCPNode CR as Pending' => sub { ... };
subtest 'with Robocop ready: polls CR phase' => sub { ... };
subtest 'without Robocop: calls OCP::Node->reconcile_until_ready' => sub { ... };
```

- [ ] **Step 2: Implement** per spec's "Node Add" section. Provider resolution order: explicit `--provider` → single provider → default-annotated → error.

Flag-compatibility matrix (from spec):

| Flag             | `hetzner` | `ssh` | `local` |
| ---              | ---       | ---   | ---     |
| `--host`         | reject    | req   | reject  |
| `--server-type`  | opt       | rej   | rej     |
| `--location`     | opt       | rej   | rej     |
| `--image`        | opt       | rej   | rej     |

Robocop detection: `k8s->get('apps/v1', 'Deployment', 'robocop', namespace => 'ocp-system')->{status}{readyReplicas} // 0 >= 1`. Plus 5s grace.

- [ ] **Step 3: Run — PASS**

- [ ] **Step 4: Commit**

```bash
git add lib/OCP/Cmd/Node/Add.pm t/18-node.t
git commit -m "C5: ocp node add with flag validation and Robocop gate"
```

---

### Task C6: `Node::Rm` with resumable steps

**Files:**
- Create: `lib/OCP/Cmd/Node/Rm.pm`
- Extend: `t/18-node.t`

- [ ] **Step 1: Write tests**

```perl
subtest 'patches phase=Terminating first' => sub { ... };
subtest 'skips each step if already done (resumable)' => sub { ... };
subtest 'leaves CR with Failed condition on partial failure' => sub { ... };
```

- [ ] **Step 2: Implement** per spec's "Node Rm" section:

1. Load CR → error if missing
2. Patch `phase: Terminating` (durable marker)
3. Drain k8s Node (skip if gone) — via `Kubernetes::REST` eviction API
4. `provider->delete_server` (skip if server gone)
5. Delete k8s Node (skip if gone)
6. Delete OCPNode CR

- [ ] **Step 3: Run — PASS**

- [ ] **Step 4: Commit**

```bash
git add lib/OCP/Cmd/Node/Rm.pm t/18-node.t
git commit -m "C6: ocp node rm with resumable teardown"
```

---

## Group D — `ocp apply` Refactor

### Task D1: Rewire apply flow around CRs

**Files:**
- Modify: `lib/OCP/Cmd/Apply.pm` (significant — delete `_deploy_workers` ~line 1937, add new CR-writing flow)

- [ ] **Step 1: Read current `Apply.pm` end-to-end** to map the existing structure (bootstrap CP → Cilium → workers). Identify call-site of `_deploy_workers`.

- [ ] **Step 2: Replace the worker section with spec's Apply flow (steps 1–9):**

```
1. Bootstrap first CP (unchanged).
2. Install Cilium (unchanged).
3. k8s->ensure CRDs from manifests/robocop/crds/ — always.
4. For each provider in config → k8s->ensure OCPNodeProvider + Secret.
5. Write CP OCPNode CR (phase=Ready, providerRef=<bootstrapper>).
6. For each worker pool entry → k8s->ensure OCPNode CR (Pending).
7. If robocop_enabled:
    - k8s->ensure Robocop RBAC + Deployment.
    - Wait readyReplicas>=1 (60s). 5s grace after ready.
    - If ready: poll all OCPNode phases → Ready/Failed/600s timeout.
    - If not ready: fall through to step 8.
8. Else: for each worker CR → OCP::Node->from_cr(...)->reconcile_until_ready.
9. Final status report.
```

- [ ] **Step 3: Delete `_deploy_workers` method and any helper that only it used.**

- [ ] **Step 4: Add integration test scaffold** (`t/20-apply-refactor.t`) with heavy mocking of `k8s`, `OCP::Node`, `OCP::Provider::*`. Test that the right CRs get `ensure`d in the right order. Not a full end-to-end (that's Group E).

- [ ] **Step 5: Run — PASS** (plus full `make test` to verify no regressions)

- [ ] **Step 6: Commit**

```bash
git add lib/OCP/Cmd/Apply.pm t/20-apply-refactor.t
git commit -m "D1: apply writes CRs and delegates worker reconcile to OCP::Node"
```

---

### Task D2: Migration path — observational CRs for legacy clusters

**Files:**
- Modify: `lib/OCP/Cmd/Apply.pm` (add one-shot migration step after step 4, before step 5)

- [ ] **Step 1: Write the migration routine**

For a cluster that was deployed before this change: k8s Nodes exist but OCPNode CRs don't. On first apply after upgrade:

- List k8s Nodes not yet tracked by an OCPNode CR (by matching name).
- For each such Node: synthesize an `OCPNode` CR with `phase: Ready`, `providerRef` = the provider that matches (resolved from `ocp.yaml`) or the synthetic `legacy` provider.
- If the `legacy` provider doesn't exist and is needed, create it:

```yaml
apiVersion: ocp.internal/v1
kind: OCPNodeProvider
metadata:
  name: legacy
  namespace: ocp-system
  annotations:
    ocp.internal/synthetic: "true"
spec:
  type: ssh
```

Synthesized OCPNode body (example):

```yaml
apiVersion: ocp.internal/v1
kind: OCPNode
metadata: {name: <node-name>, namespace: ocp-system, annotations: {"ocp.internal/synthetic": "true"}}
spec: {role: worker, providerRef: legacy, host: <known-ip-or-empty>}
status: {phase: Ready, kubernetesNodeName: <node-name>, publicIP: <ip>}
```

- [ ] **Step 2: Test** — integration test with mocked cluster state that has two Nodes and no OCPNode CRs; assert CRs are synthesized.

- [ ] **Step 3: Run — PASS**

- [ ] **Step 4: Commit**

```bash
git add lib/OCP/Cmd/Apply.pm t/20-apply-refactor.t
git commit -m "D2: migrate legacy nodes to observational OCPNode CRs"
```

---

## Group E — Docs, Validation, Cleanup

### Task E1: Documentation

**Files:**
- Modify: `CLAUDE.md`, `README.md`
- Add: POD to `lib/OCP/Node.pm`, new Cmd modules (via `=attr`/`=method` per `@Author::GETTY` bundle)

- [ ] **Step 1: Update `CLAUDE.md`**

In "Implementierte Features" → "Commands": add
```
- `ocp node add|rm|ls` — Node-Lifecycle via OCPNode CRs
- `ocp provider add|rm|ls` — Provider-Management via OCPNodeProvider CRs
```

In "Module": add `OCP::Node` with one-line description.

- [ ] **Step 2: Update `README.md`** — add a short quickstart:

```
# Add a worker node (idempotent, CR-backed)
ocp provider add --name hetzner-a --type hetzner --token-file token.txt --default
ocp node add worker-1 --role worker
ocp node ls
```

- [ ] **Step 3: Write POD** in `lib/OCP/Node.pm` using `=attr` and `=method` (per the `@Author::GETTY` PodWeaver bundle — inline, not standalone blocks). Cover: all attrs, `from_cr`, `reconcile`, `reconcile_until_ready`, `teardown`.

- [ ] **Step 4: Write POD in each new `OCP::Cmd::Node::*` and `OCP::Cmd::Provider::*` module** — short synopsis per the existing Cmd modules' style.

- [ ] **Step 5: Verify POD renders**

Run: `docker run --rm -v $(pwd):/w -w /w ocp dzil build && podchecker build-dir/lib/OCP/Node.pm`
Expected: no syntax errors.

- [ ] **Step 6: Commit**

```bash
git add CLAUDE.md README.md lib/OCP/Node.pm lib/OCP/Cmd/Node/*.pm lib/OCP/Cmd/Provider/*.pm
git commit -m "E1: docs and POD for node/provider commands"
```

---

### Task E2: End-to-end validation in Docker

**Files:** none modified, purely validation.

- [ ] **Step 1: Full test suite**

Run: `make test`
Expected: all tests pass, including new `t/16–20`.

- [ ] **Step 2: Build image**

Run: `make build`
Expected: image tags applied.

- [ ] **Step 3: Smoke test — add a node to a throwaway cluster**

*(Requires a live local cluster. If not available: skip and document deferral. Use `bin/robocop-test-join` as a substitute if that's easier to instrument.)*

```
ocp init --provider ssh --host 192.168.x.y --nopassword
ocp apply
ocp provider add --name ssh-local --type ssh --default
ocp node add probe --host 192.168.x.z --role worker
ocp node ls    # probe should reach Ready
ocp node rm probe
ocp node ls    # probe gone
```

- [ ] **Step 4: Check for leftover `kubectl` shell-outs**

Run (inside repo): `rg -n 'kubectl' lib/ bin/`
Expected: only hits are POD strings, user-facing print hints, and the `Apply.pm:375` remote-SSH `kubectl` on the RKE2 node (documented in the spec as out of scope). No new spawns, exec, `qx`, or `system` calls of `kubectl`.

- [ ] **Step 5: Note any deferrals**

Document in the commit message (of E3 below) anything not reachable from this environment.

---

### Task E3: Update MEMORY / close out

**Files:** none in repo; potentially add/update memory entries (user's auto-memory).

- [ ] **Step 1: Update project memory if relevant**
  - If anything surprising or non-obvious came out of implementation, save as a memory.
  - Update the `Robocop is opt-in, default off` entry if implementation reshaped the rule.

- [ ] **Step 2: Optional — commit the spec and plan files themselves**

If user wants them in git:

```bash
git add docs/superpowers/specs/2026-04-14-node-lifecycle-design.md docs/superpowers/plans/2026-04-14-node-lifecycle.md
git commit -m "E3: commit node-lifecycle spec and plan"
```

Otherwise delete them.

---

## Execution Notes for the Implementing Engineer

- **Always work inside Docker.** `make test` runs the full suite in the image.
- **`Kubernetes::REST::ensure()`** is the preferred create-or-update primitive. Check its signature in `~/dev/perl/kubernetes-rest/lib/Kubernetes/REST.pm` if you haven't used it before.
- **`OCP::Rex`** wraps Rex for RKE2/K3s installs. Don't reimplement the Rex setup — reuse the existing helper.
- **Provider factory:** `OCP::Provider->from_cr($cr, k8s => $k8s)` dispatches on `spec.type`; the provider reads its own token from the referenced Secret via `k8s`.
- **CR shape reference:** `manifests/robocop/crds/ocpnode.yaml` and `ocpnodeprovider.yaml` are the authoritative schemas.
- **When in doubt about behavior:** the spec (`docs/superpowers/specs/2026-04-14-node-lifecycle-design.md`) is the source of truth. If the plan and the spec disagree, the spec wins — flag it so the plan can be updated.
