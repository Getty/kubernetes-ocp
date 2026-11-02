# Part B: one way into the cluster — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking. In this repo "subagent" means an `ocp-*`
> team agent, never a built-in one.

**Goal:** Every command that talks to the cluster API gets its client from one method in
`OCP::Role::Cmd`. That method unlocks the key, reads kubeconfig.yaml, builds the client,
checks it once, and caches it. When the API is down, every such command says so in one
line that names the server.

**Architecture:** `OCP::Role::Cmd` gains two methods:
- `connect_cluster_api($kubeconfig_yaml)`, the inner function: it builds the client through
  `OCP::Kubernetes`, remembers it, and tells the renderer its endpoint. It sends no request.
- `cluster_api(%opt)`: the key, kubeconfig.yaml, `connect_cluster_api`, one `GET /version`.

With `optional => 1`, `cluster_api` answers undef plus the reason instead of dying.
`OCP::ErrorLine` remembers the endpoint for Part A's renderer. The commands drop their own
copies of the build, in five small groups.

**Tech stack:** Perl 5, Moo, MooX::Cmd / MooX::Options, Test::More, Kubernetes::REST 1.110,
`OCP::Kubernetes`, `OCP::Secrets`.

**Spec:** `docs/superpowers/specs/2026-10-31-one-place-per-concern-design.md`, Part B. Part
A (k398) is on main. Its plan, `docs/superpowers/plans/2026-11-01-part-a-one-error-renderer.md`,
shows what this part builds on: `OCP::ErrorLine::user_line`, `api_error_line`, and the
sweep in `t/398-one-error-renderer.t`.

**Card:** k399. It absorbs:
- k389;
- k395's client-build and raw-API-error items;
- the cluster-API items of k396.

## Decisions this plan makes (the builder's calls in the spec, made here)

1. **Names.** `cluster_api` and `connect_cluster_api`. `cluster` is taken: `deploy-image`
   has a `--cluster` option (DeployImage.pm:103).
2. **The inner function sends no request.** The spec puts `GET /version` into it, but
   `ocp apply` must not get a fatal check there. Right after bootstrap the API may not
   answer yet, and Bootstrap.pm:628-640 checks it itself and tolerates that. So apply calls
   `connect_cluster_api` only; `cluster_api` adds the check for every other command.
3. **The endpoint reaches the renderer through `OCP::ErrorLine`**, process-wide, as the
   secret registry does. When `execute` dies, `run_cli` no longer holds the command object,
   because MooX::Cmd built it inside `new_with_cmd`. The last client built names the
   server.
4. **Optional mode** separates three cases:
   - no kubeconfig.yaml → `(undef, undef)`: nothing to say;
   - a failure while reading, building or checking → `(undef, $line)`;
   - a key problem → dies, outside any eval, as k382 settled.
5. **The key step** is Destroy.pm's k382 block (Destroy.pm:130-135), moved verbatim into
   `cluster_api`. Both modes run it first.

## Global constraints

- No new CPAN dependencies; `cpanfile` stays unchanged.
- Every claim in `t/` stays, except the two that Task 5 replaces on purpose (k395).
  - Some tests fake the cluster through `local *OCP::Kubernetes::new` or
    `Kubernetes::REST::Kubeconfig`. Such a fake may now need to answer `GET /version`.
  - Adapt the fake, or add `local *OCP::Role::Cmd::reach_cluster_api = sub { $_[1] };`.
    Never change an assertion.
  - A test that injects the client through a command's `k8s`/`api` attribute is
    unaffected: that short-circuit stays in every command.
- A file that no longer builds a client drops its `use Kubernetes::REST::Kubeconfig`, and
  its `use File::Temp` when nothing else in it uses that.
- "Config file … not found" and every other ocp.yaml check stay in the commands; they are
  Part C.
- Out of scope:
  - `OCP::Cmd::InjectKey` (Net::Async::Kubernetes, not Kubernetes::REST);
  - robocop;
  - `OCP::Node`'s use of the kubeconfig text (Apply/CR.pm:1152, Node/Add.pm:401). That
    is no client build.
- Tests run only through the guarded command:
  `DOCKER_BUILDKIT=0 timeout 1800 make test TESTS="<explicit list>" IMAGE=localhost/ocp-w399`.
  Never `t/`, never an empty list.
- Mutation check: only for `cluster_api`'s modes (Task 1), at most five mutants in one
  guarded run.
- One patch per task. The release manager runs ONE full suite on the stack and commits per
  task. The id is written `k399`.

## Review focus

1. **A wrong PIN1 under optional mode** stops `destroy` and `status` in OCP::Secrets' words.
   It never becomes "the API does not answer" (k382). Task 1 pins it on `cluster_api`;
   Task 4 keeps t/382 green unchanged.
2. **A second call in one command** returns the cached client: no second build, no second
   PIN prompt. Task 1 pins it.
3. **`ocp apply` against an API that does not answer yet** gets no new fatal check.
   Task 6 pins that building apply's client sends no request.
4. **A stale endpoint.** Apply rebuilds on bootstrap's new kubeconfig; the renderer must
   name the latest server. Task 1 pins it with two connects to two servers.
5. **`destroy` with kubeconfig.yaml, no key at all and the Hetzner token set** (k396,
   from k382) goes on without the API. Today it says nothing; now it says why, once.
   Task 4 pins it.

---

### Task 1 (B1): the method, the inner function, and health, node ls and provider ls on them

**Files:**
- Modify: `lib/OCP/Role/Cmd.pm` (add `connect_cluster_api` and `cluster_api` near
  `reach_cluster_api`, with POD; the `reach_cluster_api` POD example at :752 uses
  `cluster_api`)
- Modify: `lib/OCP/ErrorLine.pm` (`set_cluster_endpoint`; `user_line` passes the endpoint)
- Modify: `lib/OCP/Cmd/Health.pm:40-58`, `lib/OCP/Cmd/Node/Ls.pm:25-52`,
  `lib/OCP/Cmd/Provider/Ls.pm:18-44`
- Test: `t/399-one-way-into-the-cluster.t` (new; later tasks add subtests)

**Interfaces:**
- Produces: `OCP::ErrorLine::set_cluster_endpoint($endpoint_or_undef) -> undef`.
  `user_line` then calls `api_error_line($err, $endpoint)` with the last value set.
  Undef means no endpoint, as in Part A.
- Produces: `$self->connect_cluster_api($kubeconfig_yaml) -> Kubernetes::REST`.
  - It does `OCP::Kubernetes->new(kubeconfig => $yaml)` and keeps that object on
    `$self->{_cluster_kubernetes}` (it holds the temp file).
  - It stores `->api` on `$self->{_cluster_api}`.
  - It calls `set_cluster_endpoint($api->server->endpoint)` when `$api->can('server')`.
    That guard keeps test fakes working, as in `cluster_api_error`.
  - It returns the api and sends no request.
- Produces: `$self->cluster_api(%opt) -> Kubernetes::REST`; with `optional => 1` in list
  context, `($api, $why)`.
  1. A cached `$self->{_cluster_api}` is returned as is.
  2. The project dir is `path($self->ocp->config)->parent`.
  3. No kubeconfig.yaml: dies with `OCP::Secrets->no_kubeconfig_refusal`, or with
     `optional` answers `(undef, undef)`.
  4. The key step (Decision 5), outside any eval.
  5. `read_kubeconfig`, `connect_cluster_api`, `reach_cluster_api`. Without `optional`
     they run bare and die as they die. With `optional` they run inside one eval; a
     failure answers `(undef, $line)`, where
     `$line = OCP::ErrorLine::user_line($@) // OCP::ErrorLine::one_line($@)`.
- Changes: health, node ls and provider ls keep their injection short-circuit and their
  config checks. Then they call `$self->cluster_api`: Health stores it with
  `$self->api(...)`, Node::Ls and Provider::Ls with `$self->k8s(...)`. Their own
  `File::Temp`, `Kubernetes::REST::Kubeconfig`, `OCP::K8s->register` and
  `reach_cluster_api` lines go; `OCP::Kubernetes` registers both.

- [ ] **Step 1: Write the failing tests.**
  - Fixture: the one t/384 builds: a project with an age key, and kubeconfig.yaml
    encrypted and pointing at a closed local port.
  - The methods are called on a command object whose `ocp->config` is the fixture's
    ocp.yaml; `OCP::Cmd::Health` will do.
  - Assert:
    - required, no kubeconfig.yaml: the error is exactly `OCP::Secrets->no_kubeconfig_refusal`;
    - required, closed port: the error matches
      `qr{\AThe cluster API at https://127\.0\.0\.1:\d+ could not be reached: .+\n\z}`;
    - optional, no kubeconfig.yaml: `(undef, undef)`;
    - optional, closed port: `(undef, $line)`, with `$line` matching the same pattern
      without the newline;
    - optional, age.key.enc with no `.ocp/age.key` and a wrong PIN1 on `--pins-stdin`
      (t/382's harness): it dies with OCP::Secrets' wrong-PIN text (Review focus 1);
    - two `cluster_api` calls build once (count `OCP::Kubernetes::new` calls) and return
      the same object (Review focus 2);
    - after `connect_cluster_api` to two kubeconfigs with different servers,
      `user_line($e599)` names the second server (Review focus 4). Reset with
      `set_cluster_endpoint(undef)` at the end of the subtest.
- [ ] **Step 2: Run them and see them fail.** Expected: "Can't locate object method
  "cluster_api"".
- [ ] **Step 3: Implement** the three functions, then move the three commands.
- [ ] **Step 4: Run them green.**
  `TESTS="t/399-one-way-into-the-cluster.t t/384-api-unreachable.t t/387-api-error-answers.t
  t/398-one-error-renderer.t t/230-health-json.t t/230-node-ls-json.t t/370-clone-read-unlocks.t
  t/375-pin1-user-errors.t t/382-destroy-wrong-pin1.t"`, plus every test the three commands'
  names grep to. Expected: PASS, with t/384, t/387 and t/398 unchanged.
- [ ] **Step 5: Mutation check, at most five mutants in one guarded run, plus an
  unmutated control.** Mutate:
  - the key step moved inside the optional eval;
  - `optional` answering `(undef, $line)` for no kubeconfig.yaml;
  - the cache check dropped;
  - `set_cluster_endpoint` not called;
  - `user_line` ignoring the endpoint.

  Each must turn a test red. Load Rex first and assert `%INC`, as the briefing says.
- [ ] **Step 6: Hand the patch over.** Subject, for example "Build the cluster client in one
  place, OCP::Role::Cmd::cluster_api, and move health, node ls and provider ls onto it
  (k399)". Changes bullet: an API error that escapes any command now names the server.

### Task 2 (B2, group 1): the node commands

**Files:**
- Modify: `lib/OCP/Cmd/Node/Add.pm:120-135`, `lib/OCP/Cmd/Node/Rm.pm:50-65`,
  `lib/OCP/Cmd/Node/TrustHost.pm:38-52`
- Test: `t/399-one-way-into-the-cluster.t`

**Interfaces:**
- Consumes: `cluster_api` (Task 1), required mode.
- Changes: each keeps its `k8s` short-circuit and its config checks, then uses
  `$self->k8s($self->cluster_api)`. Its own read, temp file and build go. New behaviour:
  the command now sends `GET /version` first, so an unreachable API is the one line
  naming the server (k389).

- [ ] **Step 1: Write the failing test: the closed-port table.** It is a list of
  `[ words, args ]`, one row per command, run through `bin/ocp` against the Task 1 fixture.
  - Rows for this task: `node add`, `node rm`, `node trust-host`, each with the minimum
    arguments that reach the API.
  - Per row assert:
    - STDERR is exactly one line matching
      `qr{\AError: The cluster API at https://127\.0\.0\.1:\d+ could not be reached: .+\n\z}`;
    - no `internal error`, no ` at \S+ line \d+`;
    - exit 1.
  - A command that cannot reach the API step without a network or a prompt is listed in
    the test with its reason, never dropped silently.
- [ ] **Step 2: Run it and see it fail.** Expected: today's raw LWP text or "internal
  error", depending on the command.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run it green**, with every test the three files grep to:
  `t/220-node-add-gpu-operator.t` and the `node add/rm/trust-host` tests (`ls t/*node*`).
  Expected: PASS, every claim unchanged.
- [ ] **Step 5: Hand the patch over.** Subject, for example "Say an unreachable cluster API
  in one line naming the server in ocp node add, node rm and node trust-host (k399)". The
  Changes bullet names the three commands.

### Task 3 (B2, group 2): provider add/rm, deploy-image, deploy-robocop, kubeconfig

**Files:**
- Modify: `lib/OCP/Cmd/Provider/Add.pm:75-92`, `lib/OCP/Cmd/Provider/Rm.pm:25-40`,
  `lib/OCP/Cmd/DeployImage.pm:445-466`, `lib/OCP/Cmd/DeployRobocop.pm:35-52`,
  `lib/OCP/Cmd/Kubeconfig.pm:98-117`
- Test: `t/399-one-way-into-the-cluster.t`

**Interfaces:**
- Consumes: `cluster_api`, `connect_cluster_api`, `reach_cluster_api`.
- Changes:
  - The first four work as in Task 2.
  - `ocp kubeconfig` still reads the admin kubeconfig itself, because it derives the
    read-only one from that text. It builds with
    `$api //= $self->reach_cluster_api($self->connect_cluster_api($admin))`, so the
    kubeconfig is not decrypted a second time.

- [ ] **Step 1: Add the five rows to the closed-port table**, with the same three
  assertions. The red run shows today's text.
- [ ] **Step 2: Run it and see it fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run it green**, with every test the five files grep to (provider, deploy and
  kubeconfig tests). Expected: PASS, every claim unchanged.
- [ ] **Step 5: Hand the patch over.** Subject, for example "Say an unreachable cluster API
  in one line naming the server in ocp provider add/rm, deploy-image, deploy-robocop and
  kubeconfig (k399)". The Changes bullet names the five.

### Task 4 (B2, group 3): destroy and the machines role on optional mode

**Files:**
- Modify: `lib/OCP/Cmd/Destroy.pm:106-153` (`_cluster_api`; its key block moved in Task 1)
- Modify: `lib/OCP/Role/Cmd/Machines.pm:168-187` (`_cluster_api`)
- Test: `t/399-one-way-into-the-cluster.t`

**Interfaces:**
- Consumes: `cluster_api(optional => 1)`.
- Changes: Destroy's `_cluster_api` keeps its `k8s` short-circuit, then:
  - `my ($api, $why) = $self->cluster_api(optional => 1)`.
  - With `$why` it says it once on STDERR. Use the words `_ocpnode_entries` uses for a
    failed list (Destroy.pm:346-352, "[!!] Could not read the OCPNodes from the cluster
    API:" and where the workers come from instead), sets `_api_down(1)`, and goes on
    without the API.
  - `_ocpnode_entries`' own message stays for a failure after the check. The robocop-stop
    warning (Destroy.pm:~767) says its error through
    `OCP::ErrorLine::user_line($err) // one_line($err)` (k396).
- Changes: Machines' `_cluster_api` keeps `return undef unless $secrets->has_kubeconfig`.
  With `$why` from optional mode it dies:
  `"ERROR: Could not read the OCPNodes from the cluster API: $why\n" . $self->_ocpnodes_unreadable`.
  That is the message `_ocpnodes` gives today, so t/96 keeps its claim.

- [ ] **Step 1: Write the failing tests.**
  - `destroy` against the closed port, with the Hetzner adapter and every machine call
    faked as t/353 does: STDERR has the reason once, naming the server; no ` at … line N.`;
    the teardown goes on.
  - `destroy` with kubeconfig.yaml, no key at all, and `HETZNER_API_TOKEN` set: the reason
    is said once (Review focus 5).
  - `keys secure` against the closed port: today's "Could not read the OCPNodes" message,
    now with the server.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them green**, with `t/353-destroy-said-lines.t t/382-destroy-wrong-pin1.t
  t/345-destroy-cp-fallback.t t/96-keys-secure.t` and every other destroy, keys and
  operator test (`ls t/*destroy* t/*keys* t/*operator*`). Expected: PASS, every claim
  unchanged.
- [ ] **Step 5: Hand the patch over.** Subject, for example "Say once why ocp destroy goes on
  without the cluster API, and name the server in keys secure and the operator commands
  (k399)". The Changes bullet names both behaviours.

### Task 5 (B2, group 4): status and ssh on optional mode, and status's raw API errors

**Files:**
- Modify: `lib/OCP/Cmd/Status.pm:86-113` (text) and `:224-245` (`_collect_json`); `:325`
  (the drift reason)
- Modify: `lib/OCP/Drift.pm:818` and `:1223` (the API errors it carps)
- Modify: `lib/OCP/Cmd/SSH.pm:383-389` (`_kubernetes`)
- Test: `t/399-one-way-into-the-cluster.t`

**Interfaces:**
- Consumes: `cluster_api(optional => 1)`, `OCP::ErrorLine::user_line`.
- Changes, `status`, text and JSON:
  - `my ($api, $why) = $self->cluster_api(optional => 1)`.
  - Without `$api` but with `$why`: the text path prints `ERROR: $why` on STDERR plus its
    kubeconfig hint and returns 1; the JSON path sets `$out->{error} = $why` and returns 1.
    These are the lines a failed `list_nodes` gives today.
  - Without `$why`: today's no-kubeconfig branch.
  - Then `my $k8s = OCP::Kubernetes->new(api => $api)` and the rest unchanged.
  - The two-line "WARNING: Cannot connect to cluster API" / "Error: …" branch (k395)
    goes. A client that cannot be built is now `$why`, said as `ERROR: $why`. A
    `list_nodes` that dies after the check with something other than an `APIError` is
    said as `ERROR: ` plus `OCP::ErrorLine::one_line($err)`.
  - **Two claims change on purpose,** and the patch header names both:
    - t/384:294 (a kubeconfig without contexts): STDERR becomes the one line
      `ERROR: <the build error>`. Its other three claims stay: no "could not be reached",
      no "internal error", and the report ends on the kubeconfig hint.
    - t/257:121 (the fake's `connection refused`): STDERR becomes
      `ERROR: connection refused\n`.
- Changes: the drift reason at Status.pm:325 and the two carps in Drift.pm say an
  `APIError` as `OCP::ErrorLine::user_line($err) // $err`, as one line, with no source
  location (k395).
- Changes: SSH's `_kubernetes` asks `cluster_api(optional => 1)`.
  - It wraps the api in `OCP::Kubernetes->new(api => $api)`.
  - With `$why` it says it once on STDERR and returns undef; the hostname path is tried,
    as today.
  - `_node_names`' quiet eval stays quiet: it is completion, not a command.

- [ ] **Step 1: Write the failing tests.**
  - `status` and `status --json` against the closed port: one line naming the server,
    exit 1, STDOUT one JSON document in the JSON case.
  - `status` with a kubeconfig.yaml the client cannot be built from: no "Cannot connect"
    and no source location.
  - `ssh <name>` against the closed port: the reason once on STDERR, then the hostname
    path, which is faked.
  - A drift probe that dies with an `APIError` during `status`: one line, no location.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them green**, with every status, drift and ssh test (`ls t/*status*
  t/*drift* t/*ssh*`). These are the files that fake `OCP::Kubernetes::new`; adapt their
  fakes per the global constraint and change no assertion. Expected: PASS.
- [ ] **Step 5: Hand the patch over.** Subject, for example "Get ocp status's and ocp ssh's
  cluster through cluster_api, and say an API error in status and drift as one line
  (k399)". The Changes bullet names what the user sees differently.

### Task 6 (B2, group 5): apply, update and drift build through the inner function; the guards

**Files:**
- Modify: `lib/OCP/Cmd/Apply/K8s.pm:40-66` (`api`: the build becomes
  `$self->connect_cluster_api($kubeconfig)`; the cache and the rebuild on a new
  kubeconfig stay)
- Modify: `lib/OCP/Cmd/Apply.pm:16`, `lib/OCP/Cmd/Apply/K8s.pm:9` (the `use` lines go),
  and the POD mentions at `Apply/K8s.pm:297`
- Test: `t/399-one-way-into-the-cluster.t`

**Interfaces:**
- Consumes: `connect_cluster_api` (Task 1). Every `$self` that `Apply::K8s::api` gets
  consumes `OCP::Role::Cmd`: Apply and Update do. If one does not, stop and report.

- [ ] **Step 1: Write the failing tests.**
  - `OCP::Cmd::Apply::K8s::api($apply, $kubeconfig)` sends no request, which Review
    focus 3 needs. Count calls on a fake `io`, or point the kubeconfig at the closed port
    and assert that it returns. After it, `user_line($e599)` names that server.
  - **The source guard:** no file under lib/ except `lib/OCP/Kubernetes.pm` contains
    `Kubernetes::REST::Kubeconfig`; robocop is in that check too. This is the spec's
    "Done when".
  - **The command guard:** every lib/OCP/Cmd file that calls `cluster_api` or
    `connect_cluster_api` is in the closed-port table, or in an exempt list with its
    reason:
    - apply and update: bootstrap flow, no check;
    - destroy, status, ssh, keys: optional mode, with their own subtests.
- [ ] **Step 2: Run them and see the guard fail** on Apply/K8s.pm and Apply.pm.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run it green**, with every apply, update and drift test that fakes
  `Kubernetes::REST::Kubeconfig` or calls `Apply::K8s::api`, found by grep. Expected: PASS,
  every claim unchanged.
- [ ] **Step 5: Hand the patch over.** Subject, for example "Build ocp apply's and ocp
  update's cluster client through connect_cluster_api, the one build left (k399)".
  Changes bullet: "none (refactor)" unless a test shows a visible change.

## Not in this plan

- **Removing `cluster_api_call` and the per-call wrappers** in node ls and provider ls.
  The renderer now names the server, so they add nothing, but removing them changes no
  behaviour. That is a cleanup card for the backlog, if the maintainer wants it.
- **k395's remaining items:**
  - `one_line` keeping every line of LWP's text;
  - the `ERROR:` label in `no_kubeconfig_refusal` and in the status and health `--json`
    STDERR lines;
  - node ls and discovery.

  They stay on k395.
- **k396's non-API items** (silent ssh skips, Hetzner search wording): they stay on k396.
- **The ocp.yaml shape checks** in front of every command: Part C (k400).
