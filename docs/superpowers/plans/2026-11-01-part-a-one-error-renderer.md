# Part A: errors rendered in one place — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking. In this repo "subagent" means an `ocp-*`
> team agent, never a built-in one.

**Goal:** A foreign exception that reaches `OCP::run_cli` is one user line instead of
"This is an internal error". A failure of a `--json` command is one JSON error object.
Every secret the process has read is masked in whatever is printed.

**Architecture:** `OCP::ErrorLine` grows three pure pieces:
- the cluster-API wording, moved out of `OCP::Role::Cmd`;
- a secret registry;
- a translator for known foreign exception types.

`OCP::_report_error` calls them. `run_cli` tells `_report_error` whether the resolved
command runs with `--json`. No other call site changes, except that `node ls` drops its own
JSON wrapper, which becomes a duplicate.

**Tech stack:** Perl 5, Moo, MooX::Cmd / MooX::Options, Test::More, JSON::MaybeXS,
Kubernetes::REST 1.110 (`Kubernetes::REST::APIError`), Path::Tiny (`Path::Tiny::Error`).

**Spec:** `docs/superpowers/specs/2026-10-31-one-place-per-concern-design.md`, Part A.
Read it first: it holds the why, the gate, and what Parts B and C will build on top.

**Card:** k398.

## Global constraints

- No new CPAN dependencies; `cpanfile` stays unchanged.
- The `die "…\n"` convention for user errors stays. Nothing here replaces it.
- Messages that exist today keep their exact wording. In particular, `cluster_api_error`'s
  output stays byte-identical (t/384, t/387 green unchanged).
- STDOUT is the payload, STDERR the diagnosis. The JSON error object on STDOUT follows the
  k388 precedent (`node ls --json`).
- Anything that is not a known foreign type stays an internal error, as today (t/219's
  claim is kept).
- Tests run only through the guarded command:
  `DOCKER_BUILDKIT=0 timeout 1800 make test TESTS="<explicit list>" IMAGE=localhost/ocp-w398`.
  Never `t/`, never an empty list.
- Mutation checks: only for the translator and the registry (non-trivial lib/ logic), at
  most five mutants in one guarded run.
- Workers deliver one patch per task. The release manager runs ONE full suite on the
  stacked patches and commits them in order. The id is written `k398`.

## Review focus

1. **A `--json` command that already printed its own object and then dies** must not leave
   two JSON documents on STDOUT. `status` and `health` print their own object and return 1.
   Task 4 pins that STDOUT parses as exactly one document on their error paths.
2. **An empty, undef or very short secret** must not mask unrelated text, such as a "0"
   inside every number. The registry ignores values shorter than 8 characters. Task 2
   pins it.
3. **`--verbose`** still prints the raw exception with its trace, so the operator can
   debug. Secrets are masked there too. Task 3 pins both.
4. **An `APIError` with code 599 and an empty body** reads "could not be reached: unknown
   error", never an empty reason. Task 1 pins it.
5. **`--json` given to a command that has no `json` option** prints no JSON. The
   MooX::Options refusal stays as it is. Task 4 pins it.

---

### Task 1: the cluster-API wording as a pure function

**Files:**
- Modify: `lib/OCP/ErrorLine.pm` (add `api_error_line`, with POD in the file's existing style)
- Modify: `lib/OCP/Role/Cmd.pm:240-262` (`cluster_api_error` delegates)
- Test: `t/398-one-error-renderer.t` (new file; later tasks add subtests to it)

**Interfaces:**
- Produces: `OCP::ErrorLine::api_error_line($err, $endpoint) -> Str|undef`.
  - It returns undef unless `$err` is a `Kubernetes::REST::APIError`.
  - With `$endpoint` defined, the line starts "The cluster API at $endpoint"; with undef it
    starts "The cluster API".
  - The rest is `cluster_api_error`'s wording, unchanged: 599 "could not be reached: why",
    401 "refused the credentials in the kubeconfig", 403 "denied the request", 5xx
    "failed", else "answered", then "(code Reason)" and ": message".
- Produces: `OCP::Role::Cmd::cluster_api_error($self, $client, $err)` keeps its signature
  and output. It now computes the endpoint as today and returns
  `api_error_line($err, $endpoint)`.

- [ ] **Step 1: Write the failing test**

```perl
use Kubernetes::REST::APIError;
sub api_err { Kubernetes::REST::APIError->new(@_) }

subtest 'api_error_line' => sub {
    is OCP::ErrorLine::api_error_line(api_err(code => 599, body => "Connection refused\n"), undef),
        'The cluster API could not be reached: Connection refused';
    is OCP::ErrorLine::api_error_line(api_err(code => 599, body => ''), undef),
        'The cluster API could not be reached: unknown error';
    is OCP::ErrorLine::api_error_line(api_err(code => 599, body => 'refused'), 'https://h:6443'),
        'The cluster API at https://h:6443 could not be reached: refused';
    like OCP::ErrorLine::api_error_line(api_err(code => 403,
            body => '{"kind":"Status","reason":"Forbidden","message":"nodes is forbidden"}'), undef),
        qr/\AThe cluster API denied the request \(403 Forbidden\): nodes is forbidden\z/;
    is OCP::ErrorLine::api_error_line("plain string\n", undef), undef;
};
```

- [ ] **Step 2: Run it and see it fail.**
  `make test TESTS="t/398-one-error-renderer.t" …`. Expected: FAIL, "Undefined subroutine
  &OCP::ErrorLine::api_error_line".
- [ ] **Step 3: Implement.** Move the body of `cluster_api_error` (Role/Cmd.pm:240-262) into
  `api_error_line`, with `$at` built from `$endpoint`. `cluster_api_error` keeps the blessed
  check and the endpoint lookup, then calls it.
- [ ] **Step 4: Run it green, together with the existing claims.**
  `TESTS="t/398-one-error-renderer.t t/384-api-unreachable.t t/387-api-error-answers.t"`.
  Expected: PASS, with t/384 and t/387 unchanged.
- [ ] **Step 5: Hand the patch over.** The header names "(k398)" and the subject, for
  example "Word a cluster API error in OCP::ErrorLine, so one renderer can say it". The
  Changes bullet is "none (refactor)".

### Task 2: the secret registry

**Files:**
- Modify: `lib/OCP/ErrorLine.pm` (`add_secret`, `mask_secrets`, `one_line` masks the registry)
- Modify: `lib/OCP/Secrets.pm:1097` (`hetzner_token` registers what it returns)
- Modify: `lib/OCP/Provider/Hetzner.pm` (register `token` in `BUILD`)
- Modify: `lib/OCP/Hetzner/Picker.pm` (register `token` in `BUILD`)
- Test: `t/398-one-error-renderer.t`

**Interfaces:**
- Produces: `OCP::ErrorLine::add_secret($value) -> undef`. It ignores undef and values
  shorter than 8 characters, and remembers the rest for the life of the process.
- Produces: `OCP::ErrorLine::mask_secrets($text) -> Str`. Every remembered secret becomes
  `********`; undef comes back as ''.
- Changes: `OCP::ErrorLine::one_line($err, %opt)` masks the registry as well as
  `$opt{mask}`. The registry masks first, so a long token cannot be half-masked by a
  shorter one that it contains: sort by length, longest first.

- [ ] **Step 1: Write the failing test**

```perl
subtest 'secret registry' => sub {
    OCP::ErrorLine::add_secret('tok-abcdefgh-1234567890');
    OCP::ErrorLine::add_secret($_) for undef, '', '0', 'short';
    is OCP::ErrorLine::mask_secrets('GET with tok-abcdefgh-1234567890 failed'),
        'GET with ******** failed';
    is OCP::ErrorLine::mask_secrets('port 0 and a short word'), 'port 0 and a short word';
    is OCP::ErrorLine::one_line("x tok-abcdefgh-1234567890 at lib/X.pm line 3.\n"), 'x ********';
    my $p = OCP::Provider::Hetzner->new(token => 'hz-token-registered-0001');
    is OCP::ErrorLine::mask_secrets('hz-token-registered-0001'), '********';
};
```

  `OCP::Provider::Hetzner->new` needs no network. If its constructor demands more
  arguments, the test passes the minimum the class requires.
- [ ] **Step 2: Run it and see it fail.** Expected: "Undefined subroutine
  &OCP::ErrorLine::add_secret".
- [ ] **Step 3: Implement the two functions and the `one_line` change.** Then add the three
  registrations, one line each, where the token enters the object or leaves
  `hetzner_token`.
- [ ] **Step 4: Run it green.** `TESTS="t/398-one-error-renderer.t t/373-hetzner-token-masked.t
  t/383-hetzner-list-pins-stdin.t"`. Expected: PASS.
- [ ] **Step 5: Hand the patch over.** Subject, for example "Mask every Hetzner token the
  process has read in whatever OCP prints (k398)". Changes bullet: masking now covers
  every message, not only the Hetzner adapter's.

### Task 3: the translator in `_report_error`

**Files:**
- Modify: `lib/OCP/ErrorLine.pm` (`user_line`)
- Modify: `lib/OCP.pm:243-271` (`_report_error` asks `user_line` first and masks every path)
- Test: `t/398-one-error-renderer.t`

**Interfaces:**
- Consumes: `api_error_line` (Task 1), `mask_secrets` (Task 2).
- Produces: `OCP::ErrorLine::user_line($err) -> Str|undef`.
  - A `Kubernetes::REST::APIError` gives `api_error_line($err, undef)`. Part B passes the
    endpoint later; not here.
  - A `Path::Tiny::Error` gives "cannot VERB FILE: REASON", from its `{op}`, `{file}` and
    `{err}`. VERB is `read` for an op starting with `open (<`, `opendir`, `read`,
    `slurp`, `lines` or `stat`. It is `write` for `open (>`, `open (>>`, `sysopen`, `spew`,
    `append`, `mkpath`, `mkdir` or `touch`. Otherwise it is the op's first word.
  - Anything else gives undef.
- Changes: `_report_error($err, $verbose)`.
  - Without verbose: if `user_line` is defined, print "Error: <line>" with no internal
    hint; otherwise do what it does today.
  - With verbose: print the raw text as today.
  - Every printed text goes through `mask_secrets`.

- [ ] **Step 1: Write the failing test.** Capture STDERR around `OCP::_report_error`.

```perl
subtest 'foreign errors are user lines' => sub {
    my $e599 = api_err(code => 599, body => "Connection refused\n",
        _location => ' at lib/Kubernetes/REST.pm line 1546.');
    is stderr_of(sub { OCP::_report_error($e599, 0) }),
        "Error: The cluster API could not be reached: Connection refused\n";
    eval { Path::Tiny::path("$tmp/missing/file")->slurp_utf8 };
    like stderr_of(sub { OCP::_report_error($@, 0) }),
        qr{\AError: cannot read \Q$tmp\E/missing/file: No such file or directory\n\z};
    eval { Path::Tiny::path("$tmp/missing/dir/x")->spew_utf8('x') };
    like stderr_of(sub { OCP::_report_error($@, 0) }), qr{\AError: cannot write };
    eval { Carp::croak('boom') };
    like stderr_of(sub { OCP::_report_error($@, 0) }), qr/internal error/;      # t/219's claim
    like stderr_of(sub { OCP::_report_error($e599, 1) }), qr/line 1546/;        # verbose raw
    OCP::ErrorLine::add_secret('tok-abcdefgh-1234567890');
    unlike stderr_of(sub { OCP::_report_error("x tok-abcdefgh-1234567890\n", 1) }),
        qr/tok-abcdefgh/;
};
```

  `stderr_of` is a small local helper that runs the sub with STDERR opened to a scalar.
  Declare `$e599` at file scope, because Tasks 4 and 5 reuse it.
- [ ] **Step 2: Run it and see it fail.** Expected: the 599 case shows "internal error".
- [ ] **Step 3: Implement `user_line` and the `_report_error` change.**
- [ ] **Step 4: Run it green, together with the files that assert on CLI error output.**
  `TESTS="t/398-one-error-renderer.t t/23-cli-errors.t t/219-rex-task-failure-not-internal.t
  t/384-api-unreachable.t t/370-clone-read-unlocks.t t/375-pin1-user-errors.t"`.
  Expected: PASS, and every existing claim unchanged.
- [ ] **Step 5: Mutation check, at most five mutants in one guarded run.** Mutate:
  - the APIError branch of `user_line`;
  - the read/write verb rule;
  - the "no internal hint when `user_line` is defined" condition;
  - the mask call on the verbose path;
  - the 8-character floor.

  Each must turn a test red. Load the mutant lib the way the briefing says.
- [ ] **Step 6: Hand the patch over.** Subject, for example "Say an unreachable or refusing
  cluster API and a file OCP cannot read or write as one line, not as an internal error
  (k398)". The Changes bullet names the behaviour change: these errors no longer read
  "internal error".

### Task 4: the JSON error object in one place

**Files:**
- Modify: `lib/OCP.pm` (`_resolve_commands` returns the leaf class; `run_cli` computes
  `$json` and passes it on; `_report_error` prints the object)
- Modify: `lib/OCP/Cmd/Node/Ls.pm:55-71` (drop the wrapper: `execute` returns `$self->_ls`)
- Test: `t/398-one-error-renderer.t`

**Interfaces:**
- Changes: `_resolve_commands($class, $argv) -> $leaf_class`. The leaf is the last command
  class it required, or `$class` when no command word resolved.
- Changes: `run_cli`. Before resolving, it notes whether `@ARGV` holds `--json`. After
  resolving, `$json` is that, and true only when `$leaf->can('json')`. An error from
  `_resolve_commands` itself has no leaf, so `$json` is false.
- Changes: `_report_error($err, $verbose, $json)`. When `$json` is true, it first prints
  `JSON::MaybeXS->new(canonical => 1, pretty => 1)->encode({ error => $line })` on STDOUT.
  `$line` is the masked message the `Error:` line carries, without label or hint. Then it
  prints the STDERR line as before, and the exit stays 1.

- [ ] **Step 1: Write the failing test.** It drives `OCP->run_cli` with `local @ARGV` in a
  temp project dir, as t/383 does, and captures STDOUT and STDERR.
  - `node ls --json` with `OCP::Cmd::Node::Ls::_ls` locally replaced by
    `sub { die "nodes failed\n" }`: STDOUT decodes to `{ error => 'nodes failed' }`, is one
    document, and STDERR is `Error: nodes failed`.
  - The same with `_ls` dying with `$e599`: STDOUT `{ error => 'The cluster API could not be
    reached: Connection refused' }`.
  - `version --json`, a command without a json option: STDOUT has no `{`.
  - `status --json` and `health --json` on a project with no kubeconfig.yaml: STDOUT parses
    as exactly one JSON document. This is Review focus 1; use whatever error path these
    commands take today without a cluster.
- [ ] **Step 2: Run it and see it fail.** Expected: `node ls`'s case passes (its old
  wrapper), but the 599 case shows a raw line, or `version --json` misbehaves. Then remove
  the `node ls` wrapper first and see the `node ls` case fail too.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run it green.** `TESTS="t/398-one-error-renderer.t t/384-api-unreachable.t
  t/387-api-error-answers.t t/23-cli-errors.t t/339-status-pool-count.t t/230-node-ls-json.t
  t/230-status-json.t t/230-health-json.t t/258-status-json-amd-gpu.t"`. Expected: PASS.
  k388's `node ls --json` claims live in t/384 and t/387 and stay unchanged. If one of
  them asserts the raw text of an internal error (location included), stop and report;
  do not change its claim.
- [ ] **Step 5: Hand the patch over.** Subject, for example "Print a --json command's failure
  as one JSON error object, in OCP.pm instead of in node ls (k398)". Changes bullet: an
  error that escapes `status`, `health` or `node ls` under `--json` is now the JSON object
  too.

### Task 5: the sweep over the command map

**Files:**
- Test: `t/398-one-error-renderer.t` (one more subtest)

**Interfaces:**
- Consumes: Tasks 3 and 4.

- [ ] **Step 1: Write the sweep.**
  - Walk every leaf command class from `OCP::_command_map`, the way t/383 does.
  - For each class, locally replace its `execute` with `sub { die $e599 }`.
  - Fill each required MooX::Options option from the class's option metadata with a dummy
    value.
  - Run `OCP->run_cli` with the class's words, plus `--json` when `$class->can('json')`.
  - Assert:
    - STDERR is exactly one line, `Error: The cluster API could not be reached: Connection refused`;
    - no "internal error" anywhere;
    - with `--json`, STDOUT is that one object.
  - A class that dies before `execute` fails the test, naming the class: no silent skip.
- [ ] **Step 2: Run it.** Expected: PASS after Tasks 3 and 4. A failing class means a
  command catches the error itself and prints it its own way. Report it as a finding on
  the card; do not fix it here.
- [ ] **Step 3: Hand the patch over.** Test only, Changes bullet "none (test-only)".

## Not in this plan (Parts B and C)

- **The endpoint in the central line.** Part B remembers the client on the command object;
  until then the translator's line has no endpoint.
- **Removing `cluster_api_call` and the other per-site wrappers.** Each adds something the
  renderer does not have yet: the endpoint, or the adapter's mask. That mask also guards
  robocop's OCPNode status, which never passes `run_cli`.
- **Any change to `status`'s or `health`'s own JSON objects.**
