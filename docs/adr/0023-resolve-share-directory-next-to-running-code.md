# 0023. Resolve the share directory next to the running code, and reject overrides that do not point at a directory

Date: 2026-08-14
Status: accepted

## Context

`share/` is where nearly all of the bootstrap lives — the Rexfile is over a
thousand lines of it, alongside the CRD bundles for NFD, the GPU operator and
robocop. Three modules used to look for it on their own, all with the same
hardcoded `/opt/ocp/src/share` in first position.

The way OCP is tested in development is

```
docker run -v $REPO:/src:ro --entrypoint perl IMAGE -I/src/lib /src/bin/ocp
```

where `-I` redirects `lib/` and nothing redirects `share/`. Inside the
container the image copy therefore won every time — even when the caller had
mounted a working tree and put its `lib/` on `@INC`. The mounted tree supplied
the modules while the image supplied the Rexfile. For most runs that only meant
that "works here" and "would work from the image" stayed untested apart; on one
run it meant `install_rke2_server` silently fetched `rke2.linux-amd64.tar.gz`
against an aarch64 host, because the arm64 fix was in the tree and the February
image was older than the fix. No error pointed at the mismatch — the run simply
lacked the "[arch]" line the fixed Rexfile prints.

A second, quieter failure mode came from `-d` alone: the three modules all
adopted *any* `share/` that happened to sit in the right place, including an
empty one in a debugging checkout. An empty share shadows a real one without
the user doing anything wrong.

A third failure mode belongs to a different surface. `OCP_SHARE_DIR` is the
documented override for everything — but only as long as the operator trusts
it. A typo there has to fail loudly, or it silently reintroduces exactly the
ambiguity the override exists to remove.

## Decision

There is one resolver, `OCP::Share`, with one ordering and one override rule.

The search order, with no override in play, is:

1. The `share/` next to the script that is running — first `FindBin::RealBin`,
   then `FindBin::Bin`, so a symlink into the distribution resolves to the
   distribution.
2. The image path: `$OCP::Share::IMAGE_DIR` (currently `/opt/ocp/src/share`).
   Inside the image, step 1 already points at the same directory; this step
   survives a script started from outside the distribution's own tree.
3. `File::ShareDir::dist_dir('OCP')` — the installed-from-CPAN layout.

A directory is only a share directory if it carries the `Rexfile` marker.
`-d` alone is not enough; an empty `share/` is ignored, and the search
continues.

`OCP_SHARE_DIR` bypasses the search entirely. It is checked first, before any
candidate is collected, and it dies if it is not a directory. There is no
fall-through to step 1, 2 or 3 on a wrong override: a deliberate override is
either right or it is a mistake, and a fall-through would make the mistake
look like success.

### Alternatives rejected

- **`/opt/ocp/src/share` first** — the original order, which made the image
  shadow every mounted tree that did not also override the share. The exact
  bug the reordering exists to prevent.
- **First directory that exists** — adopts an empty `share/`, hides real
  ones behind it, leaves no diagnostic. The marker check is the cost.
- **Default `$ENV{OCP_SHARE_DIR}` to `/opt/ocp/src/share` when unset** — turns
  the override into the rule, and quietly papers over the same image-wins case
  whenever the env is empty.
- **Fall through on a bad `OCP_SHARE_DIR`** — a deliberate override that does
  not exist is almost always a typo (`OCP_SHARE_DTI`), a stale reference to a
  removed checkout, or a misplaced container bind mount. Silently using the
  default in any of those cases turns the operator's intent into the wrong
  Rexfile.

## Consequences

- The Rexfile that runs is the one next to the code that runs. A developer who
  runs `perl -Ilib bin/ocp` against a checkout gets that checkout's Rexfile;
  `docker run ocp ...` still gets the image Rexfile because that is what
  `RealBin` resolves to inside the image.
- An operator who points `OCP_SHARE_DIR` at the wrong path gets a fast, loud
  `OCP share directory not found` with the list of tried candidates. They know
  the override is the cause, not a transient mount failure.
- `t/46-share-dir.t` exercises the working-tree-wins, marker-required and
  empty-share-ignored cases. Three of the subtests are not Asserting "OCP_SHARE_DIR
  die-loud" — that is left as a built-in behaviour, not a test, because the test
  would have to construct a deliberately-wrong override to exercise it and the
  die is more useful as a runtime guarantee than as a documentation line.
- `OCP::Share::IMAGE_DIR` is a package variable so a test can rebind it without
  monkey-patching the module — the test suite relies on this.
- A new share directory that is not next to a `bin/` script has no
  `RealBin`-relative resolution. Such a layout is not supported; the file and
  the resolver agree on that.
