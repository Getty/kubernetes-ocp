# 0007. Reach Kubernetes only through Kubernetes::REST and IO::K8s

Date: 2026-08-12
Status: accepted

## Context

OCP started out shelling out to `kubectl`. That has a specific set of costs,
all of which were paid before the decision was made:

- Every answer arrives as text that has to be parsed, and every error as a
  string on stderr. There is no difference between "404" and "your kubeconfig
  is wrong" until someone writes a regex for it.
- `kubectl` is a per-architecture binary that has to be in the image and has to
  be downloaded for the right platform — one more thing that silently assumed
  amd64 (ADR 0020).
- Anything richer than a one-shot command — a port-forward, a watch, a
  subresource write — becomes a subprocess management problem.
- The kubeconfig has to be materialised as a plaintext file for the child
  process, which fights the encrypted-at-rest model of ADR 0005.

## Decision

All Kubernetes API access from OCP's own process goes through
`Kubernetes::REST` (transport, typed resource map) and `IO::K8s` (typed
objects). No code path shells out to `kubectl`.

`kubectl` stays in the Docker image, explicitly and only as a debugging tool
for humans; the Dockerfile says so at the download.

Resources are addressed by registered Kind, never by API version:
`get('OCPNode', $name, namespace => $ns)`. The first argument is fed to
`expand_class`, so an API version there does not mis-address the request — it
dies outright. `OCP::K8s->register($api)` puts the two CRDs into the resource
map so they are typed like everything else.

The invariant covers OCP's own process. It does not cover the distribution's
own bundled `kubectl` invoked on a node over SSH during bootstrap
(`share/Rexfile`), where the cluster is being brought up and OCP has no
kubeconfig yet.

### Alternatives rejected

- **Keep `kubectl` for the awkward cases** — the awkward cases are exactly the
  ones where a text interface hurts most, and one permitted fallback becomes
  the path of least resistance for the next one.
- **Work around a missing client feature locally** — see below.

## Consequences

- A feature the client lacks is a ticket on the client's repository, not a
  shell-out here. `patch_status` is the model: the `/status` subresource had no
  method, so `OCP::K8s` holds the single raw-transport escape and a ticket sits
  on the `kubernetes-rest` board (ADR 0009).
- OCP is coupled to a pinned `Kubernetes::REST`/`IO::K8s` pair, and their
  release cadence is OCP's problem. Both are Getty-authored and pinned in
  `cpanfile`.
- Behaviour that "everyone knows" from `kubectl` has to be verified against the
  client instead of assumed. The controller carried a comment claiming
  in-cluster config was automatic; it was not, in any version (karr #28).
- Errors are typed and testable, which is what makes ADR 0019 possible: a mock
  transport under the real client checks verb and path, which no `kubectl`
  wrapper could.
