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
kubeconfig yet *(amended 2026-10-31, see below)*.

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
  in-cluster config was automatic; it was not, in any version (k28).
- Errors are typed and testable, which is what makes ADR 0019 possible: a mock
  transport under the real client checks verb and path, which no `kubectl`
  wrapper could.

## Amendment 2026-10-31

This ADR said under `## Decision`:

> The invariant covers OCP's own process. It does not cover the distribution's
> own bundled `kubectl` invoked on a node over SSH during bootstrap
> (`share/Rexfile`), where the cluster is being brought up and OCP has no
> kubeconfig yet.

Since k327 that exemption covers no code path. The rule now has no exception:
no code path runs `kubectl`, on this machine or on a node.

When this ADR was written, the paragraph covered some twenty `kubectl` calls in
`share/Rexfile`: the API wait, the control-plane untaint, the Gateway API and
Cilium steps, and the cert-manager upgrade. It also covered an SSH fallback in
the bootstrap, then in `OCP::Cmd::Apply`. They went one at a time:

- k191 (6f5b5c1): the Cilium and Gateway API steps moved to
  `Rex::Rancher::Cilium`, which applies through Kubernetes::REST.
- k196 (72690cd): the API wait now runs from this machine through
  `Rex::Rancher::K8s::wait_for_api`, against the node's admin kubeconfig
  fetched to this machine. The untaint tasks had no caller and were dropped.
- k198 (b3af9b0): the cert-manager upgrade, the last `kubectl` in the Rexfile,
  became a server-side apply from the CLI.
- k327 (53d34eb): the SSH fallback in `OCP::Cmd::Apply::Bootstrap` was
  dropped. After the 600 s node-Ready wait it ran RKE2's `kubectl` and
  `rke2.yaml` on the node, on k3s too. It was not ported to k3s paths.

The exemption is removed, not narrowed, because its premise no longer holds
anywhere `kubectl` could be used. Since k196, the first step after the
distribution is installed fetches the node's admin kubeconfig to this machine
and waits for the API through it. Before the API answers, a `kubectl` on the
node has nothing to ask either. The k327 fallback was not covered by the
premise in the first place: it ran after OCP had saved a kubeconfig and built
its API handle, and it asked the same apiserver again as text, which is the
cost this ADR rejects. The fallback dated from February 2026, older than this
ADR, and stood beside the exemption until k327. It is an example of the first
rejected alternative above.

What still names `kubectl` is text for a human, and the decision already covers
it (`kubectl` is a tool for humans). `_cilium_upgrade_refused` in the Rexfile
(k206) prints the `kubectl -n … delete secret …` command for a stuck Helm
release. `OCP::Cmd::Apply::Health` tells the user to export the kubeconfig for
their local `kubectl`. Neither needs an exemption.

This is an amendment, not a supersession. The decision did not move: it lost
the one exception it had, and no code depends on that exception any more. The
exemption rested on a claim about bootstrap, "OCP has no kubeconfig yet", and
k196 made that claim false.

So a new `kubectl` call during bootstrap can no longer rely on this paragraph.
It comes under the first consequence above: a ticket on the library that lacks
the feature, not a shell-out. Two tests guard this for the install tasks and the
bootstrap wait: `t/196-rexfile-lib-offload.t` ("no install task runs kubectl on
the node") and `t/327-bootstrap-node-ready.t` ("no node path and no kubectl,
run or printed"). Recorded under k337.
