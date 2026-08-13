# 0001. Split the ocp CLI from the robocop controller, and keep the controller opt-in

Date: 2026-08-12
Status: accepted

## Context

Bootstrapping a control plane and keeping worker nodes alive look like the same
job, but they need opposite things.

Bootstrap needs the operator's secrets: the age key, the PIN-protected admin SSH
key, the provider API token, and a kubeconfig that does not exist yet. It runs
once per cluster, from outside, against a machine that has no Kubernetes on it.
Worker reconciliation needs none of that; it needs to run continuously, react to
node loss, and reach the API server it already lives next to.

Putting both in one long-running in-cluster process would mean shipping the
admin key and the provider token into the cluster and keeping them there.
Putting both in the CLI would mean a laptop has to be online for a node to be
replaced.

The cost of a controller is not free either: it is a Deployment, an RBAC
surface, a robo-key inside the cluster, and an image that has to exist for the
node's architecture. A single-node cluster on an existing SSH host — the shape
`ocp init --provider ssh --host …` produces — has no worker to reconcile and no
provider that can create one.

## Decision

Ship two components.

- **`ocp`** (CLI, external) bootstraps control planes once: provisions or
  adopts the machine, installs RKE2/K3s and the stack, applies the CRDs,
  and deploys robocop.
- **`robocop`** (`Deployment` in `ocp-system`) reconciles worker `OCPNode`
  CRs from inside the cluster.

`robocop` is off unless asked for: `robocop: true` in `ocp.yaml`, and
`OCP::Config::robocop_enabled` turns it on automatically as soon as any control
plane or worker pool uses the `hetzner` provider — the only configuration in
which a controller can actually create a machine on its own.

When robocop is enabled but not ready within 60s, `ocp apply` falls back to
reconciling the worker CRs itself, through the same state machine (ADR 0003).

### Alternatives rejected

- **One in-cluster agent for everything** — would require the admin key and the
  provider token to live in the cluster permanently, which is exactly what the
  two-tier key model (ADR 0006) exists to avoid, and cannot bootstrap the
  cluster it would live in.
- **CLI only, no controller** — a lost worker then waits for a human with the
  project directory and the PINs.
- **robocop on by default** — costs a Deployment, an in-cluster key and an
  architecture-matched image on clusters that have nothing for it to do.

## Consequences

- Two entry points (`bin/ocp`, `bin/robocop`), two Dockerfiles, two release
  artifacts. A published image that exists only for amd64 makes robocop
  undeployable on an arm64 cluster while the CLI is unaffected (karr #10) — the
  split turns one packaging gap into a partial outage rather than a total one.
- The worker path only ever runs where robocop runs. That is why seven broken
  calls and a dead dispatch branch survived in `OCP::Node` for months
  (karr #21): nobody had provisioned a real worker (karr #29).
- `ocp apply` has to be able to do robocop's job as a fallback, so the
  reconcile logic cannot live in the controller. See ADR 0003.
- Anything the controller needs must be reachable from inside the cluster: the
  robo-key, the join token and the server URL are passed in, not read from the
  project directory.
