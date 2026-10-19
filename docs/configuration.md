# `ocp.yaml` reference

`ocp.yaml` is the spec: what you want the cluster to be. It lives in your
project directory, it is meant to be committed, and `ocp apply` reconciles the
real cluster towards it. Cluster *status* never goes in here — that is read
back from the cluster itself (`ocp status`).

Keys are **snake_case only**. There is no key normalisation, so a stray
`controlPlanes:` or `k8s:` is silently ignored rather than aliased. If a
setting seems to have no effect, check its spelling first.

## Annotated example

```yaml
name: mycluster                # cluster name; also the "ocp-cluster" label

kubernetes:
  dist: rke2                   # rke2 (default) or k3s
  version: ''                  # empty = OCP::Versions' pinned default,
                               # not "latest upstream"

control_planes:                # Hash (1 CP), Hash + `nodes: N` (N identical
  provider: hetzner            # CPs), or an Array of hashes (mixed).
  server_type: cx32            # rke2 deploys every entry; k3s only the first.
  location: fsn1               # No HA client endpoint yet — see "Limits" in README.
  image: debian-13

workers:                       # optional pools; each becomes Pending OCPNode
  - name: pool1                # CRs on `ocp apply` (CR-first — see below)
    provider: hetzner
    server_type: cpx21
    nodes: 3

ssh:
  private_key: .ocp/id_ed25519
  public_key: .ocp/id_ed25519.pub

robocop: true                  # optional; default false, auto-true when any
                               # control plane or worker pool uses hetzner
                               # mapping form: robocop: { image: repo:tag }
                               # pins the robocop image (default: raudssus/ocp:
                               # <version of this ocp>, see docs/robocop.md)

network:                       # optional; Cilium LB-IPAM + L2 announcement
  pod_cidr: 10.42.0.0/16       # default; cluster-cidr + Cilium pod pool, set at
                               # install only (a running cluster keeps its pool;
                               # ocp status reports a difference). Must be /23 or
                               # wider and stay clear of 10.43.0.0/16 (services),
                               # node addresses and lb_pool
  lb_pool:
    cidr: 10.0.0.240/28        # or: start / stop
  l2:
    interfaces: ['^eth[0-9]+$']  # anchored regexes; default covers eth*/en*

lbipam: false                  # optional, default false; the default LB pool
                               # takes over the host IP via ARP, breaking
                               # sshd/apiserver — opt in only with a plan

gpu:
  enabled: true                # default true; false skips GPU entirely
  driver: host                 # host (Rex installs it) | operator (GPU
                               # Operator's driver DaemonSet)
  toolkit: true                # default true: the GPU Operator runs its
                               # container toolkit, which writes the CDI
                               # specs. false (a host bringing its own
                               # toolkit, e.g. DGX/GB10): the operator runs
                               # none, and OCP writes the CDI specs on every
                               # node with a GPU (via the provider CR on
                               # workers) -- only those that do not resolve

ssl:
  email: admin@example.com     # enables Let's Encrypt issuers; omit for
                               # self-signed only (avoids ACME rate limits)

registry:
  name: ocp.internal           # local registry hostname (default)
  cache: ''                    # external docker.io pull-through cache URL
  upstream: ''                 # what the built-in cache pulls from

system:                        # detected from the host at `ocp init`; every
                               # node gets it, workers via the provider CR
  timezone: Europe/Berlin
  locale: de_DE.UTF-8
  ntp: true

nocert: false                  # true disables cert-manager entirely
```

## `workers:` is input, not state

This one surprises people, so it is worth stating plainly. On the **first**
`ocp apply`, each worker pool is translated into `OCPNodeProvider`/`OCPNode`
custom resources in the cluster. After that, `ocp.yaml`'s `workers:` section is
never read again.

From then on you manage nodes either imperatively:

```bash
ocp node add worker-1 --role worker
ocp node rm worker-1
```

…or by editing the CRs directly. The robocop controller — or the CLI fallback
when robocop is not running — reconciles them. Editing `workers:` in `ocp.yaml`
on an existing cluster changes nothing.

## Provider modes

`provider:` on a control plane or a worker pool picks how the machine comes
into existence:

| Provider | What it does |
|---|---|
| `hetzner` | Creates and destroys real Hetzner Cloud servers via the API. Idempotent, matched by label. |
| `ssh` | Uses an existing server you already have. Requires `host:`. OCP never creates or deletes this machine — it only installs and uninstalls Kubernetes on it. You put its public keys into root's `authorized_keys`: in secure mode the admin key on a control plane, the admin **and** the robo key on a worker (`ocp keys authorized-keys` prints them; see [security](security.md)). |
| `local` | Same as `ssh`, but provider operations (checks, uninstall) run directly on this machine instead of over SSH. The Kubernetes install itself still goes through Rex over SSH to `127.0.0.1`, so the admin public key must still be in this machine's `~/.ssh/authorized_keys`. |

Providers can also be registered imperatively, without touching `ocp.yaml`:

```bash
ocp provider add --name hetzner-fsn1 --type hetzner --token-file token.txt --default
ocp provider ls
```

Note that `ocp node add --provider` takes the **name** of an `OCPNodeProvider`
CR, not a provider type — `--provider ssh-default`, not `--provider ssh`.
`ocp apply` names the CRs it writes `<type>-default`, and `ocp provider ls`
lists what exists.

### A worker by hostname

`ocp node add --host NAME` with a name instead of an IP address works only if
the name also resolves **inside the cluster**. With robocop on, robocop reaches
the machine, and it looks the name up through CoreDNS and the node's resolver,
not on the machine running `ocp`. A name that resolves only on the CLI host —
through `/etc/hosts` or a container's `--add-host` — is unknown to every pod,
and the join fails.

`ocp node add` warns about this on STDERR whenever it is given a name; an IP
address gets no warning. A name that does not resolve is reported as that
(`Name 'X' does not resolve … This is not a key problem`), in the host-probe
warning, in the SSH error and in the node's `status.message` — not as a
rejected key. Use the IP address, or a DNS entry the cluster knows.

Without robocop, `ocp node add --host NAME` drives the join from the CLI and
checks the name **before it writes anything to the cluster**: first it resolves
the name on this machine, then (unless `--nowait`) it runs the usual SSH probe,
waiting as long as the join does (about 120 s). If either fails, the command
prints `Name 'X' does not resolve: the lookup failed on this machine …` or the
SSH error on STDERR and exits 1. No `OCPNode` or any other object has been
created, so there is nothing to clean up and no `node rm --keep-machine` is
needed. With `--nowait` only the resolution is checked. IP addresses are not
resolved. With robocop on nothing changes: the name can only resolve inside the
cluster, so the `OCPNode` is written as a request, the warning goes to STDERR,
and the node goes `Failed` with a message if the cluster cannot resolve it.

## Pinned versions

`kubernetes.version: ''` and every component version resolve to what this
release of OCP pins, not to whatever is newest upstream. The manifest lives in
`OCP::Versions` and covers RKE2/K3s, Cilium and its Gateway API CRD bundle,
cert-manager, and the whole GPU stack. `ocp version` prints the set in effect;
`ocp status` reports drift away from it, and `ocp update` closes the gap for
the components that can be updated in place.

## See also

- [Security model](security.md) — PIN1/PIN2 and the key layout
- [robocop](robocop.md) — the in-cluster controller that reconciles workers
- Example workloads in [`eg/`](../eg/)
