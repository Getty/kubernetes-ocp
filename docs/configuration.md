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
  toolkit: true                # default true; NVIDIA container toolkit

ssl:
  email: admin@example.com     # enables Let's Encrypt issuers; omit for
                               # self-signed only (avoids ACME rate limits)

registry:
  name: ocp.internal           # local registry hostname (default)
  cache: ''                    # external docker.io pull-through cache URL
  upstream: ''                 # what the built-in cache pulls from

system:                        # detected from the host at `ocp init`
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
| `ssh` | Uses an existing server you already have. Requires `host:`. OCP never creates or deletes this machine — it only installs and uninstalls Kubernetes on it. |
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
