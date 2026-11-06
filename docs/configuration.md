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
                               # At most 7 either way (etcd): `nodes:` and the
                               # list both.
  location: fsn1               # No HA client endpoint yet — see "Limits" in README.
  image: debian-13

workers:                       # optional pools; each becomes Pending OCPNode
  - name: pool1                # CRs on `ocp apply` (CR-first — see below)
    provider: hetzner
    server_type: cpx22         # required on a hetzner pool: no default
    nodes: 3                   # a count; an ssh pool lists its hosts instead

ssh:
  private_key: .ocp/id_ed25519
  public_key: .ocp/id_ed25519.pub

robocop: true                  # optional; default false, auto-true when any
                               # control plane or worker pool uses hetzner
                               # true/false (or 1/0) or a mapping, never a
                               # string like no or off
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
  amd:                         # optional; absent = the defaults below. An
                               # unknown key or value is refused
    allocation: device-plugin  # device-plugin | dra | none
    resource_naming: single    # single | mixed, for the device plugin
    labeller: true             # AMD's node labeller
    metrics: false             # AMD's device-metrics-exporter
    integrated: false          # set up an integrated AMD GPU on every node

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

## The address a node registers by

A node registers by one InternalIP, the RKE2/K3s `node-ip`. `node_ip:` on a
control plane, or `ocp node add NAME --node_ip ADDRESS` for a node, sets it.
Without it, a joining node registers the address of its route to the join
server (`ip route get`), not that of its default route: every worker and
every control plane after the first. The first control plane has nothing to
join and registers its default route's address. On a host with several
networks, set `node_ip:` when that is not the address the other nodes reach
it by.

## What `ocp apply` refuses in these keys

`ocp apply` checks `ocp.yaml` first and lists every error at once on STDERR.
These shapes used to be read wrongly and are refused:

- **`robocop:`** takes only `true` or `false` (`1` and `0` too) or a mapping of
  `enabled`, `security_level` and `image`. A string like `no` or `off` is
  refused: `robocop: must be true, false or a mapping (enabled,
  security_level, image), not 'no'; write robocop: false`.
- **A worker pool's `nodes:`** depends on its provider. An `ssh` pool lists its
  hosts, each a host name or IP address or a mapping with `host`:
  `nodes: [w1.example, { host: 10.0.0.7 }]`. Every other provider counts its
  machines: `nodes: 3`, a whole number.
- **`control_planes:`** holds at most 7 control planes, as a list just as with
  `nodes: N`: every control plane is an etcd member, and etcd advises no more
  than 7.
- **The other on/off switches** take only `true` or `false` (`1` and `0` too),
  as `robocop:` does: `gpu.enabled`, `gpu.toolkit`, `gpu.amd.labeller`,
  `gpu.amd.metrics`, `gpu.amd.integrated`, `lbipam`, `nocert` and `system.ntp`.
  A string such as `no` or `off` is refused, because it used to count as true
  (`gpu: { enabled: no }` left the GPU stack on, `nocert: no` left cert-manager
  out). The line names the key and, for a string that spells a boolean, what
  was meant: `gpu.enabled: must be true or false, not 'no'; write enabled:
  false`. Any other string, a list or a mapping gets the same line without the
  hint.
- **An ssh pool names its machines with `host:` or with `nodes:`**, not with
  neither and not with both. `host:` is one machine and `nodes:` a list of
  them. With neither, the pool got no worker and nothing said so; with both,
  `nodes:` is read and `host:` is not. `nodes: []` is allowed and means the
  pool has no machines yet. The lines read `an ssh pool needs host (one
  machine) or nodes (a list of machines); with neither it gets no worker --
  nodes: [] says it has none yet` and `an ssh pool takes host (one machine) or
  nodes (a list of machines), not both; beside nodes, host is not read`. A
  `host:` that is `0` or empty names no machine, so it counts as none.
- **`host:`, `server_type:`, `location:` and `image:`** are one name each, in
  a control plane and in a worker pool: a string. A list, a mapping or a
  boolean is refused (`worker pool 'p': location must be a string (a Hetzner
  location like fsn1), not a list`) instead of becoming the name of a machine.
- **`host:` belongs to an ssh pool only.** On a `hetzner` or `local` worker
  pool it names no machine: Hetzner creates its servers at the addresses it
  hands out, and a `local` pool is the machine `ocp` runs on. It is refused
  whatever it holds (`host is read for an ssh pool only, and names no machine
  of a hetzner pool, … -- remove host`; for `local` the line adds `or name
  another machine in an ssh pool`).
- **A `hetzner` worker pool names its `server_type:`.** A worker has no
  default server type: a pool without one used to get `cx32`, which nothing in
  `ocp.yaml` said. The line is `worker pool 'pool1': server_type required for
  hetzner -- a worker pool has no default; add one, e.g. server_type: cpx22`.
  A Hetzner control plane needs `server_type:` and `location:` as before;
  `ocp init` writes both, `cpx22` and `fsn1` unless you pick others.
- **An unknown key in a control plane or a worker pool** is refused, so a
  misspelt key cannot leave its default in force. A control plane takes
  `provider`, `host`, `public_ip`, `private_ip`, `node_ip`, `server_type`,
  `location`, `image`, `name` and `service` (and `nodes` on the mapping form); a
  worker pool takes `name`, `provider`, `nodes`, `host`, `server_type`,
  `location`, `image`, `labels` and `taints`. `count:` gets a hint
  (`count is read by nothing -- how many control planes there are is nodes:
  N`), and `network_interface:`, which nothing has read since k138, is refused
  like any other unknown key.
- **An unknown key under `gpu:` or `system:`** is refused, because a
  misspelt key left its default in force (`system: { time_zone: Europe/Berlin
  }` left every node on UTC). `gpu:` takes `enabled`, `driver`, `toolkit` and
  `amd`; `system:` takes `timezone`, `locale` and `ntp`. The line is
  `system.time_zone: unknown key (must be timezone, locale, or ntp)`. A
  `system:` that is not a mapping is refused too: `system: must be a mapping
  (timezone, locale, or ntp), not 'UTC'`.
- **An unknown key under `kubernetes:` or `ssh:`, or on an ssh pool's
  machine** is refused the same way, so `ocp apply` stops on it instead of
  leaving a default in force. `kubernetes:` takes `dist` and `version`; `ssh:`
  takes `private_key` and `public_key`; a mapping in an ssh pool's `nodes:`
  list takes `host` and nothing else (`node_ip` there has a line of its own:
  set it per node with `ocp node add NAME --node_ip ADDRESS`). The line is
  `ssh.privat_key: unknown key (must be private_key or public_key)`.
  `kubernetes: { distribution: k3s }` -- the name the install tasks and
  robocop use -- was read by nothing and left the cluster on RKE2; it gets a
  hint, `kubernetes.distribution: unknown key (must be dist or version); write
  kubernetes: { dist: k3s }` (for `rke2` or `k3s` as the value).
- **`kubernetes.version:` and a control plane's `name:`** are one string each:
  a list, a mapping or a boolean is refused (`kubernetes.version: must be a
  string (a release like v1.36.4+rke2r1 or v1.36.4+k3s1; empty for the one OCP
  pins), not a list`). Empty or absent `version` still means the pinned one.
  A release of the other distribution is refused too, `v1.36.4+k3s1` under
  `dist: rke2` (or under no `dist`, which is `rke2`) and `v1.36.4+rke2r1` under
  `dist: k3s` (`kubernetes.version: 'v1.36.4+k3s1' is a release of k3s, but
  kubernetes.dist is rke2; write a release of rke2 (like v1.36.4+rke2r1), or
  set kubernetes.dist to k3s`), while a version without a suffix, such as
  `v1.31.3`, passes as before.
- **An unknown key under `network:`, `network.lb_pool`, `network.l2`,
  `cilium:` or `robocop:`** is refused, so a misspelt key cannot leave its
  default in force. `network:` takes `pod_cidr`, `lb_pool` and `l2`; `lb_pool`
  takes `cidr`, `start` and `stop`; `l2` takes `node_selector` and `interfaces`;
  `cilium:` takes `devices` and `helm_values`; `robocop:` takes `enabled`,
  `security_level` and `image`. The lines read `network.lb_pols: unknown key
  (must be pod_cidr, lb_pool, or l2)`, `network.lb_pool.cidrs: unknown key
  (must be cidr, start, or stop)`, `network.l2.interface: unknown key (must be
  node_selector or interfaces)`, `cilium.device: unknown key (must be devices
  or helm_values)` and `robocop.enable: unknown key (must be enabled,
  security_level, or image)`.
- **`kubernetes.dist:` and the two `ssh:` paths.** `dist` is `rke2` or `k3s`;
  anything else is refused (`kubernetes.dist: invalid value 'rke3' (must be
  rke2 or k3s)`) instead of installing RKE2 under that name. `ssh.private_key`
  and `ssh.public_key` are one path each: a list, a mapping or a boolean is
  refused (`ssh.private_key: must be a string (a path like .ocp/id_ed25519),
  not a list`).
- **`node_ip:` names one machine**, so it is refused wherever it would stand
  for several. On a worker pool: `worker pool 'p': node_ip cannot be set on a
  pool, one address cannot be every machine's; set it per node: ocp node add
  NAME --node_ip ADDRESS, or spec.nodeIP on its OCPNode`. On an entry of a
  pool's `nodes:` list: `worker pool 'p': nodes[1].node_ip is not read from a
  pool's nodes; set it per node: …` (same ending). On a `control_planes`
  mapping with `nodes:` above 1: `control_planes: node_ip with nodes: 3 would
  give all 3 control planes the same address; list them one by one
  (control_planes: as a list), each with its own node_ip`. A pool the line
  cannot name by its `name` is quoted as `workers[N]`.

## `gpu.amd:` — AMD GPU nodes

`gpu.amd:` shapes the AMD side of the GPU stack. The block is optional, and
every key in it too: without it the defaults below hold. A key outside the five
below, or a value outside its list, is refused by `ocp apply` (`gpu.amd.X:
unknown key …`, `gpu.amd.allocation: invalid value … (must be device-plugin,
dra, or none)`).

| Key | Values | Default | What it does |
|---|---|---|---|
| `allocation` | `device-plugin`, `dra`, `none` | `device-plugin` | How the cluster hands AMD GPUs to pods: ROCm's device plugin (`amd.com/gpu`), ROCm's DRA driver (experimental, needs Kubernetes 1.34+), or neither. A node can override it with the label `ocp.internal/amd-gpu.allocation`, which OCP never sets itself. |
| `resource_naming` | `single`, `mixed` | `single` | Handed to the device plugin as is. `single` names every GPU `amd.com/gpu`; `mixed` names partitioned resources `amd.com/<partition>`. |
| `labeller` | `true`, `false` | `true` | Runs AMD's node labeller, which adds the `amd.com/gpu.*` descriptive labels. |
| `metrics` | `true`, `false` | `false` | Runs AMD's device-metrics-exporter (`/metrics` on port 5000). Upstream supports Instinct and Radeon AI, not Ryzen APUs. |
| `integrated` | `true`, `false` | `false` | Sets up an integrated AMD GPU (the iGPU of a Ryzen CPU or APU) on every node. Without it, only a node joined with `ocp node add --gpu` gets its iGPU set up. |

`integrated` reaches every node through the `OCPNodeProvider` CR: `ocp apply`
writes it to `spec.gpu.amd.integrated`, and robocop, `ocp apply`'s worker
reconcile and `ocp node add` read it from there. The first control plane gets it
from `ocp.yaml` directly. It takes effect at a node's next install: a node that
joined through an `OCPNode` and is Ready is only verified, so it has to be
joined again. `allocation`, `resource_naming`, `labeller` and `metrics` shape
the cluster's AMD stack, not a node's install, so they do not travel through the
CR.

`gpu.enabled: false` overrides all of it: no GPU is detected or set up on any
node, whatever `integrated` says, and an AMD stack already deployed is removed.
It wins over `ocp node add --gpu` as well. The switches take only `true` or
`false` (`1` and `0` too), like the other on/off switches above.

## Provider modes

`provider:` on a control plane or a worker pool picks how the machine comes
into existence:

| Provider | What it does |
|---|---|
| `hetzner` | Creates and destroys real Hetzner Cloud servers via the API. Idempotent, matched by label. |
| `ssh` | Uses an existing server you already have. Requires `host:` (a worker pool may list `nodes:` instead). OCP never creates or deletes this machine — it only installs and uninstalls Kubernetes on it. You put its public keys into root's `authorized_keys`: in secure mode the admin key on a control plane, the admin **and** the robo key on a worker (`ocp keys authorized-keys` prints them; see [security](security.md)). |
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

A Hetzner node's server type comes from `ocp node add --server-type`, or else
from its provider's (`ocp provider add --server-type`). There is no default
beyond those two: the `hetzner-default` provider `ocp apply` writes names none,
so `ocp node add` on it needs `--server-type`. A node with neither goes
`Failed` with a line that says what to add, and no server is created for it.

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
