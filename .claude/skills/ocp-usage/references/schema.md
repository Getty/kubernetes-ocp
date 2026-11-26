# ocp.yaml Schema

Read when: writing or validating ocp.yaml.

## ocp.yaml Schema — snake_case, no aliases

There is NO key normalization (plain `YAML::XS::LoadFile`) and NO camelCase
aliases: `controlPlanes:`/`cps:`/`k8s:` are **not** read. Canonical keys:

```yaml
name: mycluster
kubernetes:
  dist: rke2                # or k3s
  version: ''               # empty = fall back to the OCP::Versions manifest
                            # (NOT "latest upstream")
control_planes:             # Hash, Hash + "nodes: N", or Array of hashes
  provider: hetzner
  server_type: cx32
  location: fsn1
  image: debian-13
  # host / private_ip / public_ip / name (pinned after apply);
  # `nodes: N` on the mapping form only. Any other key is
  # refused (k347), `count:`, `service:` and `network_interface:` included
  node_ip: 10.0.0.5         # optional; a join takes its route's address; see "node_ip" below
workers:                    # optional pools; apply turns each entry into
  - name: pool1             # Pending OCPNode CRs (CR-first), reconciled by
    provider: hetzner       # robocop or the CLI fallback
    server_type: cpx22      # required on a hetzner pool (k308): no default
    nodes: 3                # a count, at most 10; an ssh pool lists hosts
                            # (strings or {host: …}) instead, see "Shapes" below
    labels:                 # optional, onto each Node (OCPNode spec.labels)
      ai.citilan.de/node-class: general
    taints: ["dedicated=ml:NoSchedule"]   # optional, kubectl syntax
                            # apply pulls changes onto existing workers;
                            # removes only what the pool set (ocp.internal/pool-*)
ssh:
  private_key: .ocp/id_ed25519
  public_key: .ocp/id_ed25519.pub
robocop: true               # default false; auto-true when a hetzner
                            # provider is configured. true/false (or 1/0) or
                            # a mapping {enabled, security_level, image};
                            # a string like no/off is refused
lbipam: true                # opt-in LB-IPAM + L2 announcements (ARP takeover
                            # on the node network — know what you're doing)
network:                    # optional; see "network" below
  pod_cidr: 10.42.0.0/16    # cluster-cidr + Cilium pool, install time only
  lb_pool:                  # LB-IPAM pool, read only with lbipam: true
    cidr: 10.0.0.240/28     # or start: + stop:, never both
  l2:                       # L2 announcement policy, lbipam: true only
    interfaces: ['^eth[0-9]+$']   # replaces the default regexes
    node_selector:          # only these nodes announce
      ai.citilan.de/l2-announce: "true"
cilium:                     # optional Cilium Helm values, install + upgrade
  devices: [enP7s7.30]      # Helm `devices` (keep Cilium off fabric NICs)
  helm_values: {}           # anything else; not ipam (OCP's)
nocert: false               # skip cert-manager stack
registry:
  cache: ''                 # external docker.io pull-through cache
  upstream: ''              # external local registry
  name: ocp.internal        # internal registry name (default)
ssl:
  email: admin@example.com  # ACME/Let's Encrypt (cert-issuers)
system:
  timezone: Europe/Berlin   # detected from host at init
  locale: de_DE.UTF-8
  ntp: true
gpu:
  enabled: true             # default true; false skips hardware detection
                            # and the GPU Operator entirely
  driver: host              # host (Rex installs the driver) or operator
                            # (the operator's driver DaemonSet)
  toolkit: true             # default true; NVIDIA container toolkit via the
                            # operator — set false on hosts that already
                            # have it (e.g. DGX vendor images)
  amd:                      # optional; absent = these defaults. An unknown
                            # key or value is a validate error
    allocation: device-plugin  # device-plugin | dra | none
    resource_naming: single    # single | mixed, for the device plugin
    labeller: true             # AMD's node labeller
    metrics: false             # device-metrics-exporter
    integrated: false          # iGPU/APU on every node
```

### node_ip — the address a node registers by (k254)

`control_planes[].node_ip`, and `ocp node add --node-ip` (the OCPNode's
`spec.nodeIP`), set the InternalIP a node registers by. That is the RKE2/K3s
`node-ip`.

- **The value** is one IP, or `v4,v6` (one address per family), with no
  whitespace. A hostname, a CIDR, loopback or link-local is refused before
  anything is ordered or installed. `ocp node add`, ocp.yaml and a
  hand-written `spec.nodeIP` refuse a value in the same words
  (`OCP::Choices::node_ip_error`).
- **Explicit wins; a join derives one.** An explicit node_ip is used as
  given. Without it, a join (every worker, every control plane after the
  first) registers the address of its route to the join server (`ip route
  get`, Rex::Rancher's `node_ip_from_route`), not its default route's. The
  first control plane derives nothing and registers its default route's
  address, which on a multi-homed host can be the wrong one. With a
  Rex::Rancher that cannot derive it, the join goes on with a `[WARN]`.
  Skill `ocp-rke2` (`references/install-flow.md`) has why and how to fix it.
- **It names one machine.** It is refused:
  - on a `workers:` pool and on the entries of its `nodes:` list (set it per
    node with `ocp node add` instead);
  - on a `control_planes:` mapping with `nodes:` above 1 (list the control
    planes one by one instead);
  - when two control planes share an address.
- **It needs a Rex::Rancher with node_ip support** (rex-rancher k100). That is
  part of Rex::Rancher 0.005, which OCP's cpanfile requires (vendored until its
  CPAN release). With an older one, the install of a node with a
  node_ip dies with the reason before its host is touched, and its OCPNode
  ends in `Failed`. Nodes without a node_ip install as before.
- **It needs an OCPNode CRD that stores `spec.nodeIP`** (k290). An older
  ocp's CRD drops the field without an error, so `ocp node add --node-ip`
  reads the CRD first and refuses (STDERR, exit 1, nothing written, before
  the SSH probe and PIN2) until `ocp apply` has updated it.
- **Registered elsewhere anyway?** Once the node is Ready, `ocp apply` or
  `ocp node add` prints one `[WARN]` on STDERR that names the fix. The same
  note stays in the OCPNode's `status.message`, whoever did the join. It is
  never fatal.

### network — pod CIDR, LB-IPAM pool, L2 announcements (k182, k127, k210)

- **`pod_cidr`** (k182) is one value for two things: the RKE2/K3s
  `cluster-cidr` and Cilium's cluster pool. Unset, it is
  `$OCP::Config::DEFAULT_POD_CIDR`, the built-in cluster-cidr of both
  distributions (Cilium's own default overlaps most host LANs).
  - **Install time only.** A fresh server and a fresh Cilium take it; a
    running cluster keeps its pool. `OCP::Drift` reports a difference,
    report-only: state the running pool in ocp.yaml, or rebuild.
  - A control plane joining as another RKE2 server repeats it (k184);
    robocop gets it as `OCP_POD_CIDR`.
- **`lb_pool`** (k127) is the `CiliumLoadBalancerIPPool` block: `cidr`, or
  `start` + `stop`, never both, IPv4 only. Read only under `lbipam: true`.
  Unset, the pool is the node IP as a `/32`, on a single-node cluster only.
  On a multi-node cluster the LB-IPAM step refuses ("set network.lb_pool"),
  and `ocp apply` prints that as `[!!] LB-IPAM setup failed` on STDERR and
  carries on; LB-IPAM is a failed component, so the run ends
  `APPLY INCOMPLETE`, exit 1 (k278).
- **`l2`** (k127) shapes the `CiliumL2AnnouncementPolicy`, also only under
  `lbipam: true`.
  - `interfaces` (Go/RE2 regexes) replaces
    `$OCP::Config::DEFAULT_L2_INTERFACES` (k210): `eth*` and `en*`, VLAN
    suffix allowed, minus switchdev `…np<N>` fabric ports.
  - `node_selector` (label → value) becomes the policy's
    `nodeSelector.matchLabels`, so only those nodes announce.
- **The checks** live in `OCP::Config::validate`.
  - `pod_cidr`, the default too: an IPv4 CIDR, no host bits, a prefix
    shorter than /24 (Cilium gives every node a /24), clear of the service
    network `$OCP::Config::SERVICE_CIDR`, the node addresses ocp.yaml names
    and `lb_pool`.
  - `lb_pool`: its shape and IPv4 addresses, and `start` not after `stop`
    (compared as addresses; equal is a pool of one, k292). `l2.node_selector`:
    a non-empty mapping of scalars. `l2.interfaces`: a non-empty list of
    strings.
  - An unknown key is refused under `network:`, `network.lb_pool` and
    `network.l2`, as under `cilium:` and `gpu.amd:` (k292): a misspelt key
    would leave its default in force.
  - **The service network** `$OCP::Config::SERVICE_CIDR` (10.43.0.0/16, the
    built-in service-cidr of RKE2 and K3s) is held against the same
    addresses as the pod CIDR (k299): control-plane `host`, `public_ip`,
    `private_ip` and `node_ip`, worker pool hosts, and `network.lb_pool`.
    One inside it is refused, whatever `pod_cidr` is; ocp.yaml has no key
    to move the service network, so the line says to use an address
    outside it.
  - **Shapes name their key** (k296, k305). A wrong shape gets one line
    naming it, not a Perl error: `control_planes`, `workers` and their
    entries, `network`, `cilium`, `gpu`, `gpu.amd`. `gpu: false` is refused
    with the hint `gpu: { enabled: false }`. A list as `name:` is refused, as
    is `control_planes: []`.
  - **`robocop:`** (k315) takes only true/false (or 1/0) or a mapping of
    `enabled`, `security_level` and `image`; `enabled` takes true/false too.
    A string like `no` or `off` is refused, with the hint `write robocop:
    false`: `robocop: must be true, false or a mapping (enabled,
    security_level, image), not 'no'`. A key outside the three is refused.
  - **A pool's `nodes:`** (k315) hangs on its provider. An `ssh` pool lists its
    hosts (strings, or mappings with `host`); every other provider counts its
    machines (`nodes: 3`, a whole number). Wrong: "nodes must be a list of
    hosts for an ssh pool" / "nodes must be a whole number".
  - **At most 10 machines in a counted pool** (k325,
    `$OCP::Config::MAX_WORKER_POOL_NODES`): every provider but ssh; an ssh
    pool's list is not counted. The maintainer's limit for now (decision
    2026-11-06), not an etcd or Hetzner one, raised when someone needs more.
    Wrong: "nodes must be at most 10, not '11'; 10 machines is OCP's limit for
    a pool for now (see docs/configuration.md)". At `workers[N].nodes`, so
    status, `keys operator add|rm`, `keys secure --drop-bootstrap` and
    `node ls --json` refuse it too (their `spec_paths`), before
    `worker_ocpnodes` could take a huge count; destroy does not read it.
  - **The other switches** (k320): `gpu.enabled`, `gpu.toolkit`,
    `gpu.amd.labeller`, `gpu.amd.metrics`, `gpu.amd.integrated`, `lbipam`,
    `nocert` and `system.ntp` take only true/false (or 1/0), as `robocop:`
    does (`OCP::Config::_is_switch`). A string such as `no` is refused:
    `gpu.enabled: must be true or false, not 'no'; write enabled: false`
    (`_switch_error`; the hint, `_boolean_hint`, names the last key segment and
    appears only for a string that spells a boolean). The accessors
    (`gpu_enabled`, `lbipam`, `no_cert`, `ntp_enabled`, …) croak with the same
    line, since `ocp update`, `ocp node add` and `ocp status`' drift check read
    them without `validate`.
  - **An ssh pool's machines** (k322, `_ssh_pool_machines_errors`): `host`
    (one) or `nodes` (a list), not neither and not both. `nodes: []` passes and
    means "no machines yet"; a `host` Perl calls false (`0`, empty) counts as
    none. `host`, `server_type`, `location` and `image` must be strings, in a
    control plane and in a pool (`_not_a_string`).
  - **A hetzner pool's `server_type`** (k308, `_worker_lines`): required, a
    worker has no default type: `worker pool 'pool1': server_type required
    for hetzner -- a worker pool has no default; add one, e.g. server_type:
    cpx22` (the example is `%HETZNER_DEFAULTS{server_type}`). Untagged, like
    the control plane's `server_type required for hetzner`, so `spec_errors`
    (destroy, status, node ls) does not stop on it. A pool's type reaches
    each OCPNode's `spec.serverType` (`worker_ocpnodes`); the provider CR
    apply writes carries none, so this line is what keeps a pool from
    `create_server`'s refusal.
  - **Unknown keys under `gpu:` and `system:`, a `system:` that is no
    mapping, and `host:` on a hetzner or local pool** (k331). `gpu:` takes
    `enabled`, `driver`, `toolkit`, `amd`; `system:` takes `timezone`,
    `locale`, `ntp` (`_unknown_keys`, `_system_errors`; `gpu_config` and
    `system_config` croak on the same lines). `host:` is read for an ssh pool
    only (`_pool_host_error`, `_pool_takes_host`): beside any other known
    provider it is refused whatever it holds, and a pool that takes none adds
    no host to the service-network/pod-CIDR address checks.
  - **Unknown keys under `kubernetes:` and `ssh:`, and on an ssh pool's
    machine** (k355). `kubernetes:` takes `dist`, `version`; `ssh:` takes
    `private_key`, `public_key`; a mapping in an ssh pool's `nodes:` takes
    `host` only (`node_ip` there has its own line). validate refuses the rest
    (`_entry_unknown_keys`, `_kubernetes_unknown_keys`), so `ocp apply` stops;
    `kubernetes.distribution: k3s` (the Rex/robocop spelling) gets the hint
    `write kubernetes: { dist: k3s }`, only when the value is rke2 or k3s.
    `kubernetes.version` and a control plane's `name` must be strings
    (`_version_error`, `_not_a_string`); `kubernetes()` and `version()` croak
    on the same lines. A `kubernetes.version` ending in the other
    distribution's suffix (`+k3sN` under `dist: rke2` or no dist, `+rke2rN`
    under `dist: k3s`; `%RELEASE_SUFFIX`, `_release_error`) is refused at the
    path `kubernetes` and by `version()`, and one without a suffix passes.
    The unknown keys of `ssh:` and of a pool machine are validate's alone
    (`ssh_config()` and `ocp destroy` do not refuse on them).
  - **`cilium:`** (k210, k292) takes `devices` (a non-empty list of interface
    names; the short form of `helm_values.devices`) and `helm_values` (a
    mapping of Helm values, deep-merged over what Rex::Rancher::Cilium
    generates). Setting `devices` and `helm_values.devices` both is refused, as
    is a `cilium:` that is no mapping and a key outside the two:
    `cilium.device: unknown key (must be devices or helm_values)`
    (`_validate_cilium`).
  - **At most 7 control planes** (`$OCP::Config::MAX_CONTROL_PLANE_NODES`):
    `control_planes.nodes` must be a whole number from 1 to 7, and the list
    form holds at most 7 entries ("must list at most 7 control planes"),
    since every control plane is an etcd member and etcd advises no more.
    An even count (2, 4, 6) is no refusal but a `[WARN]` (k325,
    `even_control_planes_warning`, rke2 only -- k3s deploys only the first):
    `ocp apply` prints it on STDERR next to the robocop arch warning and
    counts it in `{_apply_warnings}`, so the banner reads WITH WARNINGS.
  - **`ocp apply` and `ocp apply --dry-run` call `validate` first** (k255),
    before a PIN, a file, a host or the cluster: every error at once on
    STDERR, one line each, then exit 1 with nothing done. `ocp status` does
    not gate on it: it has to show a cluster whose ocp.yaml has a mistake.

### gpu.amd — AMD GPU nodes (k249–k252)

- **Labels OCP sets.** When the host step accepts an AMD GPU, the node
  registers with `ocp.internal/amd-gpu.present=true`, the marker the AMD
  stack selects on. It also gets `ocp.internal/amd-gpu.gfx-target=<gfx>`
  once the driver reports one.
- **The per-node override.** `ocp.internal/amd-gpu.allocation`, with the
  same values as `gpu.amd.allocation`, overrides the default for that node.
  Set it with `ocp node add --label`. OCP itself never sets it.
- **Integrated GPUs** (a Ryzen iGPU or APU) are set up on a node joined with
  `ocp node add --gpu`, or on every node with `gpu.amd.integrated: true`
  (k253). Like `gpu.toolkit`, it is set at a node's install (k359).
  - The first control plane gets it in the apply that builds the cluster.
  - A joined worker takes a change only when it is joined again:
    `ocp node rm NAME`, then `ocp apply` or `ocp node add NAME` with its
    flags.
  - A control plane never takes a change.

  `ocp apply` warns about such a change on STDERR. `ocp status` lists both
  values in its Spec section.
- **The rest** (components, affinity, readiness, status, the full label
  table) is in skill `ocp-gpu` (`references/amd.md`).
