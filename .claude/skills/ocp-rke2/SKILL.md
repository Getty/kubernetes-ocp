---
name: ocp-rke2
description: Use when OCP provisions RKE2 or K3s — the config.yaml and registries.yaml OCP generates, the Rex install flow, the Cilium handover. Generic RKE2 behaviour: skill kubernetes-rke2.
model: sonnet
---

# RKE2/K3s for OCP

The Rexfile's install tasks are thin wrappers around **Rex::Rancher** and
**Rex::GPU** (k155). Rex::Rancher owns config.yaml, registries.yaml, the
service, the version hold and the uninstall. `share/Rexfile` keeps only OCP's
policy, and each gap names the library card that would move it. Close generic
gaps in the libraries, not in the Rexfile (k196).

A hand-run of a task (`rex -f share/Rexfile ...`) needs OCP's `lib/` for the
Rexfile's `use OCP::BooleanEq` (k316): rex looks in `<cwd>/lib`, so from the
checkout root it is found; from anywhere else set `PERL5LIB=<checkout>/lib`.
`OCP::Rex` sets that itself on its runs.

Read `references/install-flow.md` before you change an install task. It holds
the config.yaml and registries.yaml OCP gets, the task-by-task flow
(preflight, `prepare_node`, GPU step, server/agent install, API wait,
kubeconfig, Cilium), the node-ip, the legacy containerd-template drift, and
the ssh/local uninstall.

## What OCP asks of every node

- **Cilium is the only CNI.**
  - RKE2 gets `cni: none` and `disable-kube-proxy: true`. K3s gets
    `flannel-backend: none`, `disable-network-policy` and `disable-kube-proxy`.
  - The bundled ingress is off through the distribution's default `disable`
    list. On RKE2, OCP adds the `rke2-gateway-api-crd` chart to that list
    (k161), because OCP owns the Gateway API CRDs (skill `ocp-cilium`).
- **registries.yaml goes to RKE2 servers and agents only**, from
  `_registries()`. K3s gets none. The mirrors are in skill `ocp-registry`.
- **OCP installs a distribution; it never upgrades one.** Every install passes
  `hold_running => 1` (rex-rancher k77, k193).
  - A running node keeps the version it runs, and a stopped one its binary's.
    Only an empty host gets the pin.
  - A pin that loses warns on every run.
  - Distribution upgrades stay manual, node by node. OCP::Drift reports them.
- **Check before you change.** `preflight_server`/`preflight_agent` run with
  the install's own options before `prepare_node`, so a refused host stays
  untouched (Cilium residue → reboot, or `--clean_cilium_residue` on the CLI
  paths `ocp apply`/`ocp node add`, not robocop; version skew, cluster-cidr).
  The install asks the residue check itself first, so the refusal can name the
  switch.
- **A join without `node_ip` derives it from the route** to the join server
  (`node_ip_from_route`) when Rex::Rancher can; else a `[WARN]`. An explicit
  `node_ip` wins; the first server derives nothing.
- **`cluster_cidr` belongs to a fresh server only.** A server already set up
  keeps its own, with a `[WARN]`.
- **The token lives only in config.yaml (0600).** The sealed token is reused,
  never put on a command line, never rotated. Pass empty values as undef,
  never `''`.
- **No kubectl on the node.**
  - The API wait is `Rex::Rancher::K8s::wait_for_api`. It returns false, so OCP
    dies itself.
  - The kubeconfig comes from `Rex::Rancher::Server::fetch_kubeconfig`, with
    OCP's `_kubeconfig_policy` as its filter.
  - The Cilium tasks also run from the machine running Rex, through
    Kubernetes::REST.
- **GPU labels join at registration.** The GPU step runs after preflight and
  `prepare_node`, called as a function: `do_task` forks and loses the return
  value. Its labels (AMD marker, gfx target) go into `node_labels`, which
  Rex::Rancher writes as `node-label`. Skill `ocp-gpu` has the detail.
- **No containerd template of OCP's.** The library removes a bare pre-k23
  `config.toml.tmpl`. OCP keeps neither template content nor a path list.
- **An agent is checked against the control plane's version** when a
  `kubeconfig` param comes. `ocp apply`/`ocp node add` pass the project's;
  robocop passes its service account's (k205).
- **The Cilium handover.** Nodes stay NotReady until `install_cilium` runs,
  and that is expected. On k3s, `k8s_service_host` is the join address
  (`node_api_host`, k178). RKE2 must not get one: the library uses
  127.0.0.1:6443 there.
- **With a pin, RKE2 installs from the checksum-verified tarball**
  (`install_method => 'artifact'`). K3s keeps the install script.
