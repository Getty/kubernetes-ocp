# RKE2/K3s install flow, config files, uninstall

The detail behind `../SKILL.md`. Generic RKE2/K3s behaviour (paths, the
9345 join port, drop-in merge rules) belongs to skill `kubernetes-rke2`.

## Config files Rex::Rancher writes for OCP

Server, `/etc/rancher/rke2/config.yaml` (K3s: `/etc/rancher/k3s/`), mode 0600:

```yaml
cni: none                    # Cilium is installed after RKE2 starts
disable-kube-proxy: true     # Cilium's eBPF kube-proxy replacement
token: <join-token>
node-name: police1
tls-san:
  - <public-ip>              # every control-plane address, one entry each (k137)
cluster-cidr: <pod_cidr>     # fresh server only; one already set up keeps its own
node-ip: <node_ip>           # only when asked for (k254); see "node-ip" below
disable:
  - rke2-ingress-nginx       # the distribution's default list, + rke2-gateway-api-crd (k161)
```

- K3s gets `flannel-backend: none`, `disable-network-policy` and
  `disable-kube-proxy` instead (k178). Its default list disables `traefik` and
  `servicelb`.
- `node-label` entries come from the OCPNode's `spec.labels` that the kubelet
  may set itself (k211), plus the GPU step's labels.
- The labels the kubelet may not set, and the taints, are put on the Node by
  `OCP::Node` through the API.

Agent:

```yaml
server: https://<cp-ip>:9345
token: <join-token>
node-name: worker-1
node-ip: <node_ip>           # as on a server
```

`/etc/rancher/rke2/registries.yaml` is RKE2-only, on servers and agents alike.
It comes from `_registries()` and is written 0600: docker.io goes through
ocp-cache (`localhost:30500`), and `registry.local` plus the registry name go
through ocp-registry (`localhost:30501`). External endpoints from ocp.yaml
replace them. K3s nodes get no registries.yaml, and never did. Skill
`ocp-registry` has the detail.

## The flow, task by task

Since k155 every install task is a thin wrapper around Rex::Rancher and
Rex::GPU (CPAN; floors in `cpanfile`, exact versions in `cpanfile.snapshot`).

0. **Preflight, before the host is touched.** First of all the Rexfile's
   `_node_ip_opt`: a `node_ip` this Rex::Rancher cannot set dies here (see
   "node-ip" below). Then
   `Rex::Rancher::Server::preflight_server(%opts)` or
   `Rex::Rancher::Agent::preflight_agent(%opts)` (rex-rancher k78) runs with the
   options the install gets. The checks:
   - Cilium residue, the first read of the host (`check_cilium_residue`,
     rex-rancher k71): a host with Cilium's pins, its cgroup2
     mount or `cilium_host`, but no RKE2/K3s, is refused with a request to
     reboot. The old socket LB hangs every image pull (k190).
   - The version to hold and its skew, against the control plane when a
     `kubeconfig` is passed.
   - On a server, the cluster-cidr of one already set up (rex-rancher k67).

   `install_server`/`install_agent` run the same checks again first thing, so
   their log lines appear twice.
1. **`prepare_node`** is `Rex::Rancher::Node::prepare_node(hostname, domain,
   timezone, locale, ntp => $ntp)` (rex-rancher k42). OCP does none of the
   library's steps itself:
   - the apt refresh;
   - the hostname, and an `/etc/hosts` line without a domain, only when no line
     names the host already;
   - the timezone, and the locale (enabled in `/etc/locale.gen` and generated
     before it is set);
   - swap off, `br_netfilter`/overlay and the Kubernetes sysctls;
   - NTP. A clock that `timedatectl` reports synchronised is left alone.
     Otherwise chrony, falling back to systemd-timesyncd, and a warning (not a
     death) when neither is available. `ntp => 0` skips NTP entirely.
2. **GPU step** (`_maybe_detect_gpu`). `detect_gpu` is called as a function,
   because `do_task` forks and its return value never comes back. It runs
   `install_nvidia` and/or `install_amd` and returns the node labels (the AMD
   marker and gfx target). `_with_gpu_labels` appends them to `node_labels`;
   a key the spec already sets keeps the spec's value. `gpu => 0` skips it.
   Detail: skill `ocp-gpu`.
3. **`install_{rke2,k3s}_server`**, through
   `Rex::Rancher::Server::install_server`:
   - config.yaml 0600.
   - The token lives only in config.yaml, and the sealed one is reused. A
     rotated token arms "bootstrap data already found and encrypted with
     different token" (k150, k154). Empty values are passed as undef, never
     `''`.
   - `cluster_cidr` lands as config.yaml's own `cluster-cidr`, on both
     distributions (rex-rancher k41).
   - `nvidia_runtime_path => 1` and `hold_running => 1`.
   - RKE2 with a pin uses `install_method => 'artifact'` (the checksum-verified
     tarball). K3s keeps the install script.
   - The service starts `--no-block` and is waited on for at most 10 minutes,
     dying with its journal. A pinned version is verified against the
     installed binary.
   - A running rke2 server restarts only when its config.yaml(.d),
     registries.yaml or `/etc/default` file changed (rex-rancher k49).
   - Right before the start, the library removes a bare containerd
     `config.toml.tmpl` (only `imports` + `version = 2`, what OCP before k23
     wrote; any other template stays). A running service still on its output
     restarts once (rex-rancher k72). Agents get the same.
   - The old `config.yaml.d/50-ocp-cluster-cidr.yaml` drop-in is removed
     afterwards, and only when its content states exactly the `cluster_cidr`
     now passed. A drop-in that disagrees is kept, with a message, because the
     cluster runs on what it says.
   - Then `Rex::Rancher::K8s::wait_for_api` waits through the node's admin
     kubeconfig, from the machine running Rex. The library returns false on
     its 5-minute timeout, so OCP dies itself (k196).
   - The kubeconfig comes from `Rex::Rancher::Server::fetch_kubeconfig`
     (rex-rancher k73): read off the node, `server` patched to the Rex host,
     saved 0600. OCP's policy, the CA dropped for `insecure-skip-tls-verify`,
     is its `filter` (`_kubeconfig_policy`). `OCP::Rex::fetch_kubeconfig_ssh`
     applies the same after the library's pure `patch_kubeconfig_server`.
4. **`install_{rke2,k3s}_agent`**, through
   `Rex::Rancher::Agent::install_agent`:
   - server and token go only into config.yaml (0600).
   - The 10-minute bounded start dies with its journal (k185).
   - The join URL in a failed join's error is the library's (rex-rancher k44).
   - With a `kubeconfig` task param, the agent is first checked against the
     control plane's version. An agent of a newer minor is refused before the
     host is touched (k196). `ocp apply` and `ocp node add` pass the
     project's kubeconfig; robocop passes its own service account as one
     (`in_cluster_kubeconfig`, k205).
5. **`install_cilium` / `upgrade_cilium`** go through `Rex::Rancher::Cilium`
   with a kubeconfig fetched off the node:
   - `gateway_api_channel => 'standard'`;
   - `ipam_mode => 'cluster-pool'`;
   - `cluster_cidr` on a fresh install only;
   - `wait => 1, wait_duration => 600|300`.

   - The API address: on k3s OCP passes `k8s_service_host`, the join address
     (`OCP::Rex` `node_api_host`, k178), because k3s agents serve the API on
     127.0.0.1:6444 and no localhost port works on every node. RKE2 must not
     get one: the library uses 127.0.0.1:6443 there and refuses the option.

   Until Cilium runs, the nodes are NotReady. That is expected; do not restart
   the service. `update_gateway_api` is
   `Rex::Rancher::Cilium::ensure_gateway_api_crds`. No kubectl apply is left in
   the Rexfile. Detail: skill `ocp-cilium`.

## node-ip (k254)

- **The chain.** `spec.nodeIP` (`OCP::Node`) or `control_planes[0].node_ip`
  (`OCP::Cmd::Apply::Bootstrap::cp_node_ip`) → `OCP::Rex`
  `install_server`/`install_agent` (`_node_ip_param`, only when set) → the
  Rexfile's `node_ip` task param → `_node_ip_opt` → Rex::Rancher, which
  writes `node-ip` to config.yaml. Unset, nothing is passed, and a
  Rex::Rancher with node_ip support keeps the `node-ip` that config.yaml
  already holds. What values pass, and that there is no default: skill
  `ocp-usage`.
- **The library needs node_ip support (rex-rancher k100).** It is part of
  Rex::Rancher 0.005, which OCP's cpanfile requires (vendored until its CPAN
  release). The Rexfile asks for it by capability, not by version
  (`Rex::Rancher::Distribution->can('node_addresses')`). Without it the
  install dies before anything on the host is read or changed, and the
  OCPNode ends in `Failed` with that message. A library without the
  option would ignore it, and the node would join on the wrong address
  without a word.
- **The multi-homed case.** Without a node-ip, RKE2/K3s register the address
  of the default route as the InternalIP. If the default route is not on
  the cluster network, the other nodes cannot reach that address. The node
  still turns Ready, but Cilium's tunnel to it breaks. Live: synapse joined
  by 10.230.30.50 and registered 192.168.0.165.
- **Fixing a node that registered wrong** takes two restarts:
  - Re-run its install, so that config.yaml carries the node-ip and
    rke2/k3s restarts. The node keeps its old address until then.
  - Then restart the Cilium agent pod on the node by hand. Until it
    restarts, its CiliumNode keeps the old address.

  A re-run that changes the value warns from Rex::Rancher, and `OCP::Rex`
  shows that as a `[WARN]`.
- **The check at Ready.** `OCP::Node->node_ip_mismatch` holds the Node's
  InternalIPs against `status.nodeIP`, the address the install was handed,
  and its line names this fix. `ocp apply` runs the same check for police1.
  Where the warning appears: skill `ocp-usage`.

## Legacy containerd template (drift)

- `detect_legacy_containerd_template` is read-only and safe on `ocp status`.
  For each distribution whose `config.toml.tmpl` matches
  `$dist->is_bare_template_output` (decided by content, never by path), it
  prints `OCP-DRIFT-PRESENT <path>`.
- `cleanup_legacy_containerd_template` is OCP::Drift's remedy: Rex::Rancher's
  `$dist->heal_bare_containerd_template`, per distribution (rex-rancher k83).
  - It removes that template and keeps any other one.
  - It restarts a running service whose config.toml is still the template's
    output. A stopped service is not started.
  - The installs do not run it; they remove the template themselves.
- OCP keeps no template content and no path list of its own (k196).

## Uninstall (ssh/local hosts)

- `OCP::Role::Provider::ExistingHost::delete_server` runs
  `Rex::Rancher::Uninstall->uninstall_cmd` through the provider's own channel
  (`run_command`: SSH or the local shell).
- That one line runs every RKE2/K3s uninstaller on the host. It removes the
  leftovers (Cilium CLI, `/opt/cni`, `/run/k3s`), Cilium's datapath and its ip
  rules.
- It dies with `"$host: " . uninstall_failure($exit, $stderr)` when the line's
  own outcome check fails:
  - RKE2/K3s is still on PATH (k175);
  - Cilium state survived, which asks for a reboot (k190).
- `uninstall_warnings($stdout, $stderr)` go to STDERR as `"$host: <warning>"`
  and fail nothing (rex-rancher k79). Examples: no `tc`, no iptables backend,
  so that part of the datapath went unchecked.
- The line's content is the library's (rex-rancher k71). What it does on a
  host is pinned by `t/29-destroy-cleanup.t` and `t/190-cilium-leftovers.t`.
