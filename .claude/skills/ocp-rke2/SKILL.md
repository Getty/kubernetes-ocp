---
name: ocp-rke2
description: Use when OCP provisions RKE2 or K3s — the config.yaml and registries.yaml OCP generates, the Rex install flow, the Cilium handover. Generic RKE2 behaviour: skill kubernetes-rke2.
model: sonnet
---

# RKE2/K3s Configuration for OCP

## RKE2 Server Config

Location: `/etc/rancher/rke2/config.yaml`

```yaml
cni: none                    # OCP uses Cilium instead
disable-kube-proxy: true     # Cilium replaces kube-proxy via eBPF
token: <join-token>
node-name: police1
tls-san:
  - <public-ip>
disable:
  - rke2-ingress-nginx       # OCP uses Cilium Gateway API
```

Key decisions:
- `cni: none` — Cilium is installed separately after RKE2 starts
- `disable-kube-proxy: true` — Cilium's eBPF kube-proxy replacement is more efficient
- No ingress-nginx — Cilium Gateway API handles ingress

## RKE2 Agent Config

```yaml
server: https://<cp-ip>:9345
token: <join-token>
node-name: worker-1
```

## registries.yaml

Location: `/etc/rancher/rke2/registries.yaml` (same path for agents)

```yaml
mirrors:
  docker.io:
    endpoint:
      - http://localhost:30500    # ocp-cache (pull-through)
  registry.local:
    endpoint:
      - http://localhost:30501    # ocp-registry (local)
  ocp.internal:
    endpoint:
      - http://localhost:30501    # ocp-registry (alias)
```

Built as a hash by `_registries()` in the Rexfile and written (0600) by
Rex::Rancher's `install_server`/`install_agent`. RKE2 servers and agents get it;
K3s nodes get none (never did).

External registries override localhost endpoints when configured in ocp.yaml:
```yaml
registry:
  cache: http://external-cache:5000     # replaces localhost:30500
  upstream: http://external-reg:5000    # replaces localhost:30501
  name: ocp.internal                    # internal registry name
```

## Cilium Integration

1. RKE2 starts with `cni: none` (no networking)
2. Node shows NotReady until CNI is installed
3. Cilium CLI is installed on the node
4. `cilium install` with:
   - `kubeProxyReplacement=true` (replaces disabled kube-proxy)
   - `k8sServiceHost=localhost`, `k8sServicePort=6443`
   - `gatewayAPI.enabled=true`
5. Node becomes Ready once Cilium is running

## K3s Differences

- Config: `/etc/rancher/k3s/` (instead of rke2)
- Kubeconfig: `/etc/rancher/k3s/k3s.yaml`
- Binary: `kubectl` directly (not `/var/lib/rancher/rke2/bin/kubectl`)
- Install: `curl -sfL https://get.k3s.io | sh -s - server --disable=traefik --disable=servicelb`
- Agent: `K3S_URL=... K3S_TOKEN=... sh -s - agent`
- Token: `/var/lib/rancher/k3s/server/node-token`

## Installation Flow (Rex)

Since k155 the Rexfile tasks are thin wrappers around **Rex::Rancher** and
**Rex::GPU** (pinned 0.003 in cpanfile, still unreleased/vendored); what stays
in the Rexfile is OCP's own, each gap marked with the library card that would
move it.

1. `prepare_node` — since Rex::Rancher 0.003 (rex-rancher k42) this is just
   `Rex::Rancher::Node::prepare_node(hostname, domain, timezone, locale, ntp
   => $ntp)`, then `cleanup_legacy_containerd_template`. OCP hands the library
   its parameters and does nothing of the library's steps itself any more:
   the library does the apt refresh, hostname, the `/etc/hosts` entry without
   a domain (only when no line names the host already), timezone, the locale
   enabled in `/etc/locale.gen` and generated before it is set, swap off,
   `br_netfilter`/overlay, the Kubernetes sysctls, **and** NTP — a clock
   `timedatectl` already reports synchronised is left alone, otherwise
   chrony, falling back to systemd-timesyncd on a failed chrony install, and
   warning (not dying) when neither is available. `ntp` defaults on; OCP
   passes `ntp => 0` only to skip it entirely.
2. `detect_gpu` — sysfs detection (OCP's own); `install_nvidia` calls
   `Rex::GPU::NVIDIA::install_driver(gpus => ..., setup => 'Rex::GPU::NVIDIA::Setup::UbuntuDrivers')`
   on Ubuntu (since k191, rex-gpu k69), plain `install_driver(gpus => ...)`
   elsewhere; toolkit via `install_container_toolkit` unless the runtime
   binaries exist. See skill `ocp-gpu` for the Ubuntu setup's package choice.
3. `install_{rke2,k3s}_server` — `cluster_cidr` is passed straight into
   `Rex::Rancher::Server::install_server`, which writes it as config.yaml's
   own `cluster-cidr` (rex-rancher k41; both distributions). The
   `config.yaml.d/50-ocp-cluster-cidr.yaml` drop-in OCP used to write itself
   is no longer created — a leftover from before 0.003 is removed only when
   its content states exactly the `cluster_cidr` now passed (it would
   otherwise keep overriding config.yaml on every node set up before); a
   drop-in that disagrees is kept, with a message, because the cluster is
   running on what it says. `install_server` also carries config.yaml 0600,
   token reuse, Cilium-only CNI keys, the default disable list,
   `nvidia_runtime_path`, and a bounded service wait with journal (RKE2 with
   a pin uses `install_method => 'artifact'`; a running rke2 server restarts
   only when its config actually changed, rex-rancher k49) — then OCP waits
   for the API. `install_{rke2,k3s}_agent` — plain
   `Rex::Rancher::Agent::install_agent`; the join URL in a failed join's error
   is the library's own since 0.003 (rex-rancher k44), OCP adds nothing to it.
4. `install_cilium` / `upgrade_cilium` — `Rex::Rancher::Cilium` with a local
   kubeconfig fetched off the node, `gateway_api_channel => 'standard'`,
   `cluster_cidr` passed only on a fresh install (the pool of a running
   Cilium is the library's to keep), IPAM mode always stated as
   `cluster-pool`, and `wait => 1, wait_duration => 600|300` — the library's
   own readiness wait since 0.003 (rex-rancher k43), replacing OCP's `cilium
   status --wait`. `update_gateway_api` goes through the library too
   (`Rex::Rancher::Cilium::ensure_gateway_api_crds`), so there is no kubectl
   apply left in the Rexfile. See skill `ocp-cilium` for the detail.
