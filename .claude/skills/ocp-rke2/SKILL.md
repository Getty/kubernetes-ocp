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
**Rex::GPU** (pinned 0.002 in cpanfile); what stays in the Rexfile is OCP's own,
each gap marked with the library card that would move it.

1. `prepare_node` — `Rex::Rancher::Node::prepare_node` (apt refresh, hostname,
   timezone, locale, swap, modules, sysctl) with `ntp => 0`; OCP adds NTP
   (skip when synced, chrony failure not fatal), `/etc/hosts` without a domain
   and `locale-gen` (rex-rancher k42), then `cleanup_legacy_containerd_template`.
2. `detect_gpu` — sysfs detection (OCP's own); `install_nvidia` calls
   `Rex::GPU::NVIDIA::install_driver(gpus => ...)`, except on Ubuntu, which keeps
   `ubuntu-drivers install` (rex-gpu k69); toolkit via `install_container_toolkit`
   unless the runtime binaries exist.
3. `install_{rke2,k3s}_server` — writes `config.yaml.d/50-ocp-cluster-cidr.yaml`
   (pod_cidr; rex-rancher k41), then `Rex::Rancher::Server::install_server`
   (config.yaml 0600, token reuse, Cilium-only CNI keys, default disable list,
   `nvidia_runtime_path`, bounded service wait with journal; RKE2 with a pin
   uses `install_method => 'artifact'`), then OCP waits for the API.
   `install_{rke2,k3s}_agent` — `Rex::Rancher::Agent::install_agent`; OCP adds
   the join URL to a failure (rex-rancher k44).
4. `install_cilium` / `upgrade_cilium` — `Rex::Rancher::Cilium` with a local
   kubeconfig fetched off the node, `gateway_api_channel => 'standard'`, IPAM
   mode + pool always stated (live values on a running Cilium, rex-rancher
   k43), then OCP's `cilium status --wait`. `update_gateway_api` stays OCP's
   kubectl server-side apply (rex-rancher k43).
