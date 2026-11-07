---
name: ocp-registry
description: Use when working on OCP's two registries in ocp-system — ocp-cache and ocp-registry, manifest generation, CoreDNS patching, image reference paths. Generic registry operation: skill docker-registry.
model: sonnet
---

# Registry Architecture for OCP

## Two Registries

OCP deploys two registries in the `ocp-system` namespace:

1. **ocp-cache** (NodePort 30500) — Pull-through cache for docker.io
   - Proxies to `https://registry-1.docker.io`
   - Reduces external bandwidth, speeds up pulls
   - Storage: `/var/lib/ocp/cache` (hostPath)

2. **ocp-registry** (NodePort 30501) — Local image storage
   - Stores images pushed to it (OCP builds none in-cluster; NFD runs
     the upstream `registry.k8s.io` release image)
   - Used as `registry.local` and `ocp.internal`
   - Storage: `/var/lib/ocp/registry` (hostPath)

## containerd Mirrors (registries.yaml)

RKE2/K3s nodes are configured to use these registries via `/etc/rancher/rke2/registries.yaml`:

```yaml
mirrors:
  docker.io:
    endpoint:
      - http://localhost:30500      # ocp-cache
  registry.local:
    endpoint:
      - http://localhost:30501      # ocp-registry
  ocp.internal:
    endpoint:
      - http://localhost:30501      # ocp-registry
```

RKE2 server and agent nodes get the same registries.yaml (hash built by `_registries()` in the Rexfile, written 0600 by Rex::Rancher); K3s nodes get none.

## External Registry Override

Users can bring their own registries via ocp.yaml:

```yaml
registry:
  cache: http://external-cache:5000     # replaces ocp-cache
  upstream: http://external-reg:5000    # replaces ocp-registry
  name: my.registry                     # custom name (default: ocp.internal)
```

When external registries are configured, OCP skips deploying the corresponding built-in component.

## CoreDNS registry.local

After registry deployment, CoreDNS is patched with a `hosts` plugin entry:

```
hosts {
    <NODE_IP> registry.local
    fallthrough
}
```

This allows pods to resolve `registry.local` to the node IP where the registry NodePort is exposed.

How the record is read and written (k338, k348; ADR 0022 amendment k392). Writer
`configure_registry_dns` (`OCP::Cmd::Apply::Network`) and probe `registry_dns_drift`
(`OCP::Drift`) read the Corefile through one parser, `OCP::Corefile`:

- **Read from the block that answers.** `block_for` takes the server block CoreDNS answers
  the name from: of the blocks whose zone covers it, the most specific, the root zone
  covering every name. `address_of` reads the record there; a record in another block does
  not count. Only plain DNS on port 53 answers (`on_cluster_port`).
- **`coredns-custom` on k3s.** When the Corefile has a top-level `import` from
  `/etc/coredns/custom/` (`corefile_imports_custom`; k3s's stock Corefile does, RKE2's does
  not), both sides also read `kube-system/coredns-custom` and take its `*.server` snippets
  as server blocks. `*.override` files are not read (k3s imports them inside the root block).
- **A snippet that maps the name to the control plane counts as solved**: no drift, the
  writer does nothing. One that maps it elsewhere or has no record is `spec` drift with a
  `manual_step` that `ocp apply` does not close; the writer dies with the reason and the
  caller prints it as `[WARN]` on STDERR instead of writing a root-block record the
  snippet would shadow.
- **OCP writes only the inline record** in the Corefile's root block (merged into an
  existing `hosts` block where there is one). It never writes or maintains `coredns-custom`.

## Image References

- In-cluster (Service, port 5000): `ocp-registry.ocp-system.svc:5000/myimage:tag`
- Node-side pulls: `localhost:30501/myimage:tag`
- Config references: `registry.local/myimage:tag` or `ocp.internal/myimage:tag`

## Manifest Generation

`_generate_registry_manifest()` in Apply.pm builds:
1. Namespace (ocp-system)
2. ConfigMap for ocp-cache (proxy config)
3. Deployment + NodePort Service for ocp-cache (unless external)
4. Deployment + NodePort Service for ocp-registry (unless external)

All applied via Server-Side Apply with hash tracking in `.ocp/deployed.yaml`.
