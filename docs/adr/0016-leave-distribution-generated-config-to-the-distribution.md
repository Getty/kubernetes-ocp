# 0016. Leave distribution-generated config to the distribution; merge, never replace

Date: 2026-08-12
Status: accepted

## Context

RKE2 and k3s generate configuration that OCP also wants to influence. Two cases
hit at once on the same machine, and both had the same shape: OCP writing its
own version of something the distribution generates.

**CoreDNS.** OCP added a `hosts` block to the Corefile so that `registry.local`
resolves. k3s already ships a Corefile with a `hosts /etc/coredns/NodeHosts`
plugin. CoreDNS allows the plugin once per server block, so cluster DNS died:
`plugin/hosts: this plugin can only be used once per Server Block`, CoreDNS in
CrashLoopBackOff (karr #15). RKE2's Corefile has no `NodeHosts` block, so the
bug was invisible on the distribution the smoke test used.

**containerd.** OCP wrote `config.toml.tmpl` to configure the NVIDIA runtime.
The path was RKE2's, hardcoded, so on k3s it wrote nothing and the function was
a silent no-op; the machine worked only because k3s finds the runtime itself.
The larger finding was in the template: it had no `{{ template "base" . }}`.
k3s and RKE2 render a template *instead of* their generated config, so on an
RKE2 GPU node that file would have discarded the registry mirrors, the sandbox
image and the CNI settings (karr #23).

Both distributions scan `$PATH` for `nvidia-container-runtime` at service start
— with `/usr/local/nvidia/toolkit` and `/opt/kwasm/bin` prepended, exactly where
the toolkit DaemonSet installs — and write what they find into their own
containerd config. OCP installs the toolkit in `detect_gpu`, before the
distribution, so the ordering already works.

## Decision

Config the distribution generates belongs to the distribution. OCP merges into
it, or does nothing at all.

- **containerd/NVIDIA: do nothing.** `_configure_nvidia_containerd` was deleted
  outright. Both distributions register the runtime themselves. The only
  remainder is one additive line — `_configure_nvidia_runtime_path` writes a
  `PATH=` into `/etc/default/rke2-server`/`-agent`, because
  `rke2-server.service` sets no `Environment=` at all — and it is not called for
  k3s.
- **CoreDNS: merge inline.** `_corefile_with_host` appends the record *into* the
  existing `hosts` block and creates a block of its own only when there is none.
  It is a pure function, idempotent, corrects a changed control-plane IP in
  place, and `_corefile_drop_added_hosts` repairs a Corefile already broken by
  the previous behaviour — but only while more than one `hosts` block exists,
  and never the last one.
- **Do not make the NVIDIA runtime the default.** Neither distribution does, and
  OCP will not do it through the back door. The documented path is
  `RuntimeClass nvidia`; anyone who really needs a default runtime uses
  `--default-runtime nvidia`, which fails loudly at start if the runtime is
  missing instead of silently doing nothing.

### Alternatives rejected

- **CoreDNS `coredns-custom` (`*.override` / `*.server`)** — `*.override` is
  imported *into* the server block, so a second `hosts` fails on the same rule;
  what remains is `template`/`rewrite` with a regex instead of an A record. And
  the extension point does not exist on RKE2 at all (`extraConfig: {}` in the
  chart), so it would be two mechanisms instead of one.
- **k3s `NodeHosts`** — the ConfigMap key belongs to the k3s supervisor
  (`managedFields`), which rewrites it.
- **RKE2 `HelmChartConfig`** — RKE2-only, and it means carrying a copy of the
  chart's `servers:` list (ADR 0011).
- **Keeping a `config.toml.tmpl` with `{{ template "base" . }}` added** —
  correct but pointless: the distribution already registers the runtime, and the
  file would be one more thing to keep in step with two distributions and with
  containerd 2.x's renamed `config-v3.toml.tmpl`.

## Consequences

- Both distributions own their CoreDNS ConfigMap, so a distribution upgrade
  resets the Corefile and `registry.local` stops resolving until the next
  `ocp apply` puts it back. That was observed live: k3s' addon manager restored
  its default and removed the record. The record is spec, the Corefile is
  cluster state, so `_configure_registry_dns` is on the reconcile path
  (ADR 0018) and the drift is self-healing.
- The window between the upgrade and the next apply stays open, deliberately.
  It is reported rather than closed by a second, upgrade-durable mechanism;
  see ADR 0022 for the measurements behind that (karr #19).
- The ConfigMap has to be looked up under both names, because RKE2's is
  Helm-mangled (`rke2-coredns-rke2-coredns`). That list is shared between the
  writer and the drift reader so they cannot diverge — and so is
  `resolve_address`, after the two sides derived the expected address
  separately and disagreed on every correctly configured cluster (ADR 0019).
  One fact, one derivation, used by everyone who needs it.
- OCP now depends on the distributions' runtime auto-detection continuing to
  work, and on the toolkit being installed before the distribution starts. Both
  were verified on k3s; the RKE2 `PATH` line is written and unverified.
