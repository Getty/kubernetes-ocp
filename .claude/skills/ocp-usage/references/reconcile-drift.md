# Reconciliation & Drift

Read when: ocp apply reconciles an existing cluster: drift, hashes, CR-first workers.

## Reconciliation & Drift

`ocp apply` with an existing `kubeconfig.yaml` enters reconcile mode:

1. **Drift detection first** (`OCP::Drift`): Cilium and cert-manager version
   drift carry Rex remedies (`upgrade_cilium`/`upgrade_cert_manager`) and are
   fixed automatically; distribution drift and moved pinned IPs are
   report-only — a human decides. `ocp status` shows the same drift report,
   and its "N of M can be reconciled automatically" count (and `--json`
   `fixable`) is what `ocp apply` closes (k312): a remedy, a `self_healing`
   entry, or kind `missing`; unfound checks (kind `error`) are not counted.
2. **Hash-based components** (`.ocp/deployed.yaml`, MD5 of generated
   manifests): registry, NFD, GPU operator. cert-manager is tracked by
   component version, not manifest hash. NFD and the GPU Operator are also
   self-healing (k351): their step reads the image the drift probe reads
   (`OCP::Drift->version_against_pin`) and re-applies the manifest when the
   tag is off its pin, even at an unchanged hash; args and other fields are
   not compared. `--dry-run` says "would re-apply the NFD manifest" (or the
   GPU Operator's, under `gpu.enabled`).
3. Apply stamps `status.ocpVersion` at the end — `ocp update` and
   `ocp version` depend on it.

Fresh bootstrap additionally deploys: Cilium Gateway API, cert-issuers
(selfsigned + ACME with `ssl.email`), `registry.local` DNS entry in CoreDNS,
and LB-IPAM (only when `lbipam: true`).

Worker flow is CR-first: apply always applies CRDs, creates an
OCPNodeProvider + Secret per configured provider (`<type>-default`), an
observational OCPNode for the CP, and Pending OCPNodes for worker pool
entries; robocop (or the CLI fallback) reconciles them
Pending→Provisioning→Installing→Joining→Ready. Details: skill `ocp-core`,
decision history: `docs/adr/`.
