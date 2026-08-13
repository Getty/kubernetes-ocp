# 0017. Make the success banner a statement about the cluster, not about the run

Date: 2026-08-12
Status: accepted

## Context

`ocp apply` printed `CONTROL PLANE DEPLOYED SUCCESSFULLY!` and exited 0 on a
cluster whose CoreDNS was in CrashLoopBackOff and whose five GPU operator pods
were in `Init:ImagePullBackOff` (karr #18). Every step had returned without an
error, so the banner was true about the *procedure* and false about the thing
the procedure exists to produce.

`xt/smoke.sh` already checked for CrashLoopBackOff, so the gap was known to the
smoke test and not to the command anyone actually runs.

A naive gate is worse than none. Pods legitimately spend minutes in
`ContainerCreating` and `PodInitializing`; a readiness probe that has not gone
green yet is not a failure; a single startup crash is not a verdict. A flaky
gate on a frequently-run command trains people to ignore the exit code, and then
the exit code is worth nothing.

There is also a severity question. The GPU operator's ImagePullBackOff was a
real fault, but it was an *opt-in add-on* failing on an otherwise working
cluster. Failing the whole apply for it is the flakiness problem in another
costume.

## Decision

The banner comes after a verdict about the cluster, obtained over the API
(ADR 0007) by listing pods.

**Wait first, judge once.** Wait until nothing is still coming up, or until the
timeout (120s, 5s interval), then judge only the last scan.

**Judge only what waiting cannot heal**: `CrashLoopBackOff`, `ImagePullBackOff`,
`ErrImagePull`, `InvalidImageName`, `CreateContainerConfigError`,
`CreateContainerError`, `RunContainerError`. `CrashLoopBackOff` additionally
requires `restartCount >= 2`.

**Scan init containers too.** `Init:ImagePullBackOff` lives in
`initContainerStatuses`; a check over `containerStatuses` alone would have
missed all five GPU pods — the exact pods that motivated the gate.

**Split the severity.** `kube-system` is fatal, exit 1: that namespace *is* the
cluster — DNS, CNI, core controllers — and a green deploy over dead DNS is the
failure mode this exists to catch. Everything else warns loudly and leaves the
exit code alone. The banner reads `SUCCESSFULLY!`, `— WITH WARNINGS`, or
`— CLUSTER IS NOT HEALTHY` accordingly.

**A broken health check is not a broken deploy.** If the check itself dies it
degrades to a warning rather than killing an otherwise successful run.

One verdict, one banner, one exit code: both the bootstrap path and the
reconcile path end in `_finish_apply`, which is the only caller of
`_check_cluster_health` (karr #22). The failure mode was a path quietly walking
past the check, so there is exactly one place it can be walked past.

Correspondingly, `ocp apply` does not stamp `status.ocpVersion` when it could
not decrypt the kubeconfig — claiming to manage a cluster it never reached is
the same class of lie.

### Alternatives rejected

- **Fail on anything unhealthy anywhere** — an opt-in add-on then reddens every
  apply, and people learn to ignore the exit code.
- **Check nothing, leave it to the smoke test** — the smoke test runs on one
  machine on purpose; the command everyone runs stayed silent.
- **Judge the first scan** — turns normal startup into a failure and makes the
  gate flaky, which is how gates get disabled.

## Consequences

- Every `ocp apply` costs an extra pod list and up to 120s of settling time.
- A pod that is genuinely stuck `Pending` (unschedulable, no resources) is
  reported as "still starting" and does not fail the run: only durable *waiting
  reasons* are judged.
- `kube-system` is a hardcoded list of one. A distribution that puts core
  components elsewhere would be judged too leniently.
- The banner is now load-bearing for humans and CI alike, so anything that
  weakens the check weakens both.
- The GPU stack's real proof — `nvidia.com/gpu` in the node capacity — is still
  not part of the gate (ADR 0015).
