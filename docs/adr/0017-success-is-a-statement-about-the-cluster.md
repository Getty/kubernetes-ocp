# 0017. Make the success banner a statement about the cluster, not about the run

Date: 2026-08-12
Status: accepted

## Context

`ocp apply` printed `CONTROL PLANE DEPLOYED SUCCESSFULLY!` and exited 0 on a
cluster whose CoreDNS was in CrashLoopBackOff and whose five GPU operator pods
were in `Init:ImagePullBackOff` (k18). Every step had returned without an
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
`_check_cluster_health` (k22). The failure mode was a path quietly walking
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
  not part of the gate (ADR 0015) *(amended 2026-10-31, see below)*.

## Amendment 2026-10-31

The last Consequence read:

> The GPU stack's real proof — `nvidia.com/gpu` in the node capacity — is still
> not part of the gate (ADR 0015).

Capacity was never that proof. The kubelet leaves it standing after a device
plugin unregisters, and only `status.allocatable` says that a pod can get the
GPU. This was seen live on amdlab on 2026-10-31 as capacity 1 / allocatable 0
(rex-rancher k106, cf10698; ADR 0015, amended the same day). The proof is the
GPU in allocatable.

For NVIDIA the rest of the sentence still holds, though no longer because
nothing asks. Since k273 (7e786ce), every `setup_gpu_operator` run that does
not skip, `unchanged` included, waits up to 300 s (`gpu_ready_timeout`). It
waits for `nvidia.com/gpu` above 0 in `status.allocatable` on every NVIDIA node
it detected, and `ocp node add --gpu` runs the same check. Since k287
(fc5740b) that also covers an NVIDIA worker that joins in the same apply after
the check ran. `setup_gpu_operator_after_join` used to check again only when
the first check had skipped, so nothing waited for that node until the next
apply. Now it also checks again after a first check that ran: it waits up to
600 s (`gpu_label_timeout`) for NFD to label the joined workers, and runs
`setup_gpu_operator` once more when one of them carries NFD's NVIDIA label.
After a failed first check there is no second one. A node without
`nvidia.com/gpu` in allocatable after 300 s is one
`[WARN] NVIDIA GPU not ready after 300s: …` on STDERR, in either check. The
verdict, the banner and the exit code stay as they were. The proof is checked,
but outside the gate.

For AMD it no longer holds. This was added alongside the capacity error, not
caused by it. Since k251 (4d90591), the AMD stack step waits for
`amd.com/gpu` in `status.allocatable` on every node the device plugin selects
(for the DRA driver, a ResourceSlice per node). A node that does not show it in
time is a failed component: `ocp apply` names it on STDERR, the banner reads
`— APPLY INCOMPLETE`, and the exit code is non-zero
(`OCP::Cmd::Apply::Health::finish`). That check is not the pod scan this ADR
describes. It reaches the same banner and exit code through the
failed-component list. `ocp node add --gpu` reports the same failure on STDERR
and names `ocp apply`; its exit code still says only whether the node is Ready.

Until k286 (bd5233d) the step waited only after it rolled a component out. An
`unchanged` component returned at once, so a node that joined an up-to-date
stack was never waited for. Now `ensure` waits on `unchanged` too, and a wait
that runs out fails the component the same way. The budget is 300 s
(`ready_timeout`), or 600 s (`join_ready_timeout`) when the step runs for a
node that just joined: `step(..., joined => 1)`, from `ocp node add --gpu` and
from `after_join` in `ocp apply`. The 600 s comes from synapse (amdlab):
Cilium's first BPF compile on the fresh node held the plugin pod back until
about 7 minutes after registration, past the 300 s. NVIDIA needs no such
budget for allocatable: its check after a join starts only once NFD has
labelled the node, so its 300 s start on a node whose CNI works.

The two vendors therefore differ. A node without its GPU in allocatable is a
warning on NVIDIA and a failed component on AMD. That asymmetry was set in k273
as a provisional call, not a maintainer decision, and it is open on k285.
k286 and k287 widened which nodes are waited for on both sides and left the
asymmetry as it was. Recorded under k274; the waits for joined nodes under
k310.
