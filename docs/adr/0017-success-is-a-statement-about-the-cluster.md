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
  reasons* are judged *(amended 2026-11-06, see below)*.
- `kube-system` is a hardcoded list of one. A distribution that puts core
  components elsewhere would be judged too leniently.
- The banner is now load-bearing for humans and CI alike, so anything that
  weakens the check weakens both.
- The GPU stack's real proof — `nvidia.com/gpu` in the node capacity — is still
  not part of the gate (ADR 0015) *(amended 2026-10-31 and 2026-11-03, see
  below)*.

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
but outside the gate *(amended 2026-11-03, see below)*.

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
as a provisional call, not a maintainer decision, and it is open on k285
*(amended 2026-11-03, see below)*.
k286 and k287 widened which nodes are waited for on both sides and left the
asymmetry as it was. Recorded under k274; the waits for joined nodes under
k310.

## Amendment 2026-11-03

The amendment of 2026-10-31 ended on an asymmetry:

> The two vendors therefore differ. A node without its GPU in allocatable is a
> warning on NVIDIA and a failed component on AMD. That asymmetry was set in
> k273 as a provisional call, not a maintainer decision, and it is open on
> k285.

k285 closes it in favour of parity. In `ocp apply`, an NVIDIA node without
`nvidia.com/gpu` in `status.allocatable` after the GPU Operator step's wait is
now a failed component, as an AMD node without `amd.com/gpu` has been since
k251. `ocp apply` names the node on STDERR, the banner reads
`— APPLY INCOMPLETE`, and the exit code is non-zero. The route is the AMD one:
the failed-component list, not the pod scan. `ocp node add --gpu` stays
non-fatal on both vendors, and its exit code still says only whether the node
is Ready. The call is the main agent's, not the maintainer's
*(amended 2026-11-06, see below)*.

k273 kept NVIDIA at a warning for two reasons. Neither holds any more:

- **No live NVIDIA check of the wait.** On 2026-11-03 an RTX 3090 node running
  OCP's own ClusterPolicy (driver 610.57.04) showed `nvidia.com/gpu: "1"` in
  `status.allocatable`. An idempotent `ocp apply` on its cluster exited 0 and
  reported the GPU Operator up to date.
- **The resource can carry another name.** Time-slicing with
  `renameByDefault` publishes `nvidia.com/gpu.shared`, and the MIG strategy
  `mixed` publishes `nvidia.com/mig-*`. A wait for `nvidia.com/gpu` would read
  either as a GPU that never arrived. But the ClusterPolicy OCP writes sets
  neither. Its device plugin carries no sharing config, `migManager` is off,
  and it has no `mig` block, so the operator's default MIG strategy applies.
  That default is `single`, which publishes MIG slices as `nvidia.com/gpu`
  too. The renamed resources come only from settings OCP does not write.

The k273 code gave one more reason: the operator is deployed and the node is
up, and whatever holds the device plugin back is on the node. That is just as
true on AMD, where it has been a failed component since k251. It says where to
look, not whether the apply produced what the spec asked for. This ADR's
banner is a statement about the cluster. A node that was meant to hand out a
GPU and cannot is the gap this ADR exists to report.

This is not the "fail on anything unhealthy anywhere" alternative rejected
above. The pod scan is unchanged: a broken pod in `gpu-operator` still warns
and leaves the exit code alone. The new failure is one specific proof, on
nodes where the spec enabled the GPU stack and the machine has an NVIDIA card.
It is judged once, after a wait (300 s), as the pod scan is.

The last Consequence and the 2026-10-31 sentence "the proof is checked, but
outside the gate" no longer hold for either vendor. The proof, read in
allocatable, now decides the banner and the exit code of `ocp apply` on
NVIDIA as on AMD.

Consequences of the parity:

- A ClusterPolicy given time-slicing with `renameByDefault`, or the MIG
  strategy `mixed`, by someone other than OCP now fails `ocp apply` on those
  nodes. OCP's Server-Side Apply owns only the fields it writes (ADR 0008), so
  those settings survive it, and the wait still looks for `nvidia.com/gpu`. A
  cluster OCP does not describe now shows up as an incomplete apply instead of
  a warning.
- An NVIDIA node whose driver, toolkit or validator holds the device plugin
  back now turns `ocp apply` red, where before it printed a `[WARN]` and
  exited 0. CI that runs `ocp apply` on a GPU cluster sees that.

Unverified: the live run on 2026-11-03 used the code from before the parity.
It shows that OCP's ClusterPolicy publishes `nvidia.com/gpu`. It does not show
the new failure, an NVIDIA node short of `nvidia.com/gpu` ending in
`— APPLY INCOMPLETE`, on a live cluster. The `single` default was not seen on
a MIG-capable card; the RTX 3090 has no MIG. Recorded under k285.

## Amendment 2026-11-06

A Consequence above reads:

> A pod that is genuinely stuck `Pending` (unschedulable, no resources) is
> reported as "still starting" and does not fail the run: only durable *waiting
> reasons* are judged.

That still holds for the pod scan. What it left out is the node a `Pending`
pod waits for. A first control plane that never turns Ready leaves every pod
the deploy rolls out `Pending`, and the scan judges none of them. Nothing
judged the node itself. Since k327 (53d34eb) the bootstrap's wait said so on
STDERR, `[WARN] Node NAME not seen Ready within 600s`, with the `Ready`
condition's reason, and then went on. It left the banner and the exit code to
whatever came after. In practice that was the registry step, which must
succeed. It ran out of its own 120 s wait for pods that could not be
scheduled, and the run ended `Error: …`, non-zero, with no banner and with the
registry named instead of the node. A run whose later steps passed, because
the node turned Ready after the wait, ended `SUCCESSFULLY!` over a control
plane its own wait had not seen Ready. Since k226 (4305e2d) a further control
plane that did not join and a worker short of Ready had been failed
components. The first control plane was the one node `ocp apply` did not
judge.

The maintainer decided on 2026-11-06 (k336) that a node that never got Ready
is a failure, and so is an NVIDIA or AMD node without its GPU in
`status.allocatable`. The second half is what k285 built on 2026-11-03 as the
main agent's call. It is now the maintainer's rule. In `ocp apply`, each half
reaches the banner and the exit code through the failed-component list, as
the GPU proofs already did. A failed component makes the banner read
`— APPLY INCOMPLETE` and the exit code non-zero
(`OCP::Cmd::Apply::Health::finish`).

The rule as `ocp apply` applies it, on the first deploy (no
`kubeconfig.yaml`):

- **First control plane.** The bootstrap waits 60 × 10 s = 600 s for its
  Node's `Ready` condition to read `True`. A node not seen Ready by then gets
  one `[!!] Node NAME not seen Ready within 600s: …` line on STDERR, with what
  the API said last, and is counted as `control plane NAME`, the name a
  further control plane gets (`bootstrap_control_plane`). The run goes on:
  the kubeconfig is saved, and each later step says what it could not do. A
  step that must succeed still ends the run `Error: …`, non-zero, before the
  banner. In practice that is the registry, whose pods cannot be scheduled on
  a NotReady node. A run that gets past those steps ends `— APPLY INCOMPLETE`,
  also when the node turned Ready late: the wait did not see it Ready.
- **Further control planes** (police2+, RKE2 only) join through `OCP::Node`
  within `$OCP::Node::READY_TIMEOUT` (900 s). One not Ready when its join ends
  is `control plane NAME`, since k226.
- **Workers in ocp.yaml.** A worker not Ready at the end of the worker step
  is `worker NAME`, since k226. That holds whether robocop drove it (a 600 s
  poll) or the CLI fallback did (`$OCP::Node::READY_TIMEOUT`).

On reconcile (the cluster exists):

- A worker in ocp.yaml without an OCPNode is created and driven as on the
  first deploy, and one that does not reach Ready is counted (k26).
- A worker OCPNode in `Failed` is an `[!!]` and counted. One in `Pending`,
  `Provisioning`, `Installing` or `Joining` is a `[WARN]`, and the banner
  reads `— WITH WARNINGS` with exit 0. It is reported, not waited for and not
  driven again (k234, 8d3e57f).
- A `Failed` OCPNode that ocp.yaml does not list is named, not counted. It is
  not part of the spec this apply checks (k231).

And for the GPU, on both paths:

- **NVIDIA.** The GPU Operator step waits up to 300 s
  (`gpu_ready_timeout`) for `nvidia.com/gpu` above 0 in `status.allocatable`
  on every NVIDIA node it detected. A node short of it fails the
  `GPU Operator` component (k273, k285). After a worker join it waits up to
  600 s (`gpu_label_timeout`) for NFD's label and then runs the same check,
  counted the same way (k287).
- **AMD.** The AMD stack step waits up to 300 s (`ready_timeout`) for
  `amd.com/gpu` in `status.allocatable`, or for a ResourceSlice with the DRA
  driver. For a node that just joined it waits 600 s (`join_ready_timeout`).
  A miss is a failed component, `after_join` included (k251, k286).

The argument of 2026-11-03 carries over. Each of these is one proof, judged
once, after a wait: the `Ready` condition after 600 s, as the GPU in
allocatable after 300 s. This is not the "fail on anything unhealthy
anywhere" alternative rejected above. The pod scan is unchanged, and a pod
stuck `Pending` is still "still starting". The node such a pod waits for is
now judged in its own right, which the pod scan could never do.

`ocp node add` is unchanged. Its exit code says only whether the node is
Ready, so the first half of the rule already held there. A GPU missing from
allocatable is an `[!!]` on STDERR that names `ocp apply`, with exit 0. The
GPU half of the rule is applied by the `ocp apply` it sends the operator to.

Consequences:

- A first deploy whose control plane turns Ready only after the 600 s wait
  now ends `— APPLY INCOMPLETE` and non-zero, though the stack came up on it.
  Before, it ended `SUCCESSFULLY!`. The 600 s is now load-bearing for the exit
  code, and a machine that needs longer to get its CNI up turns the first
  deploy red.
- A first deploy that dies in the registry step still ends `Error: …` and
  names the registry. The node is named only in the `[!!]` line above it; the
  run never reaches the closing `Apply did not complete` line.

Known gap, recorded and not decided (open on k417): the reconcile path does not judge the
control planes' readiness, and does not join police2+ again. There a control
plane is judged only through steps that happen to wait for a pod on it. A
component that has to roll out waits for its pods, and is counted under its
own name when they do not come up. A component that is up to date does not
wait, and the pod scan reads a pod stuck `Pending` as still starting. A rerun
after a failed bootstrap therefore ends `SUCCESSFULLY!` with the first control
plane NotReady whenever every step it runs finds its component up to date.
One way to get there: a bootstrap whose node turned Ready only after the
wait, which ended `— APPLY INCOMPLETE` with the stack deployed and recorded,
and a node that is NotReady again by the rerun. A rerun right after a
bootstrap that died in the registry step does not end green. The registry's
hash is recorded only once its pods were ready, so the rerun rolls it out
again, runs out of the same wait and counts `Registry`. It does not count
the node.

Unverified: the new failure is tested in `t/327-bootstrap-node-ready.t`
against a stubbed pod scan. It has not been seen on a live cluster. Recorded
under k336.
