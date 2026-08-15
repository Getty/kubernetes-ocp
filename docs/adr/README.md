# Architecture Decision Records

One file per architecturally significant decision: `NNNN-kebab-title.md`,
numbered monotonically from `0001`. Numbers are never reused. A decision that is
later reversed gets a new ADR that supersedes the old one; the old file stays,
with its `Status:` changed.

## Format

**Nygard** — title as a sentence, then `Date` / `Status`, then `Context`,
`Decision`, `Consequences`.

Chosen over MADR because the value here is prose, not comparison tables. Most of
these decisions were forced by a specific state of the world — a dead CoreDNS, a
404 on an image tag, a whitelist that could not match its own hardware — and the
thing worth preserving is that state and the reasoning out of it. MADR's option
matrix is at its best when several candidates were weighed evenly, which is not
what happened in most of these.

Rejected alternatives are mandatory and live as a subsection under `## Decision`,
each with the reason it was rejected. An ADR that only describes what the code
does is worthless; the code already says that. What the code cannot say is what
was tried, what was ruled out, and what got worse as a result.

`## Consequences` names the unpleasant ones too — what became harder, what is now
forbidden, and what remains unverified.

An ADR whose **decision** stops holding is superseded, not edited into shape: a
new ADR, and `Status:` changed on the old one. An ADR whose decision still holds
but whose account of its own consequences turned out to be wrong is **amended**
— the file keeps its number, its `Date` and its status, and gains a
`## Amendment YYYY-MM-DD` section at the end that quotes what it used to say,
says why that was wrong, and names the karr ticket. Each corrected sentence
carries an inline `*(amended YYYY-MM-DD, see below)*` marker, so the reader
meets the correction where the claim is and not only at the bottom of the file.
That boundary is the whole point: a wrong prediction about the consequences is
an amendment, a decision that fell is a supersession, and neither is a silent
rewrite. An ADR is a record — it never gets edited to read as though it had
always said the right thing.

## What belongs here

Decisions that constrain future work: the shape of the system, an invariant, a
rejected class of solution, a deliberate keep. Not local style, not naming, not
single-use code. A decision owned by a sibling distribution (IO::K8s,
Kubernetes::REST, WWW::Hetzner, …) is a ticket on that repository's board, not an
ADR here.

## Index

| # | Title |
|---|---|
| [0001](0001-split-cli-from-in-cluster-controller.md) | Split the ocp CLI from the robocop controller, and keep the controller opt-in |
| [0002](0002-nodes-and-providers-as-crds.md) | Model nodes and providers as CRDs and let the cluster hold node-lifecycle state |
| [0003](0003-one-trigger-neutral-node-state-machine.md) | Drive nodes from one trigger-neutral state machine, arbitrated by a lease |
| [0004](0004-spec-in-git-status-out-of-it.md) | Keep the spec in git and the status out of it |
| [0005](0005-commit-the-encrypted-files.md) | Commit the encrypted files; gitignore only the decrypted state |
| [0006](0006-two-tier-ssh-keys.md) | Split SSH access into a robo-key and a PIN-protected admin-key |
| [0007](0007-no-kubectl-in-any-code-path.md) | Reach Kubernetes only through Kubernetes::REST and IO::K8s |
| [0008](0008-server-side-apply-and-hash-convergence.md) | Write every resource with Server-Side Apply and converge components by manifest hash |
| [0009](0009-status-only-through-the-status-subresource.md) | Write CR status only through the /status subresource, and record who wrote it |
| [0010](0010-cilium-is-the-whole-network-layer.md) | Let Cilium be the whole network layer |
| [0011](0011-helm-is-never-the-default-path.md) | Keep Helm off the runtime path |
| [0012](0012-support-rke2-and-k3s-as-equals.md) | Support RKE2 and k3s as equals |
| [0013](0013-docker-first-toolchain.md) | Run the toolchain inside Docker |
| [0014](0014-pin-every-artifact-exactly-once.md) | Pin every upstream artifact exactly once, in OCP::Versions |
| [0015](0015-decide-about-gpus-from-the-machine.md) | Decide about GPUs from the machine, not from a model of it |
| [0016](0016-leave-distribution-generated-config-to-the-distribution.md) | Leave distribution-generated config to the distribution; merge, never replace |
| [0017](0017-success-is-a-statement-about-the-cluster.md) | Make the success banner a statement about the cluster, not about the run |
| [0018](0018-what-belongs-on-the-reconcile-path.md) | Admit only drift-capable, idempotent, cheap work into the reconcile path |
| [0019](0019-test-against-the-shipped-client.md) | Test against the shipped client, never against a permissive double |
| [0020](0020-arm64-is-a-first-class-target.md) | Treat arm64 as a first-class target |
| [0021](0021-robocop-polls-instead-of-watching.md) | Keep robocop polling, and hold the watch dependency as dated debt |
| [0022](0022-report-the-gap-instead-of-a-second-mechanism.md) | Report the gap instead of building a second mechanism to close it |
| [0023](0023-resolve-share-directory-next-to-running-code.md) | Resolve the share directory next to the running code, and reject overrides that do not point at a directory |
| [0024](0024-register-io-k8s-resource-providers-defensively.md) | Register IO::K8s resource providers defensively, and live with raw YAML where they are absent |
| [0025](0025-pin-perl-baseline-across-image-and-snapshot.md) | Pin the same Perl patch release in image, snapshot and runtime |
| [0026](0026-robocop-is-a-criu-and-tcp-9999-stub-pending-ticket-1.md) | Robocop is a CRIU / TCP-9999 key-injection stub pending ticket #1 |

## Provenance

0001–0021 are a backfill: the decisions already existed in the code, this
directory did not. The rationale in each was confirmed from the code itself, from
git history, and from the karr board — the tickets carry the verified *why*,
including the alternatives that were tested and refuted. 0022 is the first ADR
written alongside its decision rather than after it.

0023–0025 are also backfills — decisions in the code or the toolchain that
were not yet written down — driven by karr #63. 0026 is a snapshot, not a
decision: it records what `OCP::Robocop` currently ships (CRIU checkpoint,
TCP-9999 key injection, `sleep(60)` in place of reconciliation) and names
karr #1 / ticket #1 as the work that supersedes it. 0020 was tightened against
reality in the same pass — the "Where first-class" / "Where not yet" split is
the kind of precision karr #62 demanded (karr #10 and #58).

0004 and 0008 were amended on 2026-08-15 under karr #47 — the first use of the
amendment form described above, and the reason it is written down. Neither
decision moved. What moved was 0008's account of what the manifest hash proves:
karr #43 found `ocp destroy` leaving `.ocp/deployed.yaml` behind, and the next
apply announcing a registry it had never rolled out. The registry has since
gained the existence check the other three components already had, which makes
0008's old consequence false and shows that 0004 named `.ocp/status.yaml` but
not `.ocp/deployed.yaml`, a file obeying the same rule. Both files carry an
`## Amendment 2026-08-15` section quoting what they used to claim.

Two ADRs carry rationale that could only be reconstructed, and say so inline:
[0010](0010-cilium-is-the-whole-network-layer.md) (the rejection of Istio and
Canal is recorded only as a statement, not in any commit or ticket) and
[0011](0011-helm-is-never-the-default-path.md) (the collisions with Helm are
documented, the original decision is not). Everything else is traceable to a
commit, a ticket, or the code.

Where a decision is only partly verified — the RKE2 arm64 path, the
`gpu.driver: operator` path, the worker path end to end, the lease's 409
collision, the RKE2 half of 0022 — the ADR says so rather than implying a green
test suite proves it. 0020 splits this explicitly into "where first-class
today" and "where not yet", so the verification obligation and the artifact
claim do not get averaged into a smooth-sounding "support".

One area is deliberately absent: how robocop is constructed and reaches its
credentials in-cluster. 0026 names the ticket (karr #1, "ticket #1" in
upstream language) that will redesign that surface; until it lands, the stub
is the snapshot and the snapshot is not the goal.
