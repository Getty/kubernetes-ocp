# OCP - Omni Control Plane

Perl-based CLI to manage Kubernetes clusters (RKE2/K3s) on Hetzner, packaged as a CPAN
distribution and shipped as a Docker image. Two components: `ocp` (CLI; bootstraps
control-plane servers) and `robocop` (in-cluster controller; manages worker nodes via
OCPNode/OCPNodeProvider CRDs).

Architecture, CRDs, module map, spec/status semantics: **skill `ocp-core`**.
CLI commands, `ocp.yaml` schema, provider modes: **skill `ocp-usage`**.
Shared house rules (delegation lock, publish gate, karr): skilletor bundle `getty-house@getty`;
what only applies here, lanes, hazards: `.claude/rules/ocp-rules.md` (auto-loaded).

## Delegation

Delegate behavior-relevant code to the matching agent. The lock is a shared house
rule (bundle `getty-house@getty`), the lane boundaries are in `.claude/rules/ocp-rules.md`. Agents get their skills
force-loaded via `briefing.skills` (see `.claude/agents/`); the main agent delegates instead of
loading them itself.

| Task | Agent |
|---|---|
| Input validation, `OCP::Choices`, `option(...)` | `ocp-choices-worker` |
| Secrets/Keys, `OCP::Secrets`, `OCP::Keys`, age/SOPS/PIN | `ocp-secrets-worker` |
| State machine, `OCP::Config`, `OCP::Drift`, `OCP::Node` | `ocp-state-worker` |
| Provider, Hetzner/Local/SSH provisioning, `OCP::Rex` | `ocp-provider-worker` |
| `ocp init/apply/update/deploy-*`, Dispatcher `bin/ocp` | `ocp-apply-worker` |
| `ocp destroy` | `ocp-destroy-worker` |
| `ocp status` / `ocp version` | `ocp-status-worker` |
| robocop controller, IO::Async, reconciliation | `ocp-robocop-worker` |
| `share/`, Rexfile, Cilium/RKE2/Registry/GPU | `ocp-infra-worker` |
| Cross-cutting or unassignable | `ocp-worker` (Default) |
| Tests in `t/` | `ocp-test-writer` |
| POD and prose documents | `ocp-doc-writer` |
| ADR in `docs/adr/` | `ocp-adr-auditor` |
| Commits, `Changes`, card → done, release audit | `ocp-release-manager` |

## Knowledge map (skills in `.claude/skills/`)

| Skill | Content |
|---|---|
| `ocp-core` / `ocp-usage` | Architecture & CLI |
| `ocp-k8s` / `ocp-rke2` / `ocp-cilium` / `ocp-registry` / `ocp-gpu` | OCP configuration of these stack parts |
| `kubernetes-rke2` / `kubernetes-cilium-concepts` / `kubernetes-gpu` / `docker-registry` | the generic references underneath |
| `getty-perl-core` / `getty-perl-moo` | Getty's Perl house rules |
| `perl-kubernetes-rest` / `perl-io-k8s-kubernetes-classes` | Kubernetes::REST / IO::K8s |
| `perl-io-async-future` | Async Perl for robocop |
| `getty-perl-release-author-getty` / `perl-release-dist-ini` | Release conventions |
| `karr` | Git-native ticket board |

Only the `ocp-*` skills are repo-owned (edit them directly here). All other skills
come via **skilletor** from their sources (`.claude/skilletor.json`) — they are
build artifacts with their own `.gitignore`, **never edit them with Edit/Write**: change them in the
source and run `skilletor sync` (details: skill `skilletor`).

## Build & Test

```bash
make test          # binding suite (in the Docker image, against cpanfile.snapshot)
make test-v        # the same, verbose
make test-host     # fast, not binding (host CPAN)
make build         # build the Docker image
make snapshot      # regenerate cpanfile.snapshot (in Docker)
make docker-test   # image starts — not the suite
make smoke         # CAUTION: real host, real cluster
```

Single file: `make test TESTS=t/33-registry-manifests.t`. The toolchain is
Docker-first — details + hazards in `.claude/rules/ocp-rules.md`.

## Workflow

```bash
ocp init --hetzner   # initialize project (token, keys, config)
vim ocp.yaml         # edit spec
ocp apply            # deploy / reconcile
ocp status           # status + drift
ocp kubeconfig -e    # merge kubeconfig
ocp destroy          # delete real servers
```

## Related projects (siblings, own repos + boards)

Neighbor repos (`../`): `p5-www-hetzner`, `p5-crypt-age`, `p5-file-sops`,
`p5-net-async-kubernetes`, `io-k8s-p5`, `kubernetes-rest`. Cross-repo work goes
through karr tickets on the respective repo's board, never as a direct edit.
