# 0004. Keep the spec in git and the status out of it

Date: 2026-08-12
Status: accepted

## Context

A deployment run produces two kinds of fact, and they want opposite treatment.

Some facts are answers to questions the user *could* have decided but did not:
which public IP the control plane ended up on, which server type was used, what
the cluster is called. If those are thrown away, the next `ocp apply` re-derives
them and may derive them differently — and nothing can then detect that the
control plane moved.

Other facts are things the user could never have set: the provider's internal
server ID, the node join token, the kubeconfig, phase and timestamps. Putting
those in the file the human edits turns every apply into a diff of machine
churn, and invites someone to hand-edit a join token.

## Decision

Split them by that exact question — *could the user have set this?*

- **`ocp.yaml` (spec, git-tracked)** holds everything the user could have set.
  Computed defaults flow back into it and are pinned after the first apply, so
  the repository alone describes the cluster it built. Written by `OCP::Config`.
- **`.ocp/status.yaml` (transient, gitignored)** holds only what the user could
  not have set: provider IDs, join tokens, phases, timestamps, and the
  `ocpVersion` stamp.

`OCP::Drift` is the consequence of the split, not an addition to it: it compares
the pinned spec values against recorded and live state. A pinned `public_ip`
that no longer matches reality is *reported*, never silently corrected — a moved
control plane is a fact a human has to look at. Component version drift
(Cilium, cert-manager) carries a Rex `remedy` and is fixed automatically;
distribution upgrades never do.

There is no key normalisation and there are no camelCase aliases:
`YAML::XS::LoadFile` reads `ocp.yaml` as written, and the keys are snake_case.

### Alternatives rejected

- **One state file for everything** — either the git-tracked file fills with
  machine churn, or the reproducible parts are lost on `rm -rf`.
- **Silently rewriting a drifted pin** — makes "the control plane moved" and
  "someone edited the spec" indistinguishable, and destroys the only evidence
  that something happened.
- **Accepting camelCase aliases alongside snake_case** — two spellings for one
  key means the file no longer says what it means, and validation has to guess.

## Consequences

- `.ocp/` is disposable by construction; losing it costs a re-fetch, not the
  cluster. Losing `ocp.yaml` costs the cluster's definition.
- Every new computed value has to be classified on the way out. Getting it
  wrong is not obvious: a token in the spec is a leak, an IP only in the status
  is undetectable drift.
- Drift can only compare what was pinned. A value the spec never pinned cannot
  drift, which is the tradeoff for keeping `ocp.yaml` small.
- `ocp update` and `ocp version` refuse to work without `status.ocpVersion`,
  which apply stamps at the end — deliberately, so a run that could not reach
  the cluster does not claim to manage it.
