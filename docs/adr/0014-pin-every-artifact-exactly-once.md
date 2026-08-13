# 0014. Pin every upstream artifact exactly once, in OCP::Versions

Date: 2026-08-12
Status: accepted

## Context

OCP installs a dozen upstream components — two Kubernetes distributions, Cilium
and its CLI, the Gateway API CRDs, cert-manager, NFD, and the whole NVIDIA
stack. Because Helm is off the runtime path (ADR 0011), OCP writes those
manifests itself, which means it also decides every image tag.

Scattering those tags across the manifest generators is how the worst bug of
this cycle happened. `OCP::Versions` pinned `nvidia_validator => v26.3.3`
separately from `gpu_operator => v26.3.3` — two pins that must be equal by
definition. They were, until the upstream validator repository stopped at
v25.3.4 while the operator kept moving. The ClusterPolicy then pointed at
`nvcr.io/nvidia/cloud-native/gpu-operator-validator:v26.3.3`, which does not
exist on any architecture, and every GPU cluster went into Init:ImagePullBackOff
(karr #11).

The reflex fix — pin the validator to a version that exists — would have kept
the second pin and the trap with it.

## Decision

Every upstream artifact is pinned exactly once, in `OCP::Versions`. A version
that must equal another version is not a pin: it is a read of the first one.
`nvidia_validator` was removed, and the ClusterPolicy's validator now points at
the operator image with the operator's pin — which is also what upstream does,
since the validator binary has shipped inside the operator image since v25.10.

A pin may carry a *floor* with the reason attached. The device plugin must stay
at or above v0.17.4: GB10 (Grace Blackwell, unified memory) has no dedicated
framebuffer, `nvmlDeviceGetMemoryInfo` answers "Not Supported", and plugins
before v0.17.4 treat that as fatal — the pod crashes and the node reports zero
GPUs while the GPU works fine (karr #25). A downgrade below the floor is a
silent regression on that hardware.

Comments at a pin say why it is what it is, not what it is. `gateway_api` is
version-locked to `cilium`; `nvidia_driver` exists only for the
`gpu.driver: operator` path and is the value from the pinned operator's own
`values.yaml`.

Every pinned image must exist for every architecture OCP targets (ADR 0020).

### Alternatives rejected

- **Pin the validator to a version that exists** — keeps two pins that must
  agree, i.e. keeps the trap.
- **Omit the override and let the operator default** — verified and refuted:
  without `repository`/`version` in the CR, the operator falls back to a
  `VALIDATOR_IMAGE` environment variable that OCP's hand-written Deployment
  does not set, and errors out. The override is required (ADR 0011).
- **Track floating tags** — a cluster's component version would then depend on
  when it was installed, and drift detection would have nothing to compare to.

## Consequences

- A version bump is not a one-line edit: each pin has to be checked for
  existence and for a real `linux/arm64` entry under the same tag.
- Derived versions are invisible at the point of use — the reader of the
  ClusterPolicy sees the operator pin where a validator version used to be, and
  has to know why. The comment at the pin carries that.
- Floors are only enforced by a regression test and this record; nothing stops
  a bump from crossing one downward.
- `OCP::Drift` only probes Cilium and cert-manager, so most pins have no
  runtime verification that the cluster actually runs them.
