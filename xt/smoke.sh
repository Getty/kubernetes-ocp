#!/usr/bin/env bash
#
# Full bootstrap against a real machine: init, apply, status, kubeconfig,
# node ls, update --dry-run, destroy.
#
# Everything in t/ asserts on data structures and source text, because
# nothing in OCP can be executed without a real host. That is where every
# bug of the last round came from — a k3s join pointed at RKE2's supervisor
# port, a cluster named ".", a registry that crash-looped its way to
# readiness. None of them made a single test go red. This is the loop that
# would have caught them.
#
# Runs the working tree, not the built image: the image supplies the
# dependencies, /src supplies lib/, bin/ AND share/.
#
# share/ is the half that used to be missing, and it is the half that matters
# most: -I only redirects lib/, so share/ kept coming out of the image and
# every smoke run tested the Rexfile of the last build instead of the one just
# edited — with nearly all of the bootstrap logic living in that file. It is
# passed explicitly via OCP_SHARE_DIR rather than left to the search order, so
# this script says which tree it is testing instead of hoping.
#
#   make smoke SMOKE_HOST=reuben.cihq
#   make smoke SMOKE_HOST=reuben.cihq SMOKE_DIST=k3s
#   make smoke SMOKE_HOST=reuben.cihq SMOKE_KEEP=1   # leave the cluster up
#
# This WIPES whatever Kubernetes is installed on SMOKE_HOST. That is why the
# host has no default.
#
set -euo pipefail

HOST="${SMOKE_HOST:?set SMOKE_HOST to a throwaway machine — its cluster gets wiped}"
DIST="${SMOKE_DIST:-rke2}"
SSH_KEY="${SMOKE_SSH_KEY:-$HOME/.ssh/id_ed25519}"
IMAGE="${SMOKE_IMAGE:-raudssus/ocp:latest}"
KEEP="${SMOKE_KEEP:-}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"

steps_ok=0
trap 'printf "\n--- project dir: %s\n" "$WORK"' EXIT

step() { printf '\n=== %s\n' "$*"; }
pass() { steps_ok=$((steps_ok + 1)); printf '    ok: %s\n' "$*"; }
fail() { printf '\n!!! FAILED: %s\n' "$*" >&2; exit 1; }

expect() { # expect <output> <pattern> <description>
    printf '%s' "$1" | grep -Eq -- "$2" && pass "$3" || fail "$3 (no match for /$2/)"
}

ocp() {
    docker run --rm \
        -v "$WORK":/ocp \
        -v "$REPO":/src:ro \
        -v "$SSH_KEY":/home/ocp/.ssh/id_ed25519:ro \
        -v "$SSH_KEY.pub":/home/ocp/.ssh/id_ed25519.pub:ro \
        -e OCP_SHARE_DIR=/src/share \
        -w /ocp --entrypoint perl "$IMAGE" -I/src/lib /src/bin/ocp "$@"
}

# kubectl is a debugging tool here, not a code path — OCP itself never shells
# out to it. The smoke test uses it to check the cluster from the outside.
kube() {
    docker run --rm -v "$WORK":/ocp -w /ocp --entrypoint kubectl "$IMAGE" \
        --kubeconfig /ocp/smoke.kubeconfig "$@"
}

printf 'smoke: %s on %s\n' "$DIST" "$HOST"
printf '       working tree: %s\n' "$REPO"
printf '       any Kubernetes on %s will be wiped\n' "$HOST"

# Before wiping a machine, check that the run is about to execute the tree it
# says it is. This is the assertion whose absence let a whole week of Rexfile
# work go untested: the modules came from /src, the Rexfile came from the
# image, and nothing in the output distinguished the two.
step "provenance"
share_dir="$(docker run --rm -v "$REPO":/src:ro -e OCP_SHARE_DIR=/src/share \
    --entrypoint perl "$IMAGE" -I/src/lib -MOCP::Share -e 'print OCP::Share->dir')"
[ "$share_dir" = "/src/share" ] \
    && pass "share/ resolves to the mounted working tree" \
    || fail "share/ resolved to '$share_dir', not the working tree at /src/share"

step "init"
ocp init --provider=ssh --host="$HOST" --nopassword \
    --dist="$DIST" --name="smoke-$DIST" \
    --ssh-key=/home/ocp/.ssh/id_ed25519 --nogit >/dev/null
[ -f "$WORK/ocp.yaml" ] || fail "init wrote no ocp.yaml"
expect "$(cat "$WORK/ocp.yaml")" "^name: smoke-$DIST\$" "cluster name is what --name said"
expect "$(cat "$WORK/ocp.yaml")" "dist: $DIST" "distribution recorded"

step "destroy (pre-clean, a leftover cluster is not an error)"
ocp destroy --force >/dev/null 2>&1 || true

step "apply"
apply_out="$(ocp apply 2>&1)" || { printf '%s\n' "$apply_out"; fail "apply exited non-zero"; }
printf '%s\n' "$apply_out" | tail -5
expect "$apply_out" 'DEPLOYED SUCCESSFULLY' "apply reports success"
expect "$apply_out" 'API Endpoint: https://.*:6443' "API endpoint is the apiserver, not the join port"

step "status"
status_out="$(ocp status 2>&1)" || fail "status exited non-zero"
printf '%s\n' "$status_out"
expect "$status_out" '^Distribution: '"$DIST" "status names the distribution"
expect "$status_out" 'Ready' "status sees a ready node"

step "kubeconfig"
ocp kubeconfig > "$WORK/smoke.kubeconfig" || fail "kubeconfig exited non-zero"
expect "$(cat "$WORK/smoke.kubeconfig")" 'server: https://.*:6443' "kubeconfig points at the apiserver"
nodes_out="$(kube get nodes 2>&1)" || fail "kubectl could not reach the cluster"
printf '%s\n' "$nodes_out"
expect "$nodes_out" ' Ready ' "the node is Ready as far as Kubernetes is concerned"

step "workloads are actually running"
pods_out="$(kube get pods -A 2>&1)" || fail "kubectl get pods failed"
expect "$pods_out" 'cilium' "Cilium is deployed"
expect "$pods_out" 'ocp-registry' "the registry is deployed"
crash="$(printf '%s' "$pods_out" | grep -E 'CrashLoopBackOff|Error' || true)"
[ -z "$crash" ] || fail "pods in a bad state:\n$crash"
pass "no pod in CrashLoopBackOff or Error"

step "node ls"
nodels_out="$(ocp node ls 2>&1)" || fail "node ls exited non-zero"
printf '%s\n' "$nodels_out"
# Columns are NAME ROLE PHASE PROVIDER IP AGE.
#
# The old assertion was "smoke-$DIST|control-plane", which in an ERE is an
# alternation: any line containing "control-plane" satisfied it. It therefore
# passed on a cluster where the OCPNode CR had no status at all — the control
# plane showed up as Pending with an empty IP while `ocp status` said Ready.
# Assert the phase and the IP, which is what actually distinguishes a written
# status from a missing one.
cp_row="$(printf '%s\n' "$nodels_out" | grep -E "^smoke-$DIST[[:space:]]" || true)"
[ -n "$cp_row" ] || fail "node ls has no row for smoke-$DIST"
expect "$cp_row" '^[^[:space:]]+[[:space:]]+control-plane[[:space:]]+Ready[[:space:]]' \
    "node ls reports the control plane as Ready"
expect "$cp_row" '[[:space:]]([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]' \
    "node ls reports an IP for the control plane"

step "update --dry-run"
update_out="$(ocp update --dry-run 2>&1)" || fail "update --dry-run exited non-zero"
printf '%s\n' "$update_out"

if [ -n "$KEEP" ]; then
    step "keeping the cluster (SMOKE_KEEP set)"
else
    step "destroy"
    ocp destroy --force >/dev/null 2>&1 || fail "destroy exited non-zero"
    pass "cluster removed"
fi

printf '\nsmoke: %s checks passed for %s on %s\n' "$steps_ok" "$DIST" "$HOST"
