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
# Worker path (k29) -- off unless asked for, because both cost a machine:
#
#   OCP_SMOKE_WORKER_HOST=<host>   an ssh worker on an existing machine (free;
#                                  its Kubernetes is wiped like SMOKE_HOST's)
#   OCP_SMOKE_HETZNER_WORKER=1     a Hetzner worker (PAID: one server for the
#                                  length of the run; needs HETZNER_API_TOKEN
#                                  and a SMOKE_HOST the server can reach)
#
# Either one joins a worker through a pool in ocp.yaml during `apply`, waits for
# it to be Ready, reads its Kubernetes name from status.kubernetesNodeName,
# schedules a pod onto it, removes it with `ocp node rm` and checks the machine
# really is clean afterwards. The OCPNode lease against the live API server
# (xt/lease-409.t) runs on every smoke. docs/development.md has the details.
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
WORKER_HOST="${OCP_SMOKE_WORKER_HOST:-}"
HETZNER_WORKER="${OCP_SMOKE_HETZNER_WORKER:-}"
WORKER_TIMEOUT="${OCP_SMOKE_WORKER_TIMEOUT:-900}"
POD_IMAGE="${OCP_SMOKE_POD_IMAGE:-}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"

steps_ok=0
# A failed run with a PAID worker must not leave the server running: the
# project dir knows the cluster, so ask destroy to take the worker down.
# SMOKE_KEEP says the opposite and wins.
on_exit() {
    local rc=$?
    if [ "$rc" -ne 0 ] && [ "${WORKER_MODE:-}" = hetzner ] && [ -z "$KEEP" ] && [ -f "$WORK/ocp.yaml" ]; then
        printf '\n!!! run failed with a Hetzner worker up -- destroying the cluster so the server does not keep billing\n' >&2
        ocp destroy --force >/dev/null 2>&1 \
            || printf '!!! destroy failed: check Hetzner for servers labelled ocp-cluster=smoke-%s\n' "$DIST" >&2
    fi
    printf '\n--- project dir: %s\n' "$WORK"
}
trap on_exit EXIT

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
        -e OCP_SHARE_DIR=/src/share -e HETZNER_API_TOKEN \
        -w /ocp --entrypoint perl "$IMAGE" -I/src/lib /src/bin/ocp "$@"
}

# xt/smoke-worker.pl: the parsing the worker step needs (ocp.yaml pool, the
# node ls JSON, the test pod, the Hetzner server count), tested in t/.
helper() {
    docker run --rm -i -v "$WORK":/ocp -v "$REPO":/src:ro -e HETZNER_API_TOKEN \
        -w /ocp --entrypoint perl "$IMAGE" -I/src/lib /src/xt/smoke-worker.pl "$@"
}

# kubectl is a debugging tool here, not a code path — OCP itself never shells
# out to it. The smoke test uses it to check the cluster from the outside.
kube() {
    docker run --rm -v "$WORK":/ocp -w /ocp --entrypoint kubectl "$IMAGE" \
        --kubeconfig /ocp/smoke.kubeconfig "$@"
}

kube_stdin() {
    docker run --rm -i -v "$WORK":/ocp -w /ocp --entrypoint kubectl "$IMAGE" \
        --kubeconfig /ocp/smoke.kubeconfig "$@"
}

# The machine itself, for the checks only ssh can make (is the agent gone).
host_ssh() {
    ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$WORK/known_hosts" \
        "root@$1" "${@:2}"
}

WORKER_MODE=""
[ -z "$WORKER_HOST" ] || WORKER_MODE=ssh
if [ -n "$HETZNER_WORKER" ]; then
    [ -z "$WORKER_MODE" ] || { echo "OCP_SMOKE_WORKER_HOST and OCP_SMOKE_HETZNER_WORKER are two different runs; set one" >&2; exit 2; }
    : "${HETZNER_API_TOKEN:?OCP_SMOKE_HETZNER_WORKER=1 creates a paid server: export HETZNER_API_TOKEN}"
    WORKER_MODE=hetzner
fi
case "$DIST" in rke2) AGENT_UNIT=rke2-agent ;; k3s) AGENT_UNIT=k3s-agent ;; *) AGENT_UNIT="$DIST-agent" ;; esac

printf 'smoke: %s on %s\n' "$DIST" "$HOST"
printf '       working tree: %s\n' "$REPO"
printf '       any Kubernetes on %s will be wiped\n' "$HOST"
case "$WORKER_MODE" in
    ssh)     printf '       ssh worker on %s -- its Kubernetes will be wiped, too\n' "$WORKER_HOST" ;;
    hetzner) printf '       Hetzner worker -- creates (and deletes) a PAID server\n' ;;
esac

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

POOL=""
if [ -n "$WORKER_MODE" ]; then
    step "worker pool in ocp.yaml ($WORKER_MODE)"
    if [ "$WORKER_MODE" = ssh ]; then
        host_ssh "$WORKER_HOST" true >/dev/null 2>&1 \
            || fail "cannot ssh root@$WORKER_HOST with $SSH_KEY -- the worker is joined with the same key as the control plane"
        POOL="$(helper config /ocp/ocp.yaml --mode ssh --host "$WORKER_HOST")" || fail "could not add the ssh pool"
    else
        POOL="$(helper config /ocp/ocp.yaml --mode hetzner \
            ${OCP_SMOKE_HETZNER_SERVER_TYPE:+--server-type "$OCP_SMOKE_HETZNER_SERVER_TYPE"} \
            ${OCP_SMOKE_HETZNER_LOCATION:+--location "$OCP_SMOKE_HETZNER_LOCATION"})" || fail "could not add the hetzner pool"
    fi
    expect "$(cat "$WORK/ocp.yaml")" "name: $POOL" "ocp.yaml has the worker pool $POOL"
fi

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

step "OCPNode lease against the live API server (xt/lease-409.t)"
lease_out="$(docker run --rm -v "$WORK":/ocp -v "$REPO":/src:ro -w /src \
    -e OCP_SMOKE_KUBECONFIG=/ocp/smoke.kubeconfig --entrypoint prove "$IMAGE" -I/src/lib -v xt/lease-409.t 2>&1)" \
    || { printf '%s\n' "$lease_out"; fail "xt/lease-409.t failed"; }
printf '%s\n' "$lease_out" | tail -8
expect "$lease_out" 'Result: PASS' "two reconcilers cannot hold the lease together"

if [ -n "$WORKER_MODE" ]; then
    step "worker joins ($WORKER_MODE)"
    # `apply` drives the worker (robocop or the CLI); wait for the CR to say
    # so rather than trust its exit code, and poll the Kubernetes API only --
    # no SSH, no PIN.
    node_name=""; node_phase=""; k8s_name=""; node_host=""
    deadline=$((SECONDS + WORKER_TIMEOUT))
    while :; do
        row="$(ocp node ls --json 2>/dev/null | helper pick --pool "$POOL" || true)"
        IFS=$'\t' read -r node_name node_phase k8s_name node_host <<<"$row"
        [ "$node_phase" != Ready ] || break
        [ "$node_phase" != Failed ] || { ocp node ls 2>&1; fail "the worker OCPNode went Failed"; }
        [ "$SECONDS" -lt "$deadline" ] || { ocp node ls 2>&1; fail "worker not Ready after ${WORKER_TIMEOUT}s (phase '${node_phase:-none}')"; }
        sleep 10
    done
    pass "worker OCPNode $node_name is Ready"
    [ -n "$k8s_name" ] || fail "OCPNode $node_name is Ready but status.kubernetesNodeName is empty -- the name would be guessed"
    pass "status.kubernetesNodeName is $k8s_name"

    wnode_out="$(kube get node "$k8s_name" 2>&1)" || { printf '%s\n' "$wnode_out"; fail "kubectl get node $k8s_name: no such node"; }
    printf '%s\n' "$wnode_out"
    expect "$wnode_out" "^$k8s_name[[:space:]]+Ready[[:space:]]" "Kubernetes has $k8s_name, and it is Ready"
    if [ "$WORKER_MODE" = hetzner ]; then
        hz_count="$(helper hcloud-count --cluster "smoke-$DIST")" || fail "could not list Hetzner servers"
        [ "$hz_count" -ge 1 ] && pass "Hetzner has $hz_count server(s) labelled for smoke-$DIST" \
            || fail "no Hetzner server labelled ocp-cluster=smoke-$DIST while the worker is Ready"
    fi

    step "a pod scheduled onto the worker"
    helper pod --node "$k8s_name" ${POD_IMAGE:+--image "$POD_IMAGE"} | kube_stdin apply -f - >/dev/null \
        || fail "could not create the test pod"
    kube wait --for=condition=Ready pod/smoke-worker-pod --timeout=300s >/dev/null 2>&1 \
        || { kube describe pod smoke-worker-pod 2>&1 | tail -20; fail "the pod pinned to $k8s_name did not become Ready"; }
    pod_node="$(kube get pod smoke-worker-pod -o jsonpath='{.spec.nodeName}')"
    [ "$pod_node" = "$k8s_name" ] && pass "the pod runs on $k8s_name" \
        || fail "the pod runs on '$pod_node', not on $k8s_name"
    kube delete pod smoke-worker-pod --wait=false >/dev/null 2>&1 || true

    step "node rm $node_name"
    ocp node rm "$node_name" >/dev/null 2>"$WORK/node-rm.err" \
        || { cat "$WORK/node-rm.err" >&2; fail "node rm exited non-zero"; }
    pass "node rm exited 0"
    left="$(ocp node ls --json 2>/dev/null | helper pick --pool "$POOL" || true)"
    [ -z "$left" ] && pass "the OCPNode is gone" || fail "the OCPNode is still listed: $left"
    ! kube get node "$k8s_name" >/dev/null 2>&1 && pass "Kubernetes no longer has $k8s_name" \
        || fail "Kubernetes still has the node $k8s_name"
    if [ "$WORKER_MODE" = ssh ]; then
        # rke2-agent inactive is not enough: the unit is gone with the uninstall.
        if host_ssh "$WORKER_HOST" "systemctl is-active --quiet $AGENT_UNIT"; then
            fail "$AGENT_UNIT is still active on $WORKER_HOST after node rm"
        fi
        pass "no active $AGENT_UNIT on $WORKER_HOST"
    else
        # The server is deleted by the provider; give the API a moment.
        hz_count=1
        for _ in 1 2 3 4 5 6; do
            hz_count="$(helper hcloud-count --cluster "smoke-$DIST")" || fail "could not list Hetzner servers"
            [ "$hz_count" -eq 0 ] && break
            sleep 10
        done
        [ "$hz_count" -eq 0 ] && pass "the Hetzner server is gone at the provider" \
            || fail "$hz_count Hetzner server(s) still labelled ocp-cluster=smoke-$DIST after node rm -- PAID, delete by hand"
    fi
fi

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
