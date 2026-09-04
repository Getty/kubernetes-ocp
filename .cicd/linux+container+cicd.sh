#!/usr/bin/env bash
#
# linux+container+cicd.sh — SimpiCI CI/CD entry point for kubernetes-ocp.
#
# SimpiCI selects exactly one script per run by platform+feature and invokes it
# once, in the checked-out workspace, with the normalized event file as $1
# (see simpici TODO "Invocation contract"). This is the `linux` / `container`
# script: it builds the OCP Docker image and publishes it to BOTH registries so
# the artifact survives one of them being offline.
#
#   primary   : GitHub Container Registry  (ghcr.io)  — the promoted source
#   fallback  : Forgejo Container Registry (src.ci)   — always available to us
#
# The build itself is NOT reimplemented here: it delegates to the repo's own
# share/bin/ocp-build-image (build for this machine's arch, tag latest/version/
# git-sha, cache-aware, idempotent). This script's only job is registry login,
# calling that tool once per registry, and mapping the result onto SimpiCI's
# exit contract.
#
# --- SimpiCI contract --------------------------------------------------------
#   cwd     : the exact detached checkout (repo root)
#   $1      : CICD_EVENT_FILE (normalized event JSON) — informational here
#   exit 0  : success (every CONFIGURED registry was published)
#   exit 78 : skipped (no registry credentials supplied — nothing to publish)
#   exit !=0: failure (at least one configured registry failed) — the other
#             registry is still attempted first, so a GitHub outage does not
#             stop the src.ci publish; the log names which target failed.
#
#   Read (set by the SimpiCI runner): CICD_COMMIT, CICD_TAG, CICD_REF,
#   CICD_PLATFORM, CICD_FEATURE, CICD_WORKSPACE, CICD_EVENT_FILE. Only CICD_TAG
#   is consumed directly (a tag push pins the image version); the rest is logged
#   for traceability. ocp-build-image derives the version itself when CICD_TAG
#   is empty.
#
# --- Secret contract (delivered by the SimpiCI dispatcher, simpici k2) --------
# Per-registry credentials arrive as scoped environment variables — kept on the
# dispatcher, handed to the run as env, never on the command line, never logged.
# A registry with no user+token is silently skipped (not every run has both).
#
#   OCP_GHCR_REPO   (default ghcr.io/getty/ocp)   OCP_GHCR_USER   OCP_GHCR_TOKEN
#   OCP_SRCCI_REPO  (default src.ci/getty/ocp)    OCP_SRCCI_USER  OCP_SRCCI_TOKEN
#
# The default repo paths are an assumption to confirm once the registries exist
# (ocp k134): the Forgejo registry namespace on src.ci in particular. Override
# either via the OCP_*_REPO env vars without touching this script.
#
# --- Local testing -----------------------------------------------------------
# Set OCP_CICD_DRY_RUN=1 to print the docker/ocp-build-image actions instead of
# running them (skips login/logout and the real build). Lets the orchestration
# be verified on a host without a working docker daemon or real credentials.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_IMAGE="$REPO_ROOT/share/bin/ocp-build-image"
DRY_RUN="${OCP_CICD_DRY_RUN:-0}"

log()  { printf '[cicd] %s\n' "$*"; }
errl() { printf '[cicd] %s\n' "$*" >&2; }

# Publish to one registry. Args: label, repo, user, token.
# Returns 0 published, 1 failed, 2 skipped (no credentials). Never aborts the
# caller: a failure here must not stop the other registry (the fallback point).
publish_to() {
    local label="$1" repo="$2" user="$3" token="$4"
    local host="${repo%%/*}"     # registry host = everything before the first /
    local -a tag_arg=()
    [[ -n "${CICD_TAG:-}" ]] && tag_arg=( "--tag=$CICD_TAG" )

    if [[ -z "$user" || -z "$token" ]]; then
        log "$label: no credentials ($host) — skipping"
        return 2
    fi

    log "$label: publishing $repo (host $host)"

    if [[ "$DRY_RUN" == "1" ]]; then
        log "$label: [dry-run] docker login $host -u $user --password-stdin"
        log "$label: [dry-run] $BUILD_IMAGE --repo=$repo --push ${tag_arg[*]:-}"
        log "$label: [dry-run] docker logout $host"
        return 0
    fi

    if ! printf '%s' "$token" | docker login "$host" -u "$user" --password-stdin >/dev/null 2>&1; then
        errl "$label: docker login failed for $host"
        return 1
    fi

    local rc=0
    ( cd "$REPO_ROOT" && "$BUILD_IMAGE" --repo="$repo" --push "${tag_arg[@]}" ) || rc=$?
    docker logout "$host" >/dev/null 2>&1 || true

    if [[ "$rc" -ne 0 ]]; then
        errl "$label: ocp-build-image failed (exit $rc)"
        return 1
    fi
    log "$label: published $repo"
    return 0
}

main() {
    local event_file="${1:-${CICD_EVENT_FILE:-}}"
    log "kubernetes-ocp container build"
    log "commit=${CICD_COMMIT:-?} ref=${CICD_REF:-?} tag=${CICD_TAG:-} platform=${CICD_PLATFORM:-?} feature=${CICD_FEATURE:-?}"
    [[ -n "$event_file" ]] && log "event=$event_file"
    [[ "$DRY_RUN" == "1" ]] && log "DRY RUN — no login, no build, no push"

    if [[ ! -x "$BUILD_IMAGE" ]]; then
        errl "build tool not found or not executable: $BUILD_IMAGE"
        exit 1
    fi

    # Every configured registry is attempted; a failure in one never short-
    # circuits the other. Results are aggregated into the SimpiCI exit contract.
    local configured=0 published=0 failed=0

    local -a targets=(
        "GHCR|${OCP_GHCR_REPO:-ghcr.io/getty/ocp}|${OCP_GHCR_USER:-}|${OCP_GHCR_TOKEN:-}"
        "SRCCI|${OCP_SRCCI_REPO:-src.ci/getty/ocp}|${OCP_SRCCI_USER:-}|${OCP_SRCCI_TOKEN:-}"
    )

    local t label repo user token rc
    for t in "${targets[@]}"; do
        IFS='|' read -r label repo user token <<<"$t"
        rc=0
        publish_to "$label" "$repo" "$user" "$token" || rc=$?
        case "$rc" in
            0) configured=$((configured + 1)); published=$((published + 1)) ;;
            1) configured=$((configured + 1)); failed=$((failed + 1)) ;;
            2) : ;;   # skipped, not configured
        esac
    done

    log "summary: configured=$configured published=$published failed=$failed"

    if [[ "$configured" -eq 0 ]]; then
        log "no registry credentials supplied — nothing to publish"
        exit 78
    fi
    if [[ "$failed" -gt 0 ]]; then
        errl "at least one configured registry failed"
        exit 1
    fi
    log "done"
    exit 0
}

main "$@"
