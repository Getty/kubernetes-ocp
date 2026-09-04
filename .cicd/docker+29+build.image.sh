#!/bin/sh
#
# docker+29+build.image.sh — SimpiCI `build` phase for kubernetes-ocp.
#
# SimpiCI derives everything from this file's name: it runs in
# docker.io/library/docker:29, during the `build` phase, as job `image`.
# Scripts sharing a phase run concurrently; the next phase starts only once
# every job in this one has finished. Order: prepare build test package
# publish deploy.
#
# This job's contract is narrow on purpose: prove the image builds. It pushes
# nothing — publishing is `docker+29+publish.image.sh`, in a later phase, which
# is the only place SimpiCI hands out registry credentials.
#
# The build is NOT reimplemented here. share/bin/ocp-build-image owns it: it
# builds for this machine's architecture and writes the latest/version/git-sha
# tag triple. This script only prepares the container for it.
#
# Environment SimpiCI supplies (build phase): CICD_IMAGE_REPOSITORY, CICD_REF,
# CICD_BRANCH, CICD_TAG, CICD_COMMIT, CICD_PHASE, CICD_JOB, CICD_WORKSPACE,
# CICD_EVENT_FILE, CICD_OUTPUT, CICD_ARTIFACTS — plus the host's Docker socket,
# mounted for the build and publish phases only.
#
set -eu

# The name the rest of the project agrees on (Makefile IMAGE, DeployImage's
# $DEFAULT_REPO, the robocop manifests, xt/smoke.sh — t/66 guards that). Used
# when the caller names no image, so a bare runner still builds something real.
repository="$(printf '%s' "${CICD_IMAGE_REPOSITORY:-raudssus/ocp}" | tr '[:upper:]' '[:lower:]')"

# The official docker image is Alpine and ships no bash; ocp-build-image is a
# bash script (arrays, [[ ]]). Cheaper and more honest than rewriting a tested
# tool in POSIX sh, or carrying our own CI image just for this.
command -v bash >/dev/null 2>&1 || apk add --no-cache bash >/dev/null

# The workspace is bind-mounted from the runner and owned by another uid, which
# git refuses to read as "dubious ownership" — and ocp-build-image asks git for
# the version and the short sha. Without this the image would silently get
# tagged develop/unknown.
# SimpiCI sets CICD_WORKSPACE; the default keeps the script honest if it is
# ever run without it.
workspace="${CICD_WORKSPACE:-/workspace}"
git config --global --add safe.directory "$workspace"

# A tag push pins the version; otherwise ocp-build-image works it out itself.
set -- --repo="$repository" --no-push
[ -n "${CICD_TAG:-}" ] && set -- "$@" "--tag=$CICD_TAG"

echo "[cicd] build ${CICD_JOB:-image}: $repository (commit ${CICD_COMMIT:-?})"
exec "$workspace/share/bin/ocp-build-image" "$@"
