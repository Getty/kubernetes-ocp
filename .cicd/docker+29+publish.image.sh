#!/bin/sh
#
# docker+29+publish.image.sh — SimpiCI `publish` phase for kubernetes-ocp.
#
# Runs in docker.io/library/docker:29 during the `publish` phase, after every
# `build` job succeeded. `publish` and `deploy` are the only phases SimpiCI
# gives registry credentials to, which is why the push lives here and not
# alongside the build.
#
# One registry per run, named by the caller: SimpiCI passes exactly one
# CICD_REGISTRY / _USER / _PASSWORD triple into the container. Publishing the
# same image to several registries is therefore several runs — see
# .github/workflows/ci.yml, which defines one job per registry.
#
# Exit 78 means "nothing to do here" and SimpiCI treats it as a skip, not a
# failure. This job uses it for every revision we deliberately do not publish
# from, so a pull request stays green on the strength of its build alone.
#
# Publish policy lives here, in the repository, under review — never in
# workflow YAML: `main` and tags publish, nothing else does.
#
set -eu

if [ "${CICD_PUBLISH_IMAGE:-false}" != true ]; then
    echo "[cicd] publish: caller disabled publishing — skipping"
    exit 78
fi
if [ "${CICD_BRANCH:-}" != main ] && [ -z "${CICD_TAG:-}" ]; then
    echo "[cicd] publish: not main and not a tag (ref ${CICD_REF:-?}) — skipping"
    exit 78
fi
# Publishing was in scope but the runner handed us no credentials. That is
# runner configuration, not a bad commit: say so on stderr and skip, rather
# than failing a build that is otherwise fine.
if [ -z "${CICD_REGISTRY_USER:-}" ] || [ -z "${CICD_REGISTRY_PASSWORD:-}" ]; then
    echo "[cicd] publish: no registry credentials in the environment — skipping" >&2
    exit 78
fi

registry="${CICD_REGISTRY:-docker.io}"
repository="$(printf '%s' "${CICD_IMAGE_REPOSITORY:-raudssus/ocp}" | tr '[:upper:]' '[:lower:]')"

command -v bash >/dev/null 2>&1 || apk add --no-cache bash >/dev/null
# SimpiCI sets CICD_WORKSPACE; the default keeps the script honest if it is
# ever run without it.
workspace="${CICD_WORKSPACE:-/workspace}"
git config --global --add safe.directory "$workspace"

echo "[cicd] publish ${CICD_JOB:-image}: $repository via $registry"

# --password-stdin: the token never reaches a command line and never a log.
printf '%s' "$CICD_REGISTRY_PASSWORD" \
    | docker login "$registry" --username "$CICD_REGISTRY_USER" --password-stdin

# Same tool as the build phase, so the tag triple cannot drift between the two.
# The build itself is a cache hit against what the build phase just produced on
# this same daemon.
set -- --repo="$repository" --push
[ -n "${CICD_TAG:-}" ] && set -- "$@" "--tag=$CICD_TAG"

# `|| status=$?` rather than a bare call plus $?: under `set -e` a failing
# build would exit here and the logout below would never run.
status=0
"$workspace/share/bin/ocp-build-image" "$@" || status=$?

docker logout "$registry" >/dev/null 2>&1 || true
exit "$status"
