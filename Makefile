# OCP Makefile

# Docker image name
IMAGE ?= raudssus/ocp
TAG ?= latest

# What the test targets run. Override for a single file:
#   make test TESTS=t/33-registry-manifests.t
TESTS ?= t/

# The suite inside the image, i.e. against the dependency stand that
# cpanfile.snapshot pins and the image installs, with the working tree mounted
# at /src.
#
# Only the dependencies come from the image; lib/, bin/ and share/ all come
# from the mount. `prove -l` puts /src/lib on @INC, and OCP::Share resolves
# share/ next to the running test, so a test file under /src/t reaches
# /src/share (ADR 0023). Verified: OCP.pm -> /src/lib/OCP.pm, share ->
# /src/share, Kubernetes::REST -> the image's local-lib.
#
# Mounted read-only: the suite writes only into File::Temp directories, and a
# mount that cannot be written cannot be dirtied by a test that gets that
# wrong. It also makes the uid mismatch between the image's `ocp` user and the
# checkout's owner a non-issue.
#
# $(CURDIR), not $(PWD): make knows its own directory even under `make -C`,
# the inherited PWD does not.
DOCKER_PROVE = docker run --rm -v $(CURDIR):/src:ro -w /src \
	--entrypoint prove $(IMAGE):$(TAG)

.PHONY: all build test test-v test-host clean docker-test docker-push docker-release \
        snapshot smoke build-image vendor

all: build

# Build Docker image for the architecture of this machine. vendor/ORDER is an
# order-only prerequisite: a fresh checkout runs `make vendor` once, after
# that the build reuses vendor/ as it is. Refresh it with `make vendor`.
build: | vendor/ORDER
	docker build -t $(IMAGE):$(TAG) -t $(IMAGE):latest .

# ─── vendor: unreleased sibling dists into the image (k222) ──────────────────
# Only the local state counts: a fix that sits in a sibling dist but is not on
# CPAN yet still belongs in the image. VENDOR names sibling checkouts under
# SIBLINGS_DIR, in install order (a dist before the ones that need it).
# `make vendor` dzil-builds each one into vendor/ and writes the tarball names
# to vendor/ORDER, one per line; the Dockerfile installs them in that order,
# ahead of the cpanfile.snapshot pass, into the same contained local-lib.
#
# Each sibling is built from its committed HEAD in a throwaway clone, never in
# its own working tree: uncommitted work is not vendored (a warning says so),
# and no tarball or .build/ lands in a checkout another agent may be using.
#
# Back to CPAN-only: `make vendor VENDOR=` leaves an empty vendor/ (.keep and
# an empty ORDER), and the Dockerfile then installs nothing from it.
# Nothing pending: IO::K8s 1.110, Rex::GPU 0.004 and Crypt::Age 0.005 are on
# CPAN (2026-10-01) and pinned in cpanfile.snapshot.
VENDOR ?=
SIBLINGS_DIR ?= ..

vendor/ORDER:
	@$(MAKE) --no-print-directory vendor

vendor:
	@rm -rf $(CURDIR)/vendor && mkdir -p $(CURDIR)/vendor
	@touch $(CURDIR)/vendor/.keep $(CURDIR)/vendor/ORDER
	@set -e; for s in $(VENDOR); do \
	  d="$(SIBLINGS_DIR)/$$s"; \
	  if ! git -C "$$d" rev-parse --git-dir >/dev/null 2>&1; then \
	    echo "[vendor] $$s: no git checkout at $$d" >&2; exit 1; \
	  fi; \
	  if [ -n "$$(git -C "$$d" status --porcelain --untracked-files=no)" ]; then \
	    echo "[vendor] $$s: uncommitted changes in $$d are NOT vendored" >&2; \
	  fi; \
	  w="$$(mktemp -d)"; \
	  git clone -q "$$d" "$$w/$$s"; \
	  echo "[vendor] dzil build $$s ($$(git -C "$$w/$$s" describe --tags --always))"; \
	  ( cd "$$w/$$s" && dzil build >"$$w/dzil.log" 2>&1 ) \
	    || { cat "$$w/dzil.log" >&2; rm -rf "$$w"; exit 1; }; \
	  tgz="$$(cd "$$w/$$s" && ls *.tar.gz)"; \
	  mv "$$w/$$s/$$tgz" "$(CURDIR)/vendor/"; \
	  echo "$$tgz" >> "$(CURDIR)/vendor/ORDER"; \
	  rm -rf "$$w"; \
	done
	@echo "[vendor] install order:"; sed 's/^/  /' $(CURDIR)/vendor/ORDER

# Run the suite against the pinned dependencies inside the image. THIS is the
# binding result — the same perl and the same module versions the release
# ships, so a green here means the artifact is green.
#
# It goes through `build` on purpose: an image that has not been rebuilt since
# cpanfile.snapshot moved is the same lie as a host that was never updated for
# it, one layer further out. Fully cached that costs about a second; when the
# pin has actually moved it costs a dependency install, which is the point.
test: build
	$(DOCKER_PROVE) -l $(TESTS)

# Same run, verbose
test-v: build
	$(DOCKER_PROVE) -lv $(TESTS)

# The suite against whatever CPAN happens to be installed on this machine.
# Fast and fine while iterating, but its result does NOT bind: it is neither
# the perl nor the module versions that ship. On 2026-08-15 this run went from
# green to red between morning and evening without a line of the repo
# changing, because a newer Kubernetes::REST than the snapshot pins had been
# installed on the host (k79). The reverse is worse and silent: a host
# that stays on an old version keeps this green while the image is broken.
test-host:
	prove -l $(TESTS)

# Clean build artifacts
clean:
	docker rmi ocp 2>/dev/null || true

# Regenerate cpanfile.snapshot inside Docker (never on host).
# Installs system deps (libssh-dev etc) + carton, then runs carton install
# with the project mounted so the refreshed snapshot lands on the host.
#
# Runs the container as root because apt-get install needs it, then chowns
# the files carton writes (cpanfile.snapshot + local/) back to the host
# uid:gid so the operator can edit them without sudo. The host ids are
# passed in as env vars; chown accepts numeric ids that are not in the
# container's /etc/passwd, so this works on a clean tree without a
# matching user being created.
#
# Not handled here: local/ that is already root-owned from older runs.
# Clean that up with `sudo chown -R $$UID:$$GID local/` before re-running.
snapshot:
	docker run --rm -v $(PWD):/work -w /work \
	  -e HOST_UID=$(shell id -u) -e HOST_GID=$(shell id -g) \
	  perl:5.42.3-slim-trixie bash -c \
	  'apt-get update -qq && apt-get install -y --no-install-recommends \
	    libssh-dev libssl-dev libexpat1-dev zlib1g-dev \
	    build-essential pkg-config && \
	   cpanm --notest Carton && carton install && \
	   chown -R "$$HOST_UID:$$HOST_GID" /work/cpanfile.snapshot /work/local'

# Check that the built image starts and its entrypoint answers. This is a
# smoke test of the artifact, NOT a run of the suite — `make test` is that.
docker-test: build
	docker run --rm $(IMAGE):$(TAG) --help
	@echo "Docker image works!"

# Full bootstrap against a real machine. Wipes the cluster on SMOKE_HOST,
# which is why there is no default:
#   make smoke SMOKE_HOST=reuben.cihq [SMOKE_DIST=k3s] [SMOKE_KEEP=1]
smoke:
	@xt/smoke.sh

# Build the image for this machine's architecture and push it to Docker Hub.
# Needs the maintainer's explicit go-ahead.
docker-push: build
	docker push $(IMAGE):$(TAG)
	docker push $(IMAGE):latest

# Build the image for this machine's architecture and push it to Docker Hub
# under its version tag. Needs the maintainer's explicit go-ahead.
docker-release: build
	docker push $(IMAGE):$(TAG)
	docker push $(IMAGE):latest
	@echo "Released $(IMAGE):$(TAG)"

# Build and push the OCP image using share/bin/ocp-build-image. The script
# runs standalone (CI does not need `make`), accepts overrides via --repo
# and --tag, and prints rather than executes under --dry-run. This
# target does NOT need maintainer go-ahead — the script pushes by default,
# so `--push` here is explicit (call the script directly with `--no-push`
# for a local-only build).
build-image: | vendor/ORDER
	share/bin/ocp-build-image --push
