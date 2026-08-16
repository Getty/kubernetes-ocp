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
        snapshot smoke build-image

all: build

# Build Docker image for the architecture of this machine
build:
	docker build -t $(IMAGE):$(TAG) -t $(IMAGE):latest .

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
# installed on the host (karr #79). The reverse is worse and silent: a host
# that stays on an old version keeps this green while the image is broken.
test-host:
	prove -l $(TESTS)

# Clean build artifacts
clean:
	docker rmi ocp 2>/dev/null || true

# Regenerate cpanfile.snapshot inside Docker (never on host).
# Installs system deps (libssh-dev etc) + carton, then runs carton install
# with the project mounted so the refreshed snapshot lands on the host.
snapshot:
	docker run --rm -v $(PWD):/work -w /work perl:5.42 bash -c \
	  "apt-get update -qq && apt-get install -y --no-install-recommends \
	    libssh-dev libssl-dev libexpat1-dev zlib1g-dev \
	    build-essential pkg-config && \
	   cpanm --notest Carton && carton install"

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
build-image:
	share/bin/ocp-build-image --push
