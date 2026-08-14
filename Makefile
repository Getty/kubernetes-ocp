# OCP Makefile

# Docker image name
IMAGE ?= raudssus/ocp
TAG ?= latest

# Architectures published by the docker-push/docker-release targets below.
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: all build test test-v clean docker-test docker-push docker-release snapshot smoke \
        buildx-setup build-multiarch build-image

all: build

# Build Docker image
build:
	docker build -t $(IMAGE):$(TAG) -t $(IMAGE):latest .

# One-time host prep for cross-architecture builds: register the qemu binfmt
# handlers and create a docker-container builder (the default "docker" driver
# cannot build for a foreign architecture).
buildx-setup:
	docker run --privileged --rm tonistiigi/binfmt --install arm64
	docker buildx create --name ocp-multiarch --driver docker-container --use || \
	  docker buildx use ocp-multiarch

# Verify the image builds for every published architecture. BUILD ONLY — the
# result is discarded, nothing is pushed. Run this before docker-push/
# docker-release to sanity-check both architectures compile without actually
# pushing; docker-push/docker-release themselves need the maintainer's
# explicit go-ahead.
#
# On an amd64 host the arm64 leg runs under qemu emulation and is roughly an
# order of magnitude slower than native.
build-multiarch: buildx-setup
	docker buildx build --builder ocp-multiarch --platform $(PLATFORMS) .

# Run tests locally (uses CPAN modules)
test:
	prove -l t/

# Run tests verbose
test-v:
	prove -lv t/

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

# Quick test run with Docker
docker-test: build
	docker run --rm $(IMAGE):$(TAG) --help
	@echo "Docker image works!"

# Full bootstrap against a real machine. Wipes the cluster on SMOKE_HOST,
# which is why there is no default:
#   make smoke SMOKE_HOST=reuben.cihq [SMOKE_DIST=k3s] [SMOKE_KEEP=1]
smoke:
	@xt/smoke.sh

# Build and push to Docker Hub, multi-arch, in one buildx run.
docker-push: buildx-setup
	docker buildx build --builder ocp-multiarch --platform $(PLATFORMS) \
	  -t $(IMAGE):$(TAG) -t $(IMAGE):latest --push .

# Build and push release with version tag, multi-arch, in one buildx run.
docker-release: buildx-setup
	@echo "Building release version $(TAG)"
	docker buildx build --builder ocp-multiarch --platform $(PLATFORMS) \
	  -t $(IMAGE):$(TAG) -t $(IMAGE):latest --push .
	@echo "Released $(IMAGE):$(TAG)"
# Build and push the OCP image using share/bin/ocp-build-image. The script
# runs standalone (CI does not need `make`), accepts overrides via --repo,
# --platforms, --tag, and prints rather than executes under --dry-run. This
# target does NOT need maintainer go-ahead — the script pushes by default,
# so `--push` here is explicit (call the script directly with `--no-push`
# for a local-only build).
build-image:
	share/bin/ocp-build-image --push
