# OCP Makefile

# Docker image name
IMAGE ?= raudssus/ocp
TAG ?= latest

# Architectures published by .github/workflows/docker-publish.yml. Kept here so
# a local check covers exactly what CI ships.
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: all build test test-v clean docker-test docker-push docker-release snapshot smoke \
        buildx-setup build-multiarch

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
# result is discarded, nothing is pushed. Publishing is CI's job, and
# docker-push/docker-release need the maintainer's explicit go-ahead.
#
# On an amd64 host the arm64 leg runs under qemu emulation and is roughly an
# order of magnitude slower than native; CI does not pay this, it builds each
# architecture on its own native runner.
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

# Push to Docker Hub
docker-push: build
	docker push $(IMAGE):$(TAG)
	docker push $(IMAGE):latest

# Build and push release with version tag
docker-release: build
	@echo "Building release version $(TAG)"
	docker push $(IMAGE):$(TAG)
	docker push $(IMAGE):latest
	@echo "Released $(IMAGE):$(TAG)"
