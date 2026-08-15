# OCP Makefile

# Docker image name
IMAGE ?= raudssus/ocp
TAG ?= latest

.PHONY: all build test test-v clean docker-test docker-push docker-release snapshot smoke \
        build-image

all: build

# Build Docker image for the architecture of this machine
build:
	docker build -t $(IMAGE):$(TAG) -t $(IMAGE):latest .

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
