# OCP Makefile

# Docker image name
IMAGE ?= raudssus/ocp
TAG ?= latest

.PHONY: all build test test-v clean docker-test docker-push docker-release snapshot

all: build

# Build Docker image
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
