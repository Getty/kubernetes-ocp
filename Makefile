# OCP Makefile

# Docker image name
IMAGE ?= raudssus/ocp
TAG ?= latest

.PHONY: all build test test-v clean docker-test docker-push docker-release

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
