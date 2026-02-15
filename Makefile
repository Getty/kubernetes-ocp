# OCP Makefile

.PHONY: all build test test-v clean docker-test

all: build

# Build Docker image
build:
	docker build -t ocp .

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
	docker run --rm ocp --help
	@echo "Docker image works!"
