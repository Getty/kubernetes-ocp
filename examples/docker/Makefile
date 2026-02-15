# Omni Control Plane - Docker-based Makefile
# No local tools needed - everything runs in Docker!
#
# Usage:
#   make setup              Deploy control plane
#   make add-worker         Add worker node
#   make add-docker         Add Docker node (vast.ai)
#   make status             Show cluster status
#   make shell              Interactive shell

SHELL := /bin/bash

# Load config
-include cluster.env
export

.PHONY: help build setup add-worker add-docker status shell clean

help:
	@echo "Omni Control Plane - Docker Mode"
	@echo ""
	@echo "Usage:"
	@echo "  make build       Build OCP Docker image"
	@echo "  make setup       Deploy control plane"
	@echo "  make add-worker  Add worker (set WORKER_HOST in cluster.env)"
	@echo "  make add-docker  Add Docker node (set DOCKER_HOST in cluster.env)"
	@echo "  make status      Show cluster status"
	@echo "  make shell       Interactive shell in OCP container"
	@echo ""
	@echo "Ad-hoc commands:"
	@echo "  make run CMD='install-control-plane 1.2.3.4 --token=xxx'"

build:
	docker compose build ocp

setup: check-config
	@mkdir -p output
	docker compose run --rm setup
	@echo ""
	@echo "Kubeconfig saved to: ./output/kubeconfig"

add-worker: check-config
ifndef WORKER_HOST
	$(error Set WORKER_HOST in cluster.env or environment)
endif
	docker compose run --rm add-worker

add-docker: check-config
ifndef DOCKER_HOST
	$(error Set DOCKER_HOST in cluster.env or environment)
endif
	docker compose run --rm add-docker

status:
	@docker compose run --rm status

shell:
	@docker compose run --rm shell

# Run arbitrary OCP command
run:
ifndef CMD
	$(error Usage: make run CMD='install-control-plane 1.2.3.4')
endif
	docker compose run --rm ocp "$(CMD)"

clean:
	rm -rf output/
	docker compose down --rmi local

check-config:
	@if [ ! -f cluster.env ]; then \
		echo "ERROR: cluster.env not found"; \
		echo "Run: cp cluster.env.example cluster.env"; \
		exit 1; \
	fi
