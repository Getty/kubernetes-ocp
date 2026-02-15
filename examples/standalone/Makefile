# Omni Control Plane - Standalone Makefile
# Usage:
#   make setup        - Deploy control plane
#   make add-workers  - Add all workers from cluster.env
#   make status       - Show cluster status
#   make kubeconfig   - Fetch kubeconfig

SHELL := /bin/bash
.ONESHELL:

# Load config
-include cluster.env

# OCP location (adjust if using different path)
OCP_PATH ?= ./vendor/ocp

# Export for scripts
export OCP_SSH_KEY=$(SSH_KEY)
export OCP_K3S_VERSION=$(K3S_VERSION)
export OCP_K3S_EXTRA_ARGS=$(K3S_EXTRA_ARGS)
export OCP_K3S_NODE_LABELS=$(NODE_LABELS)

.PHONY: help setup add-workers add-docker-workers status kubeconfig clean

help:
	@echo "Omni Control Plane - Cluster Management"
	@echo ""
	@echo "Usage:"
	@echo "  make setup            Deploy control plane"
	@echo "  make add-workers      Add worker nodes from cluster.env"
	@echo "  make add-docker       Add Docker nodes from cluster.env"
	@echo "  make status           Show cluster status"
	@echo "  make kubeconfig       Fetch kubeconfig"
	@echo "  make clean            Remove local kubeconfig"
	@echo ""
	@echo "Single node operations:"
	@echo "  make add-worker HOST=1.2.3.4"
	@echo "  make add-docker-node HOST=vast-host MODE=tunnel"

setup: check-config
	@echo "=== Deploying Control Plane ==="
	$(OCP_PATH)/bin/install-control-plane $(CONTROL_PLANE_HOST) \
		--token=$(K3S_TOKEN) \
		--kubeconfig=./kubeconfig

add-workers: check-config check-kubeconfig
	@echo "=== Adding Worker Nodes ==="
	@for host in $(WORKER_HOSTS); do \
		echo "Adding $$host..."; \
		$(OCP_PATH)/bin/add-node $$host \
			--server=https://$(CONTROL_PLANE_HOST):6443 \
			--token=$(K3S_TOKEN); \
	done

add-docker: check-config check-kubeconfig
	@echo "=== Adding Docker Nodes ==="
	@for host in $(DOCKER_HOSTS); do \
		echo "Adding $$host..."; \
		$(OCP_PATH)/bin/add-docker-node $$host \
			--token=$(K3S_TOKEN) \
			--mode=tunnel \
			--control-plane=$(CONTROL_PLANE_HOST); \
	done

# Single node operations
add-worker: check-config
ifndef HOST
	$(error HOST is required. Usage: make add-worker HOST=1.2.3.4)
endif
	$(OCP_PATH)/bin/add-node $(HOST) \
		--server=https://$(CONTROL_PLANE_HOST):6443 \
		--token=$(K3S_TOKEN) \
		$(if $(LABELS),--labels=$(LABELS))

add-docker-node: check-config
ifndef HOST
	$(error HOST is required. Usage: make add-docker-node HOST=vast-host)
endif
	$(OCP_PATH)/bin/add-docker-node $(HOST) \
		--token=$(K3S_TOKEN) \
		--mode=$(or $(MODE),tunnel) \
		--control-plane=$(CONTROL_PLANE_HOST) \
		$(if $(NAME),--node-name=$(NAME)) \
		$(if $(LABELS),--labels=$(LABELS))

status: check-kubeconfig
	@echo "=== Cluster Status ==="
	@KUBECONFIG=./kubeconfig kubectl get nodes -o wide
	@echo ""
	@KUBECONFIG=./kubeconfig kubectl get pods -A

kubeconfig: check-config
	@echo "=== Fetching Kubeconfig ==="
	@source $(OCP_PATH)/lib/common.sh && \
		ocp_get_kubeconfig $(CONTROL_PLANE_HOST) ./kubeconfig
	@echo "Saved to ./kubeconfig"

clean:
	rm -f ./kubeconfig

# Internal targets
check-config:
	@if [ ! -f cluster.env ]; then \
		echo "ERROR: cluster.env not found"; \
		echo "Copy cluster.env.example to cluster.env and configure"; \
		exit 1; \
	fi

check-kubeconfig:
	@if [ ! -f ./kubeconfig ]; then \
		echo "ERROR: kubeconfig not found. Run 'make setup' first"; \
		exit 1; \
	fi
