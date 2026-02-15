#!/usr/bin/env bash
# Omni Control Plane - Quick Setup Script
# This script sets up OCP as a git submodule and prepares your repo

set -euo pipefail

echo "=== Omni Control Plane Setup ==="

# Check if we're in a git repo
if ! git rev-parse --git-dir &>/dev/null; then
    echo "Initializing git repository..."
    git init
fi

# Add OCP as submodule
if [ ! -d "vendor/ocp" ]; then
    echo "Adding OCP as git submodule..."
    mkdir -p vendor
    # Replace with your actual OCP repo URL
    git submodule add https://github.com/YOUR_ORG/ocp.git vendor/ocp
else
    echo "OCP already present in vendor/ocp"
fi

# Copy example files
if [ ! -f "cluster.env" ]; then
    echo "Creating cluster.env from example..."
    cp vendor/ocp/examples/standalone/cluster.env.example cluster.env
    echo "IMPORTANT: Edit cluster.env with your settings"
fi

if [ ! -f "Makefile" ]; then
    echo "Creating Makefile..."
    cp vendor/ocp/examples/standalone/Makefile Makefile
fi

# Create .gitignore
if ! grep -q "kubeconfig" .gitignore 2>/dev/null; then
    echo "Adding kubeconfig to .gitignore..."
    echo -e "\n# OCP\nkubeconfig\ncluster.env" >> .gitignore
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit cluster.env with your server details"
echo "  2. Run: make setup"
echo "  3. Run: make add-workers (if you have workers)"
echo ""
echo "Available commands:"
echo "  make help"
