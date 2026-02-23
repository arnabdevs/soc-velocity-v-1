#!/usr/bin/env bash
# exit on error
set -o errexit

# Install Python dependencies
pip install -r requirements.txt

# Nmap is often unavailable in standard build environments.
# On Render, we can use the 'Native Runtimes' or a custom build script
# if using a Dockerfile. For standard Flask, we rely on the system environment.
# Note: If deploying to a VPS, run 'sudo apt-get install nmap -y'

echo "Build complete."
