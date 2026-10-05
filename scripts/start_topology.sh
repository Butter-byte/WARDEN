#!/usr/bin/env bash
# Run this SECOND, in a second terminal, AFTER run_demo.sh (the controller) is already running.
set -e
cd "$(dirname "$0")/.."
echo "[*] Starting Mininet topology (needs sudo)..."
sudo python3 topology/topo.py
