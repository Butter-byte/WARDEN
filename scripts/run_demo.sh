#!/usr/bin/env bash
# Run the controller. Run this FIRST, in its own terminal, and leave it running.
set -e
cd "$(dirname "$0")/.."
echo "[*] Starting Ryu controller (ctrl+C to stop)..."
ryu-manager controller/vlan_controller.py
