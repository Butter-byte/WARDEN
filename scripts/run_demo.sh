#!/usr/bin/env bash
# Run the controller. Run this FIRST, in its own terminal, and leave it running.
# --wsapi-host 127.0.0.1 keeps the Module 4 quarantine REST endpoint local.
set -e
cd "$(dirname "$0")/.."
echo "[*] Starting Ryu controller (ctrl+C to stop)..."
ryu-manager --wsapi-host 127.0.0.1 --wsapi-port 8080 controller/vlan_controller.py