# WARDEN — Context-Aware Dynamic VLAN Segmentation using SDN

### Prototype scope: Module 1 (Topology) + Module 2 (Dynamic VLAN Assignment, incl. live mobility demo) + Module 4 (Anomaly Detection and Automated Quarantine)

## 1. Environment setup

Ryu is unmaintained and can break on Python 3.10+ due to an `eventlet` incompatibility. A dedicated Python 3.8/3.9 virtual environment is recommended. On Windows, use WSL2 with Ubuntu 20.04; on Linux, check your Python version first with `python3 --version`.

```bash
# 1. System packages (Mininet + Open vSwitch)
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch python3-pip python3-venv

# 2. If your default Python is 3.10+, install Python 3.8 alongside it
sudo apt-get install -y python3.8 python3.8-venv

# 3. Create an isolated virtual environment for Ryu
python3.8 -m venv ~/ryu-venv
source ~/ryu-venv/bin/activate

# 4. Install Ryu with the compatible eventlet version
pip install --upgrade pip
pip install ryu eventlet==0.30.1

# 5. Sanity checks
ryu-manager --version
sudo mn --test pingall
```

If `apt-get install mininet` is unavailable on your distribution, consider using the official pre-built Mininet VM with Open vSwitch already configured.

## 2. Project layout

```text
WARDEN/
├── controller/
│   ├── vlan_controller.py     # Ryu app: packet handling, flow installation, VLAN tagging, quarantine API
│   ├── vlan_manager.py        # MAC -> role -> VLAN policy lookup
│   ├── alert_store.py         # Alert and event store
│   ├── state_view.py          # Builds the /state API payload
│   └── mobility_manager.py    # Tracks host locations and detects moves
├── topology/
│   ├── topo.py                # Mininet topology; h1 has a standby link to s2
│   └── anomaly_test.py        # Automated end-to-end anomaly and response tests
├── config/
│   ├── vlan_policy.json       # MAC -> role -> VLAN policy table
│   └── switch_ports.json      # Trunk/access port configuration
├── scripts/
│   ├── run_demo.sh            # Launches the Ryu controller
│   ├── start_topology.sh      # Launches the interactive Mininet topology
│   └── demo_commands.txt      # Interactive demo command sequence
├── detection/
│   ├── engine.py              # Detection logic: six anomaly detectors
│   ├── sensor.py              # Scapy sensor; reports detections and syncs quarantine state
│   ├── simulate_attacks.py    # Generates traffic for each anomaly scenario
│   └── README.md              # Detection setup, detectors, API, and tests
├── dashboard/
│   └── index.html             # Dashboard at http://127.0.0.1:8080/
├── tests/                     # Pytest unit tests; no Mininet required
└── README.md
```

## 3. Running the interactive demo

Use this workflow when demonstrating VLAN assignment, mobility, anomaly detection, and quarantine manually.

You need three terminals and a browser open at [http://127.0.0.1:8080/](http://127.0.0.1:8080/).

### Terminal 1 — Controller

```bash
source ~/ryu-venv/bin/activate
bash scripts/run_demo.sh
```

Leave this running. The controller handles OpenFlow events, VLAN assignment, and the REST API used by the dashboard and anomaly-response system.

### Terminal 2 — Interactive topology

```bash
bash scripts/start_topology.sh
```

This opens the `mininet>` CLI. Follow `scripts/demo_commands.txt` to demonstrate connectivity across switches, cross-VLAN isolation, and host mobility.

### Terminal 3 — Anomaly sensor

```bash
sudo ~/ryu-venv/bin/python3 detection/sensor.py --iface s1-eth3
```

The sensor captures traffic on the switch trunk interface, runs the anomaly detectors, reports alerts to the controller, and synchronizes quarantine state.

**Sensor lifecycle:** The sensor now waits for the configured interface if it does not exist yet and retries packet capture if the interface disappears. This supports topology startup and teardown without immediately terminating the sensor process.

To shut down the interactive topology, enter `exit` in the Mininet CLI and then run:

```bash
sudo mn -c
```

## 4. Automated end-to-end anomaly testing

The automated test is separate from the interactive demo. It creates its own Mininet topology, executes attack simulations, checks detection and quarantine behavior through the controller API, verifies connectivity, and cleans up the topology.

**Important:** Do not start `scripts/start_topology.sh` for this workflow. The test creates its own topology, so an additional interactive topology can cause conflicts.

### Terminal 1 — Controller

```bash
bash scripts/run_demo.sh
```

Keep the controller running.

### Terminal 2 — Sensor

```bash
sudo ~/ryu-venv/bin/python3 detection/sensor.py --iface s1-eth3
```

Keep the sensor running. It waits for `s1-eth3` to appear when the test creates the topology and retries capture if the interface disappears during cleanup.

### Terminal 3 — Automated test

From the project root, run:

```bash
sudo python3 topology/anomaly_test.py
```

The test uses the system Python for Mininet. Attack simulations run inside Mininet hosts using the Ryu virtual environment's Python interpreter. The default expected path is `/home/$SUDO_USER/ryu-venv/bin/python3`.

If your virtual environment is located elsewhere, pass its interpreter explicitly:

```bash
sudo python3 topology/anomaly_test.py \
  --venv-python /path/to/ryu-venv/bin/python3
```

### What the automated test checks

| Test scenario | Expected result |
|---|---|
| Clean traffic | No unexpected alerts or quarantines |
| ARP spoofing | Alert, quarantine, selective isolation, and recovery |
| Port scan | Alert, quarantine, selective isolation, and recovery |
| VLAN hopping | Alert, quarantine, selective isolation, and recovery |
| MAC flooding | Alert without automatic quarantine |
| Traffic-rate burst | Alert without automatic quarantine |
| Unauthorized device | Alert without automatic quarantine |

For the quarantine scenarios, the test verifies that the targeted host loses connectivity, that the unaffected VLAN remains operational, and that connectivity returns after release.

The script prints an individual `PASS` or `FAIL` for each check, followed by a summary such as:

```text
========== 23/23 checks passed ==========
```

A successful run exits with status `0`; a run with failed checks exits with status `1`.

**Latest recorded result:** `23/23 checks passed` on 20 October 2026. This result covers the six tested attack scenarios and the clean-traffic checks in that run; it is not a guarantee against every possible attack or timing condition.

### Cleanup

The automated test releases the test hosts' quarantine state, clears alerts, and stops its own Mininet topology in its cleanup block. The sensor process is separate and may continue waiting for the trunk interface after the topology has stopped.

Stop the sensor and controller with `Ctrl+C` when finished. If Mininet or OVS resources remain after an interrupted run, use:

```bash
sudo mn -c
```

Before rerunning, ensure the previous test's topology has been cleaned up and the controller is still available at `http://127.0.0.1:8080`.

## 5. How it maps to the review document

| Review document section | What this prototype demonstrates |
|---|---|
| Proposed Methodology, Phase 1 | `topology/topo.py` — multi-switch OpenFlow topology |
| Proposed Methodology, Phase 2 | `controller/vlan_controller.py` — policy-driven VLAN assignment, decoupled from physical port |
| Existing Work Gap | `config/vlan_policy.json` — assignment is driven by identity (MAC/role), not port |
| Proposed Methodology, Phase 3 — detection | `detection/engine.py` and `detection/sensor.py` — six anomaly detectors, decoupled from the control plane |
| Proposed Methodology, Phase 3 — response | Controller REST API — automated quarantine to VLAN 99 and release, visible in `dashboard/index.html` |
| Phase 3 — validation | `topology/anomaly_test.py` — automated checks for detection, isolation, unaffected-VLAN connectivity, and recovery |
| Phases 4–5 (extended) | Not built yet: load-aware assignment and predictive mobility |

## 6. Known limitations

- **Identity:** VLAN policy is keyed by MAC address; real device authentication has not been implemented.
- **Topology scale:** Two switches and four hosts demonstrate the concept without unnecessary topology complexity. Extending the topology requires corresponding policy and port-configuration changes.
- **Flow management:** Persistent flow cleanup and aging have not been extensively tuned; `idle_timeout` remains a simple fixed value.
- **Detection coverage:** The automated test validates six implemented anomaly scenarios. Passing these tests does not establish detection of every possible attack.
- **Sensor timing:** Interface retry behavior supports topology creation and teardown, but a single successful run does not guarantee that all startup and shutdown timing conditions are race-free.
- **Attack simulations:** The automated scenarios generate test traffic in a controlled Mininet environment; they are not equivalent to validation against every real-world attack implementation.
