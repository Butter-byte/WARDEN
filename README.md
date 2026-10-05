# Context-Aware Dynamic VLAN Segmentation using SDN
### Tonight's prototype scope: Module 1 (Topology) + Module 2 (Dynamic VLAN Assignment)

## 1. Environment setup

Ryu is unmaintained and breaks on Python 3.10+ (an `eventlet` incompatibility).
The safest path tonight is a dedicated Python 3.8/3.9 virtualenv. If you're on
Windows, use WSL2 with Ubuntu 20.04; if you're already on Linux, check your
python3 version first (`python3 --version`).

```bash
# 1. System packages (Mininet + Open vSwitch)
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch python3-pip python3-venv

# 2. If your default python3 is 3.10+, install 3.8 alongside it
sudo apt-get install -y python3.8 python3.8-venv

# 3. Create an isolated venv for the controller
python3.8 -m venv ~/ryu-venv
source ~/ryu-venv/bin/activate

# 4. Install Ryu with the known-good eventlet version
pip install --upgrade pip
pip install ryu eventlet==0.30.1

# 5. Sanity checks
ryu-manager --version
sudo mn --test pingall          # confirms Mininet + OVS work at all
```

If `apt-get install mininet` isn't available on your distro, use the
official pre-built Mininet VM (VirtualBox) instead -- it ships with
Mininet + OVS already working, and you only need to `pip install ryu
eventlet==0.30.1` inside it.

## 2. Project layout

```
sdn-vlan-project/
├── controller/
│   └── vlan_controller.py     # Ryu app: dynamic VLAN assignment (Module 2)
├── topology/
│   └── topo.py                # Mininet topology (Module 1)
├── config/
│   ├── vlan_policy.json       # MAC -> role -> VLAN policy table
│   └── switch_ports.json      # which ports are trunk vs access, per switch
├── scripts/
│   ├── run_demo.sh            # launch the controller
│   ├── start_topology.sh      # launch Mininet
│   └── demo_commands.txt      # live-demo command cheat sheet
└── README.md
```

## 3. Running the demo

You need **two terminals** (both with the venv activated in the first one):

**Terminal 1 — controller:**
```bash
source ~/ryu-venv/bin/activate
bash scripts/run_demo.sh
```
Leave this running. It will print a line every time it (re)assigns a VLAN
to a host — this live log is the most convincing thing to show live.

**Terminal 2 — topology:**
```bash
bash scripts/start_topology.sh
```
This drops you into the `mininet>` CLI. Follow `scripts/demo_commands.txt`
from there — it walks through pings that prove same-VLAN hosts reach each
other across switches, while cross-VLAN hosts are blocked even on the same
switch.

To fully shut down between runs: in the mininet CLI run `exit`, then
`sudo mn -c` to clean up any leftover virtual interfaces before the next run.

## 4. How it maps to the review document

| Review doc section | What this prototype demonstrates |
|---|---|
| Proposed Methodology, Phase 1 | `topology/topo.py` — multi-switch OpenFlow topology |
| Proposed Methodology, Phase 2 | `controller/vlan_controller.py` — policy-driven VLAN assignment, decoupled from physical port |
| Existing Work Gap | `config/vlan_policy.json` shows assignment is driven by identity (MAC/role), not port — the gap this project targets |
| Modules 3-6 | Not built tonight; this prototype is deliberately scoped to the guaranteed core so there's a fully working demo for Review 1 |

## 5. Known limitations (be upfront about these in the review if asked)

- VLAN policy is keyed by MAC address only — no real authentication yet.
  That's intentionally deferred; Module 4 (security-reactive response) will
  sit on top of this same policy-lookup mechanism later.
- Two switches/four hosts is enough to prove the concept without fighting
  topology complexity on a one-night timeline. The architecture (policy
  file + per-switch trunk/access port config) already generalizes to more
  switches without code changes — just extend the JSON configs.
- No persistent flow cleanup/aging tuning yet; `idle_timeout` is a simple
  fixed value for now.
