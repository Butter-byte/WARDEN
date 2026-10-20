# Detection layer: engine, sensor, attack simulators

```
packet (Scapy) -> Frame -> DetectionEngine -> Alert --> POST /alerts      (dashboard feed)
   sensor.py               engine.py                 \-> POST /quarantine (if action = quarantine)
```

| File | Role |
|---|---|
| `engine.py` | Pure detection logic. No sniffing, no network. Unit-tested. |
| `sensor.py` | Sniffs a switch port, runs the engine, reports to the controller. |
| `simulate_attacks.py` | Generates each anomaly from inside a Mininet host. |

## Detectors

| Detector | Triggers when | Action |
|---|---|---|
| `arp-spoof` | An ARP packet claims an IP that policy binds to another MAC | quarantine |
| `vlan-violation` | An 802.1Q tag disagrees with the sender's expected VLAN, or the frame is double-tagged (VLAN hopping) | quarantine |
| `port-scan` | One MAC sends TCP SYNs to more than 15 distinct ports in 10 s | quarantine |
| `unauthorized-device` | A MAC that is not in `config/vlan_policy.json` sends traffic | alert only |
| `mac-flood` | More than 20 distinct source MACs in 5 s | alert only |
| `traffic-rate` | One MAC sends more than 200 frames in 5 s | alert only |

Alert-only detectors do not quarantine because the evidence does not pin the
problem on one trusted host (flooding uses spoofed MACs) or because bursty
traffic can be legitimate. The same `(detector, MAC)` pair alerts at most once
per 10 s (`--cooldown`).

Design notes:
- The expected VLAN follows quarantine state. A quarantined host is expected on
  VLAN 99, so its re-tagged frames are not reported as violations.
- IPv6 multicast and link-layer control frames (33:33:..., 01:80:c2:...) are
  ignored. Use `--ignore-mac` for any other infrastructure noise.
- Only pure TCP SYNs count toward port-scan detection. Replies carry ephemeral
  destination ports and would look like a scan.
- ARP probes (sender IP 0.0.0.0) are not treated as claims.

## Setup (once)

```bash
source ~/ryu-venv/bin/activate
pip install scapy pytest
```

## Run order

Paths below assume the repo root. Replace `/home/hrishig` and the repo folder name with yours.

| Terminal | Command |
|---|---|
| 1. Controller | `bash scripts/run_demo.sh` |
| 2. Topology | `bash scripts/start_topology.sh` |
| 3. Sensor | `sudo ~/ryu-venv/bin/python3 detection/sensor.py --iface s1-eth3` |
| Browser | `http://127.0.0.1:8080/` |

Why the commands look unusual:
- Sniff a switch port (`s1-eth3`, the trunk). Host interfaces such as `h1-eth0`
  exist only inside the host's namespace.
- `sudo python3` uses the system Python, which has no scapy. Call the venv's
  Python directly.
- Inside `mininet>`, `~` is `/root`. Use absolute paths.

Sensor flags: `--no-respond` (alert only), `--cooldown N`, `--ignore-mac MAC`, `--controller-url URL`.

## Manual attacks (inside mininet>)

```
mininet> h3 /home/hrishig/ryu-venv/bin/python3 /home/hrishig/projects/sdn-vlan-project/detection/simulate_attacks.py arp-spoof --iface h3-eth0 --victim-ip 10.0.0.1
mininet> h3 ... simulate_attacks.py port-scan     --iface h3-eth0 --target-ip 10.0.0.1
mininet> h3 ... simulate_attacks.py mac-flood     --iface h3-eth0
mininet> h3 ... simulate_attacks.py traffic-flood --iface h3-eth0 --target-ip 10.0.0.1
mininet> h3 ... simulate_attacks.py rogue-device  --iface h3-eth0
mininet> h1 ... simulate_attacks.py vlan-hop      --iface h1-eth0 --forged-vlan 20
```

## Automated tests

```bash
# Unit tests: no Mininet, no controller needed
python -m pytest tests/ -v

# End-to-end: controller + sensor running, no interactive Mininet open
sudo python3 topology/anomaly_test.py
```

The end-to-end run checks, per attack: the alert fires, the right host is
quarantined (or nobody, for alert-only detectors), the quarantined host is cut
off, the other VLAN is unaffected, and the host recovers after release. It also
runs a clean-traffic check that no detector fires on normal pings.

## Controller REST API

| Endpoint | Purpose |
|---|---|
| `GET /` | Dashboard |
| `GET /state` | Hosts, VLANs, quarantine state, switches |
| `GET /alerts?limit=N` | Alerts, controller events, per-detector counts |
| `POST /alerts` | Sensor submits an alert |
| `POST /alerts/clear` | Clear the alert feed |
| `POST /quarantine` `{"mac","reason"}` | Move a host to VLAN 99 |
| `POST /release` `{"mac"}` | Restore a host to its policy VLAN |

## Known limitations

- Identity is MAC-based. A spoofed MAC defeats the policy table.
- The REST API has no authentication; `run_demo.sh` binds it to 127.0.0.1.
- The sensor watches one port. Traffic that never crosses the sniffed trunk
  (for example two hosts on the same switch) is not seen.
- Quarantine does not repair victims' ARP caches.
- Detector thresholds are fixed constants, not tuned against real traffic.
