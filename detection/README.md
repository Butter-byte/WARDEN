# Module 3 -- Anomaly Detection  |  Module 4 -- Security-Reactive Response

The detector is a standalone Scapy sensor. It runs in its own process,
separate from the Ryu controller. When it sees an ARP spoof, it sends a
REST request to the controller, and the controller moves the attacker to
the isolated VLAN 99.

Paths below are relative to the repo root (the folder containing
`controller/`, `detection/`, `topology/`).

## Setup (once)

```bash
source ~/ryu-venv/bin/activate
pip install scapy          # Module 4 uses only the standard library
deactivate
```

## Why the commands look unusual

- **Interfaces:** Mininet puts each host in its own network namespace.
  `h1-eth0` exists only inside h1. Use a switch interface such as
  `s1-eth3` (the trunk) to sniff from your normal shell.
- **sudo and venv:** `sudo python3` uses the system Python, which has no
  scapy. Call the venv's Python directly with sudo.
- **Inside the Mininet CLI, `~` is `/root`**, so `~/ryu-venv` does not
  exist there. Use absolute paths in `h3 ...` commands. Find your path
  with `pwd` in a normal terminal.

Replace `/home/hrishig` with your home directory and `sdn-vlan-project`
with your repo folder name in the commands below.

## Test walkthrough (Module 3 alert-only, then Module 4 response)

You need **four** terminals.

| # | Terminal | Command |
|---|---|---|
| 1 | Controller | `bash scripts/run_demo.sh` |
| 2 | Mininet | `bash scripts/start_topology.sh` |
| 3 | Detector | see step 3 below |
| 4 | Normal shell (for curl) | used only for the optional check |

### Step 1: start the controller (terminal 1)

Confirm the REST line appears:
```
wsgi ... Starting ... on 127.0.0.1:8080
```

### Step 2: start Mininet (terminal 2)

Wait for the `mininet>` prompt.

### Step 3: start the detector on the trunk (terminal 3)

```bash
sudo ~/ryu-venv/bin/python3 detection/arp_spoof_detector.py --iface s1-eth3
```

Expected:
```
[*] Module 3 detector listening on s1-eth3  (Ctrl+C to stop)
[*] Loaded 4 trusted IP<->MAC bindings from policy
[*] Mode: ALERT + RESPOND   controller: http://127.0.0.1:8080
```

To watch detection without responding, add `--no-respond`.

### Optional: check the REST hook before the attack (terminal 4)

```bash
curl -s -X POST http://127.0.0.1:8080/release \
  -H "Content-Type: application/json" \
  -d '{"mac":"00:00:00:00:00:03"}'
```

Expected: `{"status": "released", "mac": "00:00:00:00:00:03", "vlan": 10, "role": "staff"}`

Note the controller log shows a `[RELEASE]` line. This is harmless. It
restores h3 to its policy VLAN and confirms the endpoint works.

### Step 4: baseline in the Mininet CLI (terminal 2)

```
mininet> h1 ping -c 2 h3
```
Should succeed (both VLAN 10).

### Step 5: the attack (terminal 2)

```
mininet> h3 /home/hrishig/ryu-venv/bin/python3 /home/hrishig/projects/sdn-vlan-project/detection/simulate_arp_spoof.py --victim-ip 10.0.0.1 --iface h3-eth0
```

### Step 6: check the detector (terminal 3)

You should see:
```
[ALERT][ARP-SPOOF] 10.0.0.1 is policy-bound to 00:00:00:00:00:01, but a reply just claimed it from 00:00:00:00:00:03!
[RESPONSE] quarantine 00:00:00:00:00:03 -> HTTP 200: {"status": "quarantined", "mac": "00:00:00:00:00:03", "vlan": 99, "reason": "ARP spoof claiming 10.0.0.1"}
```

Only one `[RESPONSE]` line appears, even though the attack sends three
forged replies. The detector sends one quarantine request per attacker MAC.

### Step 7: check the controller (terminal 1)

```
[QUARANTINE] host=00:00:00:00:00:03 moved to isolated VLAN=99 (reason: ARP spoof claiming 10.0.0.1)
[MOBILITY] flushed cached flows for 00:00:00:00:00:03 across 2 switch(es)
```

### Step 8: verify isolation (terminal 2)

```
mininet> h1 ping -c 2 h3        # should FAIL: h3 is now in VLAN 99
mininet> h2 ping -c 2 h4        # should still SUCCEED: VLAN 20 is unaffected
mininet> h1 ping -c 2 h4        # cross-VLAN, still blocked
```

### Step 9: restore the host (terminal 4 or terminal 2 with curl)

```bash
curl -s -X POST http://127.0.0.1:8080/release \
  -H "Content-Type: application/json" \
  -d '{"mac":"00:00:00:00:00:03"}'
```

Then `h1 ping -c 2 h3` in the Mininet CLI should succeed again. The
restore is a clean reversal, which shows the response is reversible.

## What the controller accepts

| Endpoint | Body | Effect |
|---|---|---|
| `POST /quarantine` | `{"mac": "...", "reason": "..."}` | Moves the MAC to VLAN 99 (role `quarantined`), flushes its cached flows |
| `POST /release` | `{"mac": "..."}` | Restores the MAC's VLAN and role from `config/vlan_policy.json` |

Malformed MACs or bodies return HTTP 400.

## Known limitations (be upfront in review)

- **Victim ARP caches are not cleaned up.** Quarantine isolates the
  attacker. Hosts that already accepted the forged ARP entry keep it until
  it expires. A real deployment would also send a gratuitous ARP to repair
  the victim.
- **Identity is MAC-based.** A spoofed or randomized MAC defeats the
  policy table. This is the same limitation noted for Module 2.
- **The REST endpoint has no authentication.** Ryu listens on all
  interfaces by default. For the demo, start Ryu with
  `--wsapi-host 127.0.0.1` to keep it local, or see `run_demo.sh`.
- **One sensor, one interface.** The detector sees traffic crossing the
  trunk it sniffs. Other trunks or access ports are not covered.
- **Flood detection is alert-only.** It is not wired to quarantine, because
  thresholds are not tuned against real traffic.
- **First-seen-wins resets when the detector restarts.**