#!/usr/bin/env python3
"""
WARDEN sensor -- the only process that touches the wire.

  packet (Scapy) -> Frame -> DetectionEngine (detection/engine.py) -> Alert
                                                                       |
                  POST /alerts  (dashboard feed)  <--------------------+
                  POST /quarantine (if alert.action == "quarantine")  <-+

Usage (sniff the trunk port; it is visible from the root namespace):
    sudo ~/ryu-venv/bin/python3 detection/sensor.py --iface s1-eth3

Run as root. Call the venv's python directly: plain `sudo python3` uses the
system Python, which has no scapy.
"""

import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import DetectionEngine, Frame, Policy, default_detectors  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(BASE_DIR, "config", "vlan_policy.json")
DEFAULT_CONTROLLER_URL = "http://127.0.0.1:8080"

# Link-layer control traffic and IPv6 multicast chatter are not host behaviour.
IGNORED_DST_PREFIXES = ("33:33:", "01:80:c2:")


# ----------------------------------------------------------------------
# Packet -> Frame  (kept separate from sniffing so it can be unit-tested)
# ----------------------------------------------------------------------
def packet_to_frame(pkt, ts=None, ignore_macs=frozenset()):
    """Convert a Scapy packet to an engine Frame, or None if it should be
    skipped. Imports Scapy lazily so the module can be imported without it."""
    from scapy.all import ARP, IP, TCP, Dot1Q, Ether
    try:
        from scapy.layers.l2 import Dot1AD
        tag_types = (Dot1Q, Dot1AD)
    except ImportError:
        tag_types = (Dot1Q,)

    eth = pkt.getlayer(Ether)
    if eth is None:
        return None
    src, dst = eth.src.lower(), eth.dst.lower()
    if src in ignore_macs or dst.startswith(IGNORED_DST_PREFIXES):
        return None

    tags = []
    layer = eth.payload
    while isinstance(layer, tag_types):
        tags.append(int(layer.vlan))
        layer = layer.payload

    frame = Frame(
        src_mac=src,
        dst_mac=dst,
        ts=float(ts if ts is not None else pkt.time),
        vlan=tags[0] if tags else None,
        inner_vlan=tags[1] if len(tags) > 1 else None,
    )

    arp = pkt.getlayer(ARP)
    if arp is not None:
        frame.arp_op = int(arp.op)
        frame.arp_psrc = str(arp.psrc)

    ip = pkt.getlayer(IP)
    if ip is not None:
        frame.src_ip, frame.dst_ip = str(ip.src), str(ip.dst)

    # Only pure TCP SYNs count toward port-scan detection. Replies carry the
    # client's ephemeral port as destination, which would look like a scan.
    tcp = pkt.getlayer(TCP)
    if tcp is not None and (int(tcp.flags) & 0x12) == 0x02:
        frame.dst_port = int(tcp.dport)

    return frame


# ----------------------------------------------------------------------
# Controller REST client
# ----------------------------------------------------------------------
class ControllerClient:
    def __init__(self, base_url=DEFAULT_CONTROLLER_URL, timeout=3):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode() or "{}")

    def post_alert(self, alert):
        try:
            self._request("POST", "/alerts", alert)
            return True
        except (urllib.error.URLError, OSError, ValueError):
            return False

    def quarantine(self, mac, reason):
        try:
            self._request("POST", "/quarantine", {"mac": mac, "reason": reason})
            return True
        except (urllib.error.URLError, OSError, ValueError):
            return False

    def quarantined_macs(self):
        """Set of currently quarantined MACs, or None if unreachable."""
        try:
            return set(self._request("GET", "/state").get("quarantined", []))
        except (urllib.error.URLError, OSError, ValueError):
            return None


# ----------------------------------------------------------------------
# Sensor
# ----------------------------------------------------------------------
class Sensor:
    SYNC_GRACE = 3.0   # seconds a local quarantine mark is trusted over the controller

    def __init__(self, engine, client, respond=True, ignore_macs=frozenset(),
                 out=print):
        self.engine, self.client = engine, client
        self.respond, self.ignore_macs, self.out = respond, set(ignore_macs), out
        self._marked_at = {}

    def handle(self, pkt):
        frame = packet_to_frame(pkt, ignore_macs=self.ignore_macs)
        if frame is not None:
            self.process_frame(frame)

    def process_frame(self, frame):
        for alert in self.engine.observe(frame):
            self._act(alert)

    def _act(self, alert):
        self.out(f"[ALERT][{alert.detector}][{alert.severity}] mac={alert.mac} "
                 f"{alert.message}")
        payload = {"detector": alert.detector, "severity": alert.severity,
                   "mac": alert.mac, "message": alert.message,
                   "action": alert.action, "ts": alert.ts}
        if not self.client.post_alert(payload):
            self.out("[WARN] controller unreachable; alert not delivered to dashboard")

        if alert.action != "quarantine":
            return
        if not self.respond:
            self.out(f"[RESPONSE] --no-respond set; would quarantine {alert.mac}")
            return
        if alert.mac in self.engine.quarantined:
            return

        # Mark BEFORE the request: once the controller re-tags the host as
        # VLAN 99, frames already in flight must not read as violations.
        self.engine.mark_quarantined(alert.mac)
        self._marked_at[alert.mac] = time.time()
        reason = f"{alert.detector}: {alert.message}"
        if self.client.quarantine(alert.mac, reason):
            self.out(f"[RESPONSE] quarantined {alert.mac} (VLAN 99)")
        else:
            self.engine.mark_released(alert.mac)
            self._marked_at.pop(alert.mac, None)
            self.out(f"[RESPONSE][ERROR] could not reach controller to quarantine {alert.mac}")

    def sync_once(self):
        """Align the engine's quarantine set with the controller's, so manual
        releases and dashboard quarantines are reflected in the VLAN check."""
        remote = self.client.quarantined_macs()
        if remote is None:
            return
        for mac in remote - self.engine.quarantined:
            self.engine.mark_quarantined(mac)
        now = time.time()
        for mac in list(self.engine.quarantined - remote):
            if now - self._marked_at.get(mac, 0) > self.SYNC_GRACE:
                self.engine.mark_released(mac)
                self._marked_at.pop(mac, None)

    def _sync_loop(self, interval):
        while True:
            self.sync_once()
            time.sleep(interval)

    def run(self, iface):
        import time
        from scapy.all import sniff

        threading.Thread(
            target=self._sync_loop,
            args=(1.0,),
            daemon=True,
        ).start()

        print(f"[*] Waiting for interface {iface}...", flush=True)

        while True:
            try:
                sniff(iface=iface, prn=self.handle, store=False)
                print(
                    f"[WARN] Capture stopped on {iface}; retrying...",
                    flush=True,
                )
            except KeyboardInterrupt:
                print("\n[*] Sensor stopped.", flush=True)
                break
            except Exception as exc:
                print(
                    f"[WARN] Capture on {iface} failed: {exc}; "
                    "retrying in 2 seconds.",
                    flush=True,
                )

            time.sleep(2)


def main():
    p = argparse.ArgumentParser(description="WARDEN sensor: six detectors + quarantine response")
    p.add_argument("--iface", required=True,
                   help="Switch port to sniff, e.g. s1-eth3 (the trunk). Host interfaces "
                        "like h1-eth0 are not visible from the root namespace.")
    p.add_argument("--controller-url", default=DEFAULT_CONTROLLER_URL)
    p.add_argument("--no-respond", action="store_true",
                   help="Alert only; never request quarantine")
    p.add_argument("--cooldown", type=float, default=10.0,
                   help="Seconds before the same (detector, MAC) can alert again")
    p.add_argument("--ignore-mac", action="append", default=[],
                   help="MAC to ignore entirely (repeatable), e.g. switch-local interfaces")
    args = p.parse_args()

    with open(POLICY_PATH) as f:
        policy = Policy(json.load(f))
    engine = DetectionEngine(policy, default_detectors(), cooldown=args.cooldown)
    sensor = Sensor(engine, ControllerClient(args.controller_url),
                    respond=not args.no_respond,
                    ignore_macs={m.lower() for m in args.ignore_mac})

    print(f"[*] WARDEN sensor on {args.iface}  "
          f"mode={'ALERT ONLY' if args.no_respond else 'ALERT + RESPOND'}  "
          f"controller={args.controller_url}")
    print(f"[*] {len(engine.detectors)} detectors: "
          f"{', '.join(d.name for d in engine.detectors)}")
    print(f"[*] {len(policy.vlan)} hosts in policy. Ctrl+C to stop.")
    sensor.run(args.iface)


if __name__ == "__main__":
    main()
