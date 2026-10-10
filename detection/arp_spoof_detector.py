#!/usr/bin/env python3
"""
Module 3 -- Anomaly Detection Layer, with Module 4 -- Security-Reactive Response.

A standalone Scapy sensor, deliberately decoupled from the Ryu controller:
it sniffs traffic, decides whether something is wrong, and reports to the
controller over REST. The controller owns the decision of what to do about it.

Checks:
  1. ARP spoofing -- every ARP reply's (IP, MAC) pair is compared to the
     trusted bindings in config/vlan_policy.json. A mismatch means someone
     is claiming an IP that isn't theirs.
  2. Flood detection -- a source MAC sending an abnormal number of packets
     in a sliding window. Alert only; not wired to quarantine, because
     bursty traffic can look like a flood without being one.

Response (Module 4):
  On an ARP-spoof alert, POST {"mac": <attacker>} to the controller's
  /quarantine endpoint. The controller moves that host to the isolated
  VLAN. Use --no-respond to keep the detector in alert-only mode.

Usage (sniff the trunk port, which is visible from the root namespace):
    sudo ~/ryu-venv/bin/python3 detection/arp_spoof_detector.py --iface s1-eth3

Must run as root for raw-socket sniffing. Use the venv's python directly
with sudo. Plain `sudo python3` uses the system Python, which has no scapy.
"""

import argparse
import collections
import json
import os
import time
import urllib.error
import urllib.request

from scapy.all import ARP, Ether, sniff

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(BASE_DIR, "config", "vlan_policy.json")

DEFAULT_CONTROLLER_URL = "http://127.0.0.1:8080"


def load_trusted_bindings():
    """IP -> trusted MAC, from the same policy file the controller uses,
    so there is one source of truth for 'who owns what' in the project."""
    with open(POLICY_PATH) as f:
        data = json.load(f)
    bindings = {}
    for mac, entry in data["policy"].items():
        ip = entry.get("ip")
        if ip:
            bindings[ip] = mac.lower()
    return bindings


class AnomalyDetector:
    def __init__(self, iface, flood_threshold, flood_window,
                 controller_url=DEFAULT_CONTROLLER_URL, respond=True):
        self.iface = iface
        self.trusted = load_trusted_bindings()
        self.controller_url = controller_url.rstrip("/")
        self.respond = respond

        # For IPs not in the static policy, enforce first-seen-wins so an
        # impersonation attempt is still caught without a pre-set entry.
        self.observed_bindings = {}

        self.flood_threshold = flood_threshold
        self.flood_window = flood_window
        self.pkt_times = collections.defaultdict(list)
        self._flood_active = set()

        # MACs we've already asked the controller to quarantine. Prevents
        # re-sending a POST for every forged packet in the same attack.
        self.quarantined = set()

    # ------------------------------------------------------------
    # Module 4: respond to the controller
    # ------------------------------------------------------------
    def _request_quarantine(self, mac, reason):
        if not self.respond:
            print(f"[RESPONSE] --no-respond set; would quarantine {mac}")
            return
        if mac in self.quarantined:
            return

        self.quarantined.add(mac)
        body = json.dumps({"mac": mac, "reason": reason}).encode("utf-8")
        req = urllib.request.Request(
            self.controller_url + "/quarantine",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                print(f"[RESPONSE] quarantine {mac} -> HTTP {resp.status}: "
                      f"{resp.read().decode('utf-8')}")
        except (urllib.error.URLError, OSError) as e:
            # Let a later alert retry if the controller wasn't reachable.
            self.quarantined.discard(mac)
            print(f"[RESPONSE][ERROR] controller unreachable at "
                  f"{self.controller_url}: {e}")

    # ------------------------------------------------------------
    def _check_flood(self, mac):
        now = time.time()
        times = self.pkt_times[mac]
        times.append(now)
        cutoff = now - self.flood_window
        while times and times[0] < cutoff:
            times.pop(0)

        if len(times) > self.flood_threshold:
            if mac not in self._flood_active:
                print(
                    f"[ALERT][FLOOD] {mac} sent {len(times)} packets in the "
                    f"last {self.flood_window}s (threshold={self.flood_threshold})"
                )
                self._flood_active.add(mac)
        else:
            self._flood_active.discard(mac)

    # ------------------------------------------------------------
    def _check_arp(self, pkt):
        arp = pkt[ARP]
        src_ip = arp.psrc
        src_mac = pkt[Ether].src.lower()

        # Only replies and gratuitous ARP update a victim's ARP cache.
        if arp.op not in (1, 2):
            return

        expected_mac = self.trusted.get(src_ip)
        if expected_mac:
            if expected_mac != src_mac:
                print(
                    f"[ALERT][ARP-SPOOF] {src_ip} is policy-bound to "
                    f"{expected_mac}, but a reply just claimed it from "
                    f"{src_mac}!"
                )
                self._request_quarantine(
                    src_mac, reason=f"ARP spoof claiming {src_ip}")
            return

        prev_mac = self.observed_bindings.get(src_ip)
        if prev_mac is None:
            self.observed_bindings[src_ip] = src_mac
        elif prev_mac != src_mac:
            print(
                f"[ALERT][ARP-SPOOF] {src_ip} was first seen as "
                f"{prev_mac}, now claimed by {src_mac}!"
            )
            self._request_quarantine(
                src_mac, reason=f"ARP spoof claiming {src_ip}")

    # ------------------------------------------------------------
    def handle(self, pkt):
        if Ether not in pkt:
            return
        src_mac = pkt[Ether].src.lower()
        self._check_flood(src_mac)
        if ARP in pkt:
            self._check_arp(pkt)

    def run(self):
        mode = "ALERT + RESPOND" if self.respond else "ALERT ONLY"
        print(f"[*] Module 3 detector listening on {self.iface}  (Ctrl+C to stop)")
        print(f"[*] Loaded {len(self.trusted)} trusted IP<->MAC bindings from policy")
        print(f"[*] Mode: {mode}   controller: {self.controller_url}")
        sniff(iface=self.iface, prn=self.handle, store=False)


def main():
    p = argparse.ArgumentParser(description="Module 3/4: ARP-spoof detector with quarantine response")
    p.add_argument("--iface", required=True,
                   help="Interface to sniff on. Use a switch trunk port such as "
                        "s1-eth3, which is visible from the root namespace. "
                        "Host interfaces like h1-eth0 are NOT visible there.")
    p.add_argument("--controller-url", default=DEFAULT_CONTROLLER_URL,
                   help=f"Ryu REST base URL (default {DEFAULT_CONTROLLER_URL})")
    p.add_argument("--no-respond", action="store_true",
                   help="Alert only. Do not send quarantine requests to the controller.")
    p.add_argument("--flood-threshold", type=int, default=50,
                   help="Packets per window that trigger a flood alert (default 50)")
    p.add_argument("--flood-window", type=float, default=5.0,
                   help="Sliding window in seconds (default 5.0)")
    args = p.parse_args()

    AnomalyDetector(
        args.iface,
        args.flood_threshold,
        args.flood_window,
        controller_url=args.controller_url,
        respond=not args.no_respond,
    ).run()


if __name__ == "__main__":
    main()