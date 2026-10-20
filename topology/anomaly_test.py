#!/usr/bin/env python3
"""
End-to-end anomaly test for WARDEN. Needs the controller and the sensor running.

  Terminal 1:  bash scripts/run_demo.sh
  Terminal 2:  sudo ~/ryu-venv/bin/python3 detection/sensor.py --iface s1-eth3
  Terminal 3:  sudo python3 topology/anomaly_test.py        <- this file

Run it with the SYSTEM python3 (Mininet is installed there). Attacks execute
inside Mininet hosts using the venv's python, found at /home/$SUDO_USER/ryu-venv
or given with --venv-python. Stop any interactive Mininet session first.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "topology"))

from mininet.log import setLogLevel          # noqa: E402
from mininet.net import Mininet              # noqa: E402
from mininet.node import OVSSwitch, RemoteController  # noqa: E402
from topo import VlanTopo                    # noqa: E402

API = "http://127.0.0.1:8080"
SIM = os.path.join(ROOT, "detection", "simulate_attacks.py")
MAC = {"h1": "00:00:00:00:00:01", "h2": "00:00:00:00:00:02",
       "h3": "00:00:00:00:00:03", "h4": "00:00:00:00:00:04"}
IP = {"h1": "10.0.0.1", "h2": "10.0.0.2", "h3": "10.0.0.3", "h4": "10.0.0.4"}
QUARANTINE_DETECTORS_OK = {"unauthorized-device"}   # alerts tolerated during clean traffic


def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.loads(r.read().decode() or "{}")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def release_all():
    for mac in MAC.values():
        api("POST", "/release", {"mac": mac})


def reset():
    release_all()
    api("POST", "/alerts/clear")
    time.sleep(2.5)   # let the sensor sync its quarantine set


def alerts():
    return (api("GET", "/alerts?limit=500") or {}).get("alerts", [])


def quarantined():
    return set((api("GET", "/state") or {}).get("quarantined", []))


def wait_for(detector, mac=None, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        for a in alerts():
            if a["detector"] == detector and (mac is None or a["mac"] == mac):
                return a
        time.sleep(0.5)
    return None


def reachable(net, src, dst_ip):
    out = net.get(src).cmd("ping -c 2 -W 1 %s" % dst_ip)
    return " 0 received" not in out and "100% packet loss" not in out


class Report:
    def __init__(self):
        self.rows = []

    def check(self, scenario, label, ok, detail=""):
        self.rows.append((scenario, label, ok))
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label, ("  -- " + detail) if detail and not ok else ""))
        return ok


def scenario(net, rep, venv_py, name, host, args, detector, mac=None,
             quarantine=None, victim=None):
    """quarantine: MAC expected to be quarantined, or None for alert-only."""
    print("\n== %s ==" % name)
    reset()
    net.get(host).cmd("%s %s %s" % (venv_py, SIM, args))
    alert = wait_for(detector, mac)
    rep.check(name, "detector '%s' raised an alert" % detector, alert is not None,
              "alerts seen: %s" % [(a["detector"], a["mac"]) for a in alerts()])
    time.sleep(2.0)
    q = quarantined()
    if quarantine:
        rep.check(name, "%s was quarantined" % quarantine, quarantine in q, "quarantined: %s" % q)
        if victim:
            src, dst = victim
            rep.check(name, "quarantined host cut off (%s -> %s fails)" % (src, dst),
                      not reachable(net, src, IP[dst]))
            rep.check(name, "other VLAN unaffected (h2 -> h4 works)", reachable(net, "h2", IP["h4"]))
        api("POST", "/release", {"mac": quarantine})
        time.sleep(2.5)
        if victim:
            rep.check(name, "recovers after release (%s -> %s works)" % victim,
                      reachable(net, victim[0], IP[victim[1]]))
    else:
        rep.check(name, "alert-only: nobody quarantined", not (q & set(MAC.values())), "quarantined: %s" % q)


def clean_traffic(net, rep):
    print("\n== clean traffic (false-positive check) ==")
    reset()
    for _ in range(3):
        reachable(net, "h1", IP["h3"])
        reachable(net, "h2", IP["h4"])
    time.sleep(3)
    bad = [a for a in alerts() if a["detector"] not in QUARANTINE_DETECTORS_OK]
    rep.check("clean traffic", "no detector fires on normal traffic", not bad,
              "false positives: %s" % [(a["detector"], a["mac"], a["message"]) for a in bad])
    rep.check("clean traffic", "nobody quarantined", not (quarantined() & set(MAC.values())))


def main():
    ap = argparse.ArgumentParser()
    user = os.environ.get("SUDO_USER", "")
    ap.add_argument("--venv-python", default="/home/%s/ryu-venv/bin/python3" % user)
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run with sudo.")
    if api("GET", "/state") is None:
        sys.exit("Controller REST API not reachable at %s. Start scripts/run_demo.sh first." % API)
    if not os.path.exists(args.venv_python):
        sys.exit("venv python not found: %s (use --venv-python)" % args.venv_python)

    setLogLevel("warning")
    net = Mininet(topo=VlanTopo(), switch=OVSSwitch, controller=None, autoSetMacs=False)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)
    net.start()
    net.configLinkStatus("h1", "s2", "down")
    rep = Report()
    py = args.venv_python
    try:
        time.sleep(3)
        reachable(net, "h1", IP["h3"]); reachable(net, "h2", IP["h4"])   # prime learning

        clean_traffic(net, rep)
        scenario(net, rep, py, "ARP spoofing", "h3",
                 "arp-spoof --iface h3-eth0 --victim-ip 10.0.0.1 --count 3",
                 "arp-spoof", MAC["h3"], MAC["h3"], ("h1", "h3"))
        scenario(net, rep, py, "Port scan", "h3",
                 "port-scan --iface h3-eth0 --target-ip 10.0.0.1 --first-port 1 --last-port 40",
                 "port-scan", MAC["h3"], MAC["h3"], ("h1", "h3"))
        scenario(net, rep, py, "VLAN hopping (forged 802.1Q tag)", "h1",
                 "vlan-hop --iface h1-eth0 --forged-vlan 20 --count 3",
                 "vlan-violation", MAC["h1"], MAC["h1"], ("h1", "h3"))
        scenario(net, rep, py, "MAC flooding", "h3",
                 "mac-flood --iface h3-eth0 --count 40", "mac-flood")
        scenario(net, rep, py, "Traffic-rate burst", "h3",
                 "traffic-flood --iface h3-eth0 --target-ip 10.0.0.1 --count 300",
                 "traffic-rate", MAC["h3"])
        scenario(net, rep, py, "Unauthorized device", "h3",
                 "rogue-device --iface h3-eth0 --count 3", "unauthorized-device")
    finally:
        reset()
        net.stop()

    passed = sum(1 for _, _, ok in rep.rows if ok)
    print("\n========== %d/%d checks passed ==========" % (passed, len(rep.rows)))
    for sc, label, ok in rep.rows:
        if not ok:
            print("  FAILED: [%s] %s" % (sc, label))
    sys.exit(0 if passed == len(rep.rows) else 1)


if __name__ == "__main__":
    main()
