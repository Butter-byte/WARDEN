"""
Detection engine -- pure logic, no packet capture, no network I/O.
 
The sensor (detection/sensor.py) converts captured packets into Frame objects
and feeds them here. Keeping the engine free of Scapy and Mininet means every
detector can be unit-tested with synthetic frames (tests/test_engine.py).
 
Detectors implemented:
  arp-spoof            ARP reply claims an IP owned by another MAC        -> quarantine
  vlan-violation       802.1Q tag disagrees with the sender's expected VLAN -> quarantine
  unauthorized-device  MAC not in the policy table sends traffic          -> alert
  mac-flood            many distinct source MACs in a short window        -> alert
  traffic-rate         one source MAC sends an abnormal packet volume     -> alert
  port-scan            one source touches many distinct destination ports -> quarantine
 
Each Alert carries an `action` the sensor acts on. The engine never acts itself.
"""
 
from __future__ import annotations
 
import collections
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set
 
BROADCAST = "ff:ff:ff:ff:ff:ff"
DEFAULT_VLAN = 99  # isolated/quarantine VLAN, matches config/vlan_policy.json
 
 
# ----------------------------------------------------------------------
# Data types
# ----------------------------------------------------------------------
@dataclass
class Frame:
    """A parsed frame. Only the fields a detector needs."""
    src_mac: str
    ts: float
    dst_mac: str = BROADCAST
    vlan: Optional[int] = None          # 802.1Q VID if the frame is tagged
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None      # TCP/UDP destination port
    arp_op: Optional[int] = None        # 1 = request, 2 = reply
    arp_psrc: Optional[str] = None      # IP the ARP packet claims
 
 
@dataclass
class Alert:
    detector: str
    severity: str          # "low" | "medium" | "high"
    mac: str               # the source MAC the alert is about
    message: str
    action: str            # "quarantine" | "none"
    ts: float
 
 
class Policy:
    """Read-only view of config/vlan_policy.json."""
 
    def __init__(self, policy_dict: dict):
        self.vlan: Dict[str, int] = {}
        self.ip_of: Dict[str, str] = {}
        self.mac_of_ip: Dict[str, str] = {}
        for mac, entry in policy_dict.get("policy", {}).items():
            mac = mac.lower()
            self.vlan[mac] = int(entry["vlan"])
            if entry.get("ip"):
                self.ip_of[mac] = entry["ip"]
                self.mac_of_ip[entry["ip"]] = mac
 
    def known(self, mac: str) -> bool:
        return mac.lower() in self.vlan
 
    def vlan_of(self, mac: str) -> Optional[int]:
        return self.vlan.get(mac.lower())
 
 
# ----------------------------------------------------------------------
# Detectors
# ----------------------------------------------------------------------
class Detector:
    name = "base"
 
    def observe(self, frame: Frame, engine: "DetectionEngine") -> List[Alert]:
        raise NotImplementedError
 
 
class ArpSpoofDetector(Detector):
    name = "arp-spoof"
 
    def __init__(self):
        self.first_seen: Dict[str, str] = {}   # IP -> MAC, for IPs not in policy
 
    def observe(self, frame, engine):
        if frame.arp_op not in (1, 2) or not frame.arp_psrc:
            return []
        ip, claimed_by = frame.arp_psrc, frame.src_mac.lower()
 
        expected = engine.policy.mac_of_ip.get(ip)
        if expected is not None:
            if expected != claimed_by:
                return [Alert(self.name, "high", claimed_by,
                              f"{ip} is policy-bound to {expected}, "
                              f"but an ARP reply claimed it from {claimed_by}",
                              "quarantine", frame.ts)]
            return []
 
        # IP not in policy: first-seen wins.
        prev = self.first_seen.setdefault(ip, claimed_by)
        if prev != claimed_by:
            return [Alert(self.name, "high", claimed_by,
                          f"{ip} was first seen as {prev}, now claimed by {claimed_by}",
                          "quarantine", frame.ts)]
        return []
 
 
class VlanViolationDetector(Detector):
    """A tagged frame whose VID disagrees with the sender's expected VLAN.
    Expected VLAN is the policy VLAN, or the quarantine VLAN if the sender
    is currently quarantined. This is the check that tests segmentation itself."""
    name = "vlan-violation"
 
    def observe(self, frame, engine):
        if frame.vlan is None:
            return []
        mac = frame.src_mac.lower()
        expected = engine.expected_vlan(mac)
        if frame.vlan != expected:
            return [Alert(self.name, "high", mac,
                          f"frame tagged VLAN {frame.vlan}, expected VLAN {expected}",
                          "quarantine", frame.ts)]
        return []
 
 
class UnauthorizedDeviceDetector(Detector):
    name = "unauthorized-device"
 
    def __init__(self):
        self.reported: Set[str] = set()
 
    def observe(self, frame, engine):
        mac = frame.src_mac.lower()
        if engine.policy.known(mac) or mac in self.reported:
            return []
        self.reported.add(mac)
        return [Alert(self.name, "medium", mac,
                      f"{mac} is not in the policy table",
                      "none", frame.ts)]
 
 
class MacFloodDetector(Detector):
    """Many distinct source MACs in a short window. Fills a switch's MAC table.
    Cannot be pinned on one host, so it alerts without quarantining."""
    name = "mac-flood"
 
    def __init__(self, window: float = 5.0, threshold: int = 20):
        self.window, self.threshold = window, threshold
        self.events = collections.deque()   # (ts, mac)
 
    def observe(self, frame, engine):
        self.events.append((frame.ts, frame.src_mac.lower()))
        cutoff = frame.ts - self.window
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()
        distinct = {mac for _, mac in self.events}
        if len(distinct) > self.threshold:
            return [Alert(self.name, "high", frame.src_mac.lower(),
                          f"{len(distinct)} distinct source MACs in {self.window}s "
                          f"(threshold {self.threshold})",
                          "none", frame.ts)]
        return []
 
 
class TrafficRateDetector(Detector):
    """One source MAC sends more frames than the threshold per window."""
    name = "traffic-rate"
 
    def __init__(self, window: float = 5.0, threshold: int = 200):
        self.window, self.threshold = window, threshold
        self.times: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
 
    def observe(self, frame, engine):
        mac = frame.src_mac.lower()
        q = self.times[mac]
        q.append(frame.ts)
        cutoff = frame.ts - self.window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) > self.threshold:
            return [Alert(self.name, "medium", mac,
                          f"{len(q)} frames in {self.window}s (threshold {self.threshold})",
                          "none", frame.ts)]
        return []
 
 
class PortScanDetector(Detector):
    """One source MAC touches many distinct destination ports in a window."""
    name = "port-scan"
 
    def __init__(self, window: float = 10.0, threshold: int = 15, action: str = "quarantine"):
        self.window, self.threshold, self.action = window, threshold, action
        self.hits: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
 
    def observe(self, frame, engine):
        if frame.dst_port is None:
            return []
        mac = frame.src_mac.lower()
        q = self.hits[mac]
        q.append((frame.ts, frame.dst_port))
        cutoff = frame.ts - self.window
        while q and q[0][0] < cutoff:
            q.popleft()
        ports = {p for _, p in q}
        if len(ports) > self.threshold:
            return [Alert(self.name, "high", mac,
                          f"{len(ports)} distinct destination ports in {self.window}s "
                          f"(threshold {self.threshold})",
                          self.action, frame.ts)]
        return []
 
 
# ----------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------
class DetectionEngine:
    """Runs every detector over each frame, suppresses repeat alerts, and
    tracks which hosts are currently quarantined so the VLAN check stays correct."""
 
    def __init__(self, policy: Policy, detectors: Iterable[Detector] = None,
                 cooldown: float = 10.0):
        self.policy = policy
        self.detectors: List[Detector] = list(detectors) if detectors is not None \
            else default_detectors()
        self.cooldown = cooldown
        self.quarantined: Set[str] = set()
        self._last_alert: Dict[tuple, float] = {}
 
    def expected_vlan(self, mac: str) -> int:
        mac = mac.lower()
        if mac in self.quarantined:
            return DEFAULT_VLAN
        vlan = self.policy.vlan_of(mac)
        return vlan if vlan is not None else DEFAULT_VLAN
 
    def mark_quarantined(self, mac: str) -> None:
        self.quarantined.add(mac.lower())
 
    def mark_released(self, mac: str) -> None:
        self.quarantined.discard(mac.lower())
 
    def observe(self, frame: Frame) -> List[Alert]:
        alerts: List[Alert] = []
        for det in self.detectors:
            for alert in det.observe(frame, self):
                key = (alert.detector, alert.mac)
                last = self._last_alert.get(key)
                if last is not None and frame.ts - last < self.cooldown:
                    continue
                self._last_alert[key] = frame.ts
                alerts.append(alert)
        return alerts
 
 
def default_detectors() -> List[Detector]:
    return [
        ArpSpoofDetector(),
        VlanViolationDetector(),
        UnauthorizedDeviceDetector(),
        MacFloodDetector(),
        TrafficRateDetector(),
        PortScanDetector(),
    ]
 