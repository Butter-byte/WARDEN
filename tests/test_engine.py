"""
Unit tests for detection/engine.py. No Mininet, no Ryu, no Scapy needed.
 
Run from the repo root:
    python -m pytest tests/ -v
"""
 
import json
import os
import sys
 
import pytest
 
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "detection"))
 
from engine import (  # noqa: E402
    ArpSpoofDetector, DetectionEngine, Frame, MacFloodDetector, Policy,
    PortScanDetector, TrafficRateDetector, UnauthorizedDeviceDetector,
    VlanViolationDetector, default_detectors,
)
 
STAFF_1 = "00:00:00:00:00:01"   # 10.0.0.1, VLAN 10
GUEST_2 = "00:00:00:00:00:02"   # 10.0.0.2, VLAN 20
STAFF_3 = "00:00:00:00:00:03"   # 10.0.0.3, VLAN 10 -- the attacker in demos
GUEST_4 = "00:00:00:00:00:04"   # 10.0.0.4, VLAN 20
STRANGER = "de:ad:be:ef:00:99"  # not in policy
 
 
@pytest.fixture
def policy():
    with open(os.path.join(ROOT, "config", "vlan_policy.json")) as f:
        return Policy(json.load(f))
 
 
def make_engine(policy, detectors=None, cooldown=0.0):
    """cooldown=0 by default so each test sees every alert it triggers.
    Cooldown has its own test below."""
    return DetectionEngine(policy, detectors=detectors, cooldown=cooldown)
 
 
# ----------------------------------------------------------------------
# Policy parsing
# ----------------------------------------------------------------------
def test_policy_loads_real_config(policy):
    assert policy.vlan_of(STAFF_1) == 10
    assert policy.vlan_of(GUEST_2) == 20
    assert policy.mac_of_ip["10.0.0.3"] == STAFF_3
    assert policy.known(GUEST_4)
    assert not policy.known(STRANGER)
 
 
def test_policy_is_case_insensitive(policy):
    assert policy.known(STAFF_1.upper())
    assert policy.vlan_of(STAFF_1.upper()) == 10
 
 
# ----------------------------------------------------------------------
# ARP spoofing
# ----------------------------------------------------------------------
def test_arp_reply_from_correct_owner_is_clean(policy):
    eng = make_engine(policy, [ArpSpoofDetector()])
    f = Frame(src_mac=STAFF_1, ts=1, arp_op=2, arp_psrc="10.0.0.1")
    assert eng.observe(f) == []
 
 
def test_arp_reply_claiming_another_hosts_ip_is_spoof(policy):
    eng = make_engine(policy, [ArpSpoofDetector()])
    f = Frame(src_mac=STAFF_3, ts=1, arp_op=2, arp_psrc="10.0.0.1")
    alerts = eng.observe(f)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.detector == "arp-spoof" and a.action == "quarantine"
    assert a.mac == STAFF_3 and a.severity == "high"
 
 
def test_arp_first_seen_wins_for_unknown_ip(policy):
    eng = make_engine(policy, [ArpSpoofDetector()])
    eng.observe(Frame(src_mac=STRANGER, ts=1, arp_op=2, arp_psrc="10.0.0.50"))
    alerts = eng.observe(Frame(src_mac=GUEST_4, ts=2, arp_op=2, arp_psrc="10.0.0.50"))
    assert len(alerts) == 1 and alerts[0].mac == GUEST_4
 
 
def test_non_arp_frame_ignored_by_arp_detector(policy):
    eng = make_engine(policy, [ArpSpoofDetector()])
    f = Frame(src_mac=STAFF_3, ts=1, src_ip="10.0.0.3", dst_ip="10.0.0.1")
    assert eng.observe(f) == []
 
 
# ----------------------------------------------------------------------
# VLAN violation (segmentation check)
# ----------------------------------------------------------------------
def test_tag_matches_policy_is_clean(policy):
    eng = make_engine(policy, [VlanViolationDetector()])
    assert eng.observe(Frame(src_mac=STAFF_1, ts=1, vlan=10)) == []
 
 
def test_tag_disagreeing_with_policy_is_violation(policy):
    eng = make_engine(policy, [VlanViolationDetector()])
    alerts = eng.observe(Frame(src_mac=STAFF_1, ts=1, vlan=20))  # staff claims guest VLAN
    assert len(alerts) == 1
    assert alerts[0].action == "quarantine" and alerts[0].mac == STAFF_1
 
 
def test_untagged_frame_is_not_a_vlan_violation(policy):
    eng = make_engine(policy, [VlanViolationDetector()])
    assert eng.observe(Frame(src_mac=STAFF_1, ts=1, vlan=None)) == []
 
 
def test_unknown_mac_tagged_outside_quarantine_vlan_is_violation(policy):
    eng = make_engine(policy, [VlanViolationDetector()])
    alerts = eng.observe(Frame(src_mac=STRANGER, ts=1, vlan=10))
    assert len(alerts) == 1  # unknown devices belong in VLAN 99
 
 
def test_quarantined_host_tagged_99_is_clean(policy):
    """After quarantine, the controller tags that host's frames with VLAN 99.
    The detector must agree with the controller, or it would alert every packet."""
    eng = make_engine(policy, [VlanViolationDetector()])
    eng.mark_quarantined(STAFF_3)
    assert eng.observe(Frame(src_mac=STAFF_3, ts=1, vlan=99)) == []
 
 
def test_quarantined_host_still_tagged_policy_vlan_is_violation(policy):
    eng = make_engine(policy, [VlanViolationDetector()])
    eng.mark_quarantined(STAFF_3)
    alerts = eng.observe(Frame(src_mac=STAFF_3, ts=1, vlan=10))
    assert len(alerts) == 1
 
 
def test_release_restores_policy_expectation(policy):
    eng = make_engine(policy, [VlanViolationDetector()])
    eng.mark_quarantined(STAFF_3)
    eng.mark_released(STAFF_3)
    assert eng.expected_vlan(STAFF_3) == 10
    assert len(eng.observe(Frame(src_mac=STAFF_3, ts=1, vlan=99))) == 1
 
 
# ----------------------------------------------------------------------
# Unauthorized device
# ----------------------------------------------------------------------
def test_known_device_not_flagged(policy):
    eng = make_engine(policy, [UnauthorizedDeviceDetector()])
    assert eng.observe(Frame(src_mac=GUEST_2, ts=1)) == []
 
 
def test_unknown_device_flagged_once(policy):
    eng = make_engine(policy, [UnauthorizedDeviceDetector()])
    first = eng.observe(Frame(src_mac=STRANGER, ts=1))
    second = eng.observe(Frame(src_mac=STRANGER, ts=2))
    assert len(first) == 1 and first[0].action == "none"
    assert second == []
 
 
# ----------------------------------------------------------------------
# MAC flood
# ----------------------------------------------------------------------
def test_mac_flood_triggers_on_many_distinct_sources(policy):
    eng = make_engine(policy, [MacFloodDetector(window=5, threshold=20)])
    alerts = []
    for i in range(25):
        mac = f"02:00:00:00:00:{i:02x}"
        alerts += eng.observe(Frame(src_mac=mac, ts=i * 0.1))
    assert len(alerts) >= 1 and alerts[0].detector == "mac-flood"
    assert alerts[0].action == "none"  # cannot be pinned on one host
 
 
def test_mac_flood_ignores_spread_out_traffic(policy):
    eng = make_engine(policy, [MacFloodDetector(window=5, threshold=20)])
    alerts = []
    for i in range(25):
        mac = f"02:00:00:00:00:{i:02x}"
        alerts += eng.observe(Frame(src_mac=mac, ts=i * 10.0))  # 10s apart
    assert alerts == []
 
 
# ----------------------------------------------------------------------
# Traffic rate
# ----------------------------------------------------------------------
def test_traffic_rate_flags_one_chatty_mac(policy):
    eng = make_engine(policy, [TrafficRateDetector(window=5, threshold=200)])
    alerts = []
    for i in range(210):
        alerts += eng.observe(Frame(src_mac=STAFF_3, ts=i * 0.01))
    assert len(alerts) >= 1 and alerts[0].mac == STAFF_3
 
 
def test_normal_traffic_rate_is_clean(policy):
    eng = make_engine(policy, [TrafficRateDetector(window=5, threshold=200)])
    alerts = []
    for i in range(50):
        alerts += eng.observe(Frame(src_mac=STAFF_3, ts=i * 0.5))
    assert alerts == []
 
 
# ----------------------------------------------------------------------
# Port scan
# ----------------------------------------------------------------------
def test_port_scan_detected_across_many_ports(policy):
    eng = make_engine(policy, [PortScanDetector(window=10, threshold=15)])
    alerts = []
    for port in range(1, 21):
        alerts += eng.observe(Frame(src_mac=STAFF_3, ts=port * 0.1, dst_port=port))
    assert len(alerts) >= 1
    assert alerts[0].detector == "port-scan" and alerts[0].action == "quarantine"
 
 
def test_repeated_same_port_is_not_a_scan(policy):
    eng = make_engine(policy, [PortScanDetector(window=10, threshold=15)])
    alerts = []
    for i in range(100):
        alerts += eng.observe(Frame(src_mac=STAFF_1, ts=i * 0.05, dst_port=80))
    assert alerts == []
 
 
# ----------------------------------------------------------------------
# Engine behaviour
# ----------------------------------------------------------------------
def test_cooldown_suppresses_repeat_alerts(policy):
    eng = DetectionEngine(policy, [ArpSpoofDetector()], cooldown=10.0)
    spoof = lambda t: Frame(src_mac=STAFF_3, ts=t, arp_op=2, arp_psrc="10.0.0.1")
    assert len(eng.observe(spoof(0.0))) == 1
    assert eng.observe(spoof(2.0)) == []        # inside cooldown
    assert len(eng.observe(spoof(11.0))) == 1   # cooldown expired
 
 
def test_default_engine_has_all_six_detectors(policy):
    names = {d.name for d in default_detectors()}
    assert names == {"arp-spoof", "vlan-violation", "unauthorized-device",
                     "mac-flood", "traffic-rate", "port-scan"}
 
 
def test_clean_traffic_produces_no_alerts_with_full_engine(policy):
    """Normal policy-compliant traffic must stay quiet across every detector."""
    eng = make_engine(policy)
    alerts = []
    frames = [
        Frame(src_mac=STAFF_1, ts=1.0, vlan=10, arp_op=2, arp_psrc="10.0.0.1"),
        Frame(src_mac=STAFF_3, ts=1.5, vlan=10, dst_port=80, src_ip="10.0.0.3"),
        Frame(src_mac=GUEST_2, ts=2.0, vlan=20, dst_port=443, src_ip="10.0.0.2"),
        Frame(src_mac=GUEST_4, ts=2.5, vlan=20, arp_op=1, arp_psrc="10.0.0.4"),
    ]
    for f in frames:
        alerts += eng.observe(f)
    assert alerts == [], [a.message for a in alerts]
 