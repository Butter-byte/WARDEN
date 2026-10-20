"""Tests for the Ryu-independent controller modules: AlertStore, state_view,
VLANManager, MobilityManager."""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "controller"))

from alert_store import AlertStore          # noqa: E402
from mobility_manager import MobilityManager  # noqa: E402
from state_view import build_state          # noqa: E402
from vlan_manager import VLANManager        # noqa: E402

POLICY = {"default_vlan": 99, "default_role": "unauthenticated", "policy": {
    "00:00:00:00:00:01": {"role": "staff", "vlan": 10},
    "00:00:00:00:00:02": {"role": "guest", "vlan": 20}}}


# ---------------- VLANManager ----------------
def test_vlan_lookup_and_defaults():
    m = VLANManager(POLICY)
    assert m.get_vlan("00:00:00:00:00:01") == 10
    assert m.get_vlan("00:00:00:00:00:01".upper()) == 10
    assert m.get_vlan("aa:aa:aa:aa:aa:aa") == 99
    assert m.get_role("aa:aa:aa:aa:aa:aa") == "unauthenticated"


def test_update_assignment_changes_vlan_and_role():
    m = VLANManager(POLICY)
    m.update_assignment("00:00:00:00:00:01", 99, role="quarantined")
    assert m.get_context("00:00:00:00:00:01") == {
        "mac": "00:00:00:00:00:01", "role": "quarantined", "vlan": 99}


# ---------------- MobilityManager ----------------
def test_first_sighting_is_not_a_move():
    mm = MobilityManager({1: {3}, 2: {3}})
    assert mm.update_location("aa:aa:aa:aa:aa:01", 1, 1)[0] is False


def test_move_between_switches_is_detected():
    mm = MobilityManager({1: {3}, 2: {3}})
    mm.update_location("aa:aa:aa:aa:aa:01", 1, 1)
    moved, prev = mm.update_location("aa:aa:aa:aa:aa:01", 2, 4)
    assert moved and prev == {"dpid": 1, "port": 1}


def test_trunk_arrivals_never_count_as_moves():
    mm = MobilityManager({1: {3}, 2: {3}})
    mm.update_location("aa:aa:aa:aa:aa:01", 1, 1)
    assert mm.update_location("aa:aa:aa:aa:aa:01", 2, 3)[0] is False
    assert mm.get_location("aa:aa:aa:aa:aa:01") == {"dpid": 1, "port": 1}


def test_same_port_again_is_not_a_move():
    mm = MobilityManager({1: {3}})
    mm.update_location("aa:aa:aa:aa:aa:01", 1, 1)
    assert mm.update_location("aa:aa:aa:aa:aa:01", 1, 1)[0] is False


# ---------------- AlertStore ----------------
def test_alert_store_newest_first_and_counts():
    s = AlertStore()
    s.add_alert({"detector": "arp-spoof", "mac": "AA:00:00:00:00:01", "message": "x"}, now=1)
    s.add_alert({"detector": "port-scan", "mac": "aa:00:00:00:00:02", "message": "y"}, now=2)
    s.add_alert({"detector": "arp-spoof", "mac": "aa:00:00:00:00:03", "message": "z"}, now=3)
    assert [a["message"] for a in s.list_alerts()] == ["z", "y", "x"]
    assert s.counts() == {"arp-spoof": 2, "port-scan": 1}
    assert s.list_alerts()[2]["mac"] == "aa:00:00:00:00:01"   # normalised


def test_alert_store_defaults_and_validation():
    s = AlertStore()
    a = s.add_alert({"detector": "d", "mac": "m", "message": "x"}, now=10)
    assert a["severity"] == "medium" and a["action"] == "none" and a["ts"] == 10
    for bad in ({}, {"detector": "d"}, {"detector": "d", "mac": "m"}, "nope", None):
        with pytest.raises(ValueError):
            s.add_alert(bad)


def test_alert_store_is_bounded_and_clearable():
    s = AlertStore(max_alerts=3)
    for i in range(10):
        s.add_alert({"detector": "d", "mac": "m", "message": str(i)}, now=i)
    assert [a["message"] for a in s.list_alerts()] == ["9", "8", "7"]
    s.clear_alerts()
    assert s.list_alerts() == []


def test_events_are_separate_from_alerts():
    s = AlertStore()
    s.add_event("quarantine", "VLAN 99", mac="m", now=1)
    assert s.list_alerts() == [] and s.list_events()[0]["kind"] == "quarantine"


# ---------------- state_view ----------------
def make_state(**kw):
    vm = VLANManager(POLICY)
    args = dict(vlan_manager=vm,
                ips={"00:00:00:00:00:01": "10.0.0.1", "00:00:00:00:00:02": "10.0.0.2"},
                policy_vlans={"00:00:00:00:00:01": 10, "00:00:00:00:00:02": 20},
                locations={}, quarantined={}, seen_macs=[], switches=[2, 1])
    args.update(kw)
    return build_state(**args), vm


def test_policy_hosts_without_location_are_offline():
    st, _ = make_state()
    assert {h["status"] for h in st["hosts"]} == {"offline"}
    assert st["switches"] == [1, 2] and st["vlans"] == {}


def test_located_host_is_online_and_counted_in_vlan():
    st, _ = make_state(locations={"00:00:00:00:00:01": {"dpid": 1, "port": 1}})
    h = next(h for h in st["hosts"] if h["mac"] == "00:00:00:00:00:01")
    assert h["status"] == "online" and h["location"] == {"dpid": 1, "port": 1}
    assert st["vlans"] == {"10": 1}


def test_quarantined_host_reports_vlan_99_and_reason():
    q = {"00:00:00:00:00:01": {"reason": "arp-spoof", "ts": 1}}
    vm = VLANManager(POLICY)
    vm.update_assignment("00:00:00:00:00:01", 99, role="quarantined")
    st, _ = make_state(vlan_manager=vm, quarantined=q,
                       locations={"00:00:00:00:00:01": {"dpid": 1, "port": 1}})
    h = next(h for h in st["hosts"] if h["mac"] == "00:00:00:00:00:01")
    assert (h["status"], h["vlan"], h["policy_vlan"], h["reason"]) == ("quarantined", 99, 10, "arp-spoof")
    assert st["quarantined"] == ["00:00:00:00:00:01"]


def test_unregistered_mac_is_listed_as_unknown_in_vlan_99():
    st, _ = make_state(seen_macs=["02:de:ad:00:00:01"])
    h = next(h for h in st["hosts"] if h["mac"] == "02:de:ad:00:00:01")
    assert (h["status"], h["vlan"], h["ip"], h["policy_vlan"]) == ("unknown", 99, None, None)
