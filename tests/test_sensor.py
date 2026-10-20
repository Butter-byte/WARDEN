"""Sensor tests: real Scapy packets -> Frame, and the sensor's response logic
with a fake controller. No Mininet or Ryu needed."""

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "detection"))

scapy = pytest.importorskip("scapy")
from scapy.all import ARP, IP, TCP, UDP, Dot1Q, Ether, IPv6  # noqa: E402

from engine import DetectionEngine, Policy, default_detectors  # noqa: E402
from sensor import Sensor, packet_to_frame  # noqa: E402

H1, H3 = "00:00:00:00:00:01", "00:00:00:00:00:03"


def reparse(pkt):
    """Round-trip through bytes, exactly like a captured packet."""
    return Ether(bytes(pkt))


# ---------------- packet -> Frame ----------------
def test_arp_reply_is_parsed():
    pkt = reparse(Ether(src=H3, dst="ff:ff:ff:ff:ff:ff") /
                  ARP(op=2, psrc="10.0.0.1", hwsrc=H3, pdst="10.0.0.1"))
    f = packet_to_frame(pkt, ts=5.0)
    assert (f.src_mac, f.arp_op, f.arp_psrc, f.vlan, f.ts) == (H3, 2, "10.0.0.1", None, 5.0)


def test_single_tag_is_outer_vlan_only():
    pkt = reparse(Ether(src=H1, dst=H3) / Dot1Q(vlan=10) / IP(dst="10.0.0.3") / UDP())
    f = packet_to_frame(pkt, ts=1)
    assert f.vlan == 10 and f.inner_vlan is None and f.dst_ip == "10.0.0.3"


def test_double_tag_populates_inner_vlan():
    pkt = reparse(Ether(src=H1, dst=H3) / Dot1Q(vlan=10) / Dot1Q(vlan=20) / IP() / UDP())
    f = packet_to_frame(pkt, ts=1)
    assert (f.vlan, f.inner_vlan) == (10, 20)


def test_tcp_syn_gives_dst_port():
    pkt = reparse(Ether(src=H3, dst=H1) / IP(dst="10.0.0.1") / TCP(dport=22, flags="S"))
    assert packet_to_frame(pkt, ts=1).dst_port == 22


def test_tcp_synack_and_ack_do_not_count_as_scan_probes():
    for flags in ("SA", "A", "PA", "R"):
        pkt = reparse(Ether(src=H3, dst=H1) / IP(dst="10.0.0.1") / TCP(dport=50000, flags=flags))
        assert packet_to_frame(pkt, ts=1).dst_port is None, flags


def test_udp_has_no_port_for_scan_detection():
    pkt = reparse(Ether(src=H3, dst=H1) / IP(dst="10.0.0.1") / UDP(dport=9))
    assert packet_to_frame(pkt, ts=1).dst_port is None


def test_ipv6_multicast_noise_is_ignored():
    pkt = reparse(Ether(src="02:aa:bb:cc:dd:ee", dst="33:33:00:00:00:02") / IPv6())
    assert packet_to_frame(pkt, ts=1) is None


def test_stp_lldp_control_frames_are_ignored():
    assert packet_to_frame(Ether(src=H1, dst="01:80:c2:00:00:0e"), ts=1) is None


def test_ignore_mac_flag():
    pkt = Ether(src=H3, dst=H1) / IP() / UDP()
    assert packet_to_frame(pkt, ts=1, ignore_macs=frozenset({H3})) is None


def test_non_ethernet_packet_is_skipped():
    assert packet_to_frame(IP(dst="10.0.0.1"), ts=1) is None


# ---------------- Sensor decisions ----------------
class FakeClient:
    def __init__(self, reachable=True, remote_q=None):
        self.alerts, self.quarantines = [], []
        self.reachable, self.remote_q = reachable, remote_q or set()

    def post_alert(self, a):
        self.alerts.append(a); return self.reachable

    def quarantine(self, mac, reason):
        if self.reachable:
            self.quarantines.append((mac, reason))
        return self.reachable

    def quarantined_macs(self):
        return set(self.remote_q) if self.reachable else None


@pytest.fixture
def make_sensor():
    with open(os.path.join(ROOT, "config", "vlan_policy.json")) as f:
        policy = Policy(json.load(f))

    def build(client=None, respond=True):
        eng = DetectionEngine(policy, default_detectors(), cooldown=0.0)
        c = client or FakeClient()
        logs = []
        return Sensor(eng, c, respond=respond, out=logs.append), c, eng, logs
    return build


def spoof_pkt():
    return reparse(Ether(src=H3, dst="ff:ff:ff:ff:ff:ff") /
                   ARP(op=2, psrc="10.0.0.1", hwsrc=H3, pdst="10.0.0.1"))


def test_spoof_posts_alert_and_quarantines(make_sensor):
    s, c, eng, _ = make_sensor()
    s.handle(spoof_pkt())
    assert [a["detector"] for a in c.alerts] == ["arp-spoof"]
    assert [m for m, _ in c.quarantines] == [H3]
    assert H3 in eng.quarantined


def test_quarantine_requested_only_once_per_host(make_sensor):
    s, c, _, _ = make_sensor()
    for _ in range(5):
        s.handle(spoof_pkt())
    assert len(c.quarantines) == 1


def test_no_respond_mode_alerts_but_never_quarantines(make_sensor):
    s, c, eng, logs = make_sensor(respond=False)
    s.handle(spoof_pkt())
    assert len(c.alerts) == 1 and c.quarantines == [] and not eng.quarantined
    assert any("would quarantine" in l for l in logs)


def test_failed_quarantine_is_rolled_back_so_it_can_retry(make_sensor):
    s, c, eng, _ = make_sensor(FakeClient(reachable=False))
    s.handle(spoof_pkt())
    assert H3 not in eng.quarantined


def test_alert_only_detector_never_quarantines(make_sensor):
    s, c, _, _ = make_sensor()
    s.handle(reparse(Ether(src="02:de:ad:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst="10.0.0.1")))
    assert [a["detector"] for a in c.alerts] == ["unauthorized-device"]
    assert c.quarantines == []


def test_no_vlan_false_positive_for_frames_in_flight_after_quarantine(make_sensor):
    """Host is quarantined; the controller re-tags it VLAN 99. Those frames must
    not trigger a vlan-violation."""
    s, c, _, _ = make_sensor()
    s.handle(spoof_pkt())
    c.alerts.clear()
    s.handle(reparse(Ether(src=H3, dst=H1) / Dot1Q(vlan=99) / IP(dst="10.0.0.1") / UDP()))
    assert [a["detector"] for a in c.alerts if a["detector"] == "vlan-violation"] == []


def test_vlan_hop_is_quarantined(make_sensor):
    s, c, _, _ = make_sensor()
    s.handle(reparse(Ether(src=H1, dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=20) / ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.2")))
    assert "vlan-violation" in [a["detector"] for a in c.alerts]
    assert [m for m, _ in c.quarantines] == [H1]


def test_sync_adopts_dashboard_quarantine_and_honours_release(make_sensor):
    s, c, eng, _ = make_sensor(FakeClient(remote_q={H1}))
    s.sync_once()
    assert H1 in eng.quarantined                 # quarantined from the dashboard
    c.remote_q = set()
    s._marked_at[H1] = 0                         # not a fresh local mark
    s.sync_once()
    assert H1 not in eng.quarantined             # released from the dashboard


def test_sync_does_not_undo_a_fresh_local_quarantine(make_sensor):
    s, c, eng, _ = make_sensor(FakeClient(remote_q=set()))
    s.handle(spoof_pkt())                        # controller state lags briefly
    s.sync_once()
    assert H3 in eng.quarantined


def test_sync_tolerates_unreachable_controller(make_sensor):
    s, _, eng, _ = make_sensor(FakeClient(reachable=False))
    eng.mark_quarantined(H1)
    s.sync_once()
    assert H1 in eng.quarantined
