#!/usr/bin/env python3
"""
Module 1 — Network Topology

Two OpenFlow switches (s1, s2) connected by a trunk link, with two hosts
on each switch. Port numbers are pinned explicitly so they always match
config/switch_ports.json.

    h1 --(p1)   s1(p3)===trunk===(p3)s2   (p1)-- h3
    h2 --(p2)                              (p2)-- h4

Run directly:
    sudo python3 topo.py
or via mn:
    sudo mn --custom topo.py --topo vlantopo --controller=remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow13
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import Link
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo


class VlanTopo(Topo):
    """Topology class so this file also works with `mn --custom`."""

    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", protocols="OpenFlow13")

        h1 = self.addHost("h1", mac="00:00:00:00:00:01", ip="10.0.0.1/24")
        h2 = self.addHost("h2", mac="00:00:00:00:00:02", ip="10.0.0.2/24")
        h3 = self.addHost("h3", mac="00:00:00:00:00:03", ip="10.0.0.3/24")
        h4 = self.addHost("h4", mac="00:00:00:00:00:04", ip="10.0.0.4/24")

        # Access links — explicit ports so they match switch_ports.json
        self.addLink(h1, s1, port2=1)
        self.addLink(h2, s1, port2=2)
        self.addLink(h3, s2, port2=1)
        self.addLink(h4, s2, port2=2)

        # Trunk link between switches — port 3 on each side
        self.addLink(s1, s2, port1=3, port2=3)


def run():
    net = Mininet(
        topo=VlanTopo(),
        switch=OVSSwitch,
        controller=None,
        autoSetMacs=False,
    )
    net.addController(
        "c0", controller=RemoteController, ip="127.0.0.1", port=6633
    )
    net.start()

    info("\n*** VLAN SDN demo topology up.\n")
    info("*** h1,h3 = policy VLAN10 (staff) | h2,h4 = policy VLAN20 (guest)\n")
    info("*** Try: pingall   (same-VLAN pairs should succeed, cross-VLAN should fail)\n\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
