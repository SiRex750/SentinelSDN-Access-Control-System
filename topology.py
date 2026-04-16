#!/usr/bin/env python3
"""Mininet topology for SDN whitelist access-control demo."""

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


class AccessControlTopology(Topo):
    def build(self):
        switch = self.addSwitch("s1", protocols="OpenFlow10")
        hosts = [
            ("h1", "10.0.0.1/24"),
            ("h2", "10.0.0.2/24"),
            ("h3", "10.0.0.3/24"),
            ("h4", "10.0.0.4/24"),
        ]

        for name, ip in hosts:
            host = self.addHost(name, ip=ip)
            self.addLink(host, switch)


def main():
    setLogLevel("info")

    network = Mininet(
        topo=AccessControlTopology(),
        switch=OVSSwitch,
        controller=RemoteController("c0", ip="127.0.0.1", port=6633),
        autoSetMacs=True,
    )

    network.start()
    info("\n*** SDN access-control topology is running\n")
    info("*** Authorized hosts: h1, h2, h3\n")
    info("*** Unauthorized host: h4\n")
    info("*** Try: h1 ping -c 2 h2 and h4 ping -c 2 h1\n\n")

    CLI(network)
    network.stop()


if __name__ == "__main__":
    main()
