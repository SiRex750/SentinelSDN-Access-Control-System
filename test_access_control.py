#!/usr/bin/env python3
"""Automated verification and regression tests for SDN access-control policy."""

import sys
import time

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


class AccessControlTopology(Topo):
    def build(self):
        switch = self.addSwitch("s1", protocols="OpenFlow10")
        for host_name, host_ip in [
            ("h1", "10.0.0.1/24"),
            ("h2", "10.0.0.2/24"),
            ("h3", "10.0.0.3/24"),
            ("h4", "10.0.0.4/24"),
        ]:
            host = self.addHost(host_name, ip=host_ip)
            self.addLink(host, switch)


def ping_once(src, dst):
    output = src.cmd("ping -c 2 -W 1 {}".format(dst.IP()))
    return "0% packet loss" in output or "1% packet loss" in output


def run_case(hosts, src_name, dst_name, expected):
    src = hosts[src_name]
    dst = hosts[dst_name]
    actual = ping_once(src, dst)
    status = "PASS" if actual == expected else "FAIL"
    expectation = "ALLOW" if expected else "DENY"
    print("[{}] {} -> {} expected={} actual={}".format(
        status,
        src_name,
        dst_name,
        expectation,
        "ALLOW" if actual else "DENY",
    ))
    return actual == expected


def check_deny_flow_installed(switch):
    flows = switch.cmd("ovs-ofctl dump-flows s1")
    return "priority=200" in flows


def main():
    setLogLevel("warning")

    net = Mininet(
        topo=AccessControlTopology(),
        controller=RemoteController("c0", ip="127.0.0.1", port=6633),
        switch=OVSSwitch,
        autoSetMacs=True,
    )

    net.start()
    time.sleep(2)

    hosts = {
        "h1": net.get("h1"),
        "h2": net.get("h2"),
        "h3": net.get("h3"),
        "h4": net.get("h4"),
    }
    switch = net.get("s1")

    base_cases = [
        ("h1", "h2", True),
        ("h2", "h3", True),
        ("h3", "h1", True),
        ("h4", "h1", False),
        ("h4", "h2", False),
        ("h4", "h3", False),
    ]

    print("=== Verification Tests ===")
    results = [run_case(hosts, src, dst, expected) for src, dst, expected in base_cases]

    print("\n=== Regression Tests (repeat policy checks) ===")
    results.extend(run_case(hosts, src, dst, expected) for src, dst, expected in base_cases)

    deny_flow_ok = check_deny_flow_installed(switch)
    print("\n[{}] deny flow rule installed (priority=200)".format("PASS" if deny_flow_ok else "FAIL"))
    results.append(deny_flow_ok)

    passed = sum(1 for item in results if item)
    total = len(results)
    failed = total - passed
    print("\nSummary: {} passed, {} failed".format(passed, failed))

    net.stop()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
