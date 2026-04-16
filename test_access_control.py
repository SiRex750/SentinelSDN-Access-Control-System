#!/usr/bin/env python3
"""Policy-matrix verification and regression tests for SDN access control."""

import json
import os
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


def load_policy(policy_path="policy.json"):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    resolved_path = policy_path
    if not os.path.isabs(policy_path):
        resolved_path = os.path.join(current_dir, policy_path)

    with open(resolved_path, "r") as policy_file:
        payload = json.load(policy_file)

    mode = payload.get("policy_mode", "strict")
    authorized = set(payload.get("authorized_hosts", []))
    allowed_pairs = {
        (pair[0], pair[1])
        for pair in payload.get("allowed_pairs", [])
        if isinstance(pair, list) and len(pair) == 2
    }
    return {
        "mode": mode,
        "authorized": authorized,
        "pairs": allowed_pairs,
    }


def run_ping(src, dst):
    output = src.cmd("ping -c 2 -W 1 {}".format(dst.IP()))
    packet_loss = "100% packet loss" in output
    return not packet_loss


def expected_policy(src, dst, policy):
    if policy["mode"] == "pair":
        return (src.IP(), dst.IP()) in policy["pairs"]
    return src.IP() in policy["authorized"] and dst.IP() in policy["authorized"]


def validate_case(src, dst, policy):
    expected = expected_policy(src, dst, policy)
    actual = run_ping(src, dst)
    status = "PASS" if actual == expected else "FAIL"
    print("[{}] {}({}) -> {}({}) expected={} actual={}".format(
        status,
        src.name,
        src.IP(),
        dst.name,
        dst.IP(),
        "ALLOW" if expected else "DENY",
        "ALLOW" if actual else "DENY",
    ))
    return actual == expected


def check_rule_installation(switch):
    flows = switch.cmd("ovs-ofctl dump-flows s1")
    has_deny = "priority=200" in flows
    has_allow = "priority=100" in flows
    return has_allow and has_deny


def run_policy_matrix(hosts, policy):
    host_list = [hosts["h1"], hosts["h2"], hosts["h3"], hosts["h4"]]
    results = []
    for src in host_list:
        for dst in host_list:
            if src == dst:
                continue
            results.append(validate_case(src, dst, policy))
    return results


def main():
    setLogLevel("warning")
    policy = load_policy()

    print("Loaded policy mode: {}".format(policy["mode"]))
    print("Authorized hosts: {}".format(sorted(policy["authorized"])))
    if policy["pairs"]:
        print("Allowed pairs: {}".format(sorted(policy["pairs"])))

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

    print("=== Verification: Full Host-Pair Policy Matrix ===")
    results = run_policy_matrix(hosts, policy)

    print("\n=== Regression: Re-run Full Matrix ===")
    results.extend(run_policy_matrix(hosts, policy))

    flow_rules_ok = check_rule_installation(switch)
    print("\n[{}] flow rules include both allow(priority=100) and deny(priority=200)".format(
        "PASS" if flow_rules_ok else "FAIL"
    ))
    results.append(flow_rules_ok)

    passed = sum(1 for item in results if item)
    total = len(results)
    failed = total - passed
    print("\nSummary: {} passed, {} failed".format(passed, failed))

    net.stop()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
