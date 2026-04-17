"""POX controller for a whitelist-based SDN access control system."""

import ipaddress
import json
import os

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str

log = core.getLogger()


class AccessPolicy(object):
    """Loads and evaluates whitelist policy from JSON."""

    def __init__(self, policy_path):
        self.policy_path = policy_path
        self.authorized_hosts = set()
        self.allowed_pairs = set()
        self.policy_mode = "strict"
        self.load()

    def load(self):
        with open(self.policy_path, "r") as policy_file:
            payload = json.load(policy_file)

        raw_hosts = payload.get("authorized_hosts", [])
        if not isinstance(raw_hosts, list):
            raise ValueError("authorized_hosts must be a list")

        self.authorized_hosts = {self._validate_ip(ip) for ip in raw_hosts}
        if not self.authorized_hosts:
            raise ValueError("Policy has no authorized hosts")

        self.policy_mode = payload.get("policy_mode", "strict")
        if self.policy_mode not in {"strict", "pair"}:
            raise ValueError("policy_mode must be either 'strict' or 'pair'")

        self.allowed_pairs = set()
        raw_pairs = payload.get("allowed_pairs", [])
        if not isinstance(raw_pairs, list):
            raise ValueError("allowed_pairs must be a list")

        for pair in raw_pairs:
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError("Each allowed_pairs entry must contain exactly 2 IPs")
            src = self._validate_ip(pair[0])
            dst = self._validate_ip(pair[1])
            self.allowed_pairs.add((src, dst))

    def _validate_ip(self, ip_text):
        return str(ipaddress.ip_address(ip_text))

    def allows(self, src_ip, dst_ip):
        if self.policy_mode == "pair":
            return (src_ip, dst_ip) in self.allowed_pairs
        return src_ip in self.authorized_hosts and dst_ip in self.authorized_hosts

    def decision_reason(self, src_ip, dst_ip):
        if self.policy_mode == "pair":
            return "pair-policy-match" if (src_ip, dst_ip) in self.allowed_pairs else "pair-policy-miss"
        if src_ip not in self.authorized_hosts:
            return "source-not-whitelisted"
        if dst_ip not in self.authorized_hosts:
            return "destination-not-whitelisted"
        return "strict-policy-match"


class AccessControlController(object):
    """OpenFlow 1.0 controller that enforces whitelist access policy."""

    def __init__(self, policy_path):
        self.mac_to_port = {}
        self.policy = AccessPolicy(policy_path)
        core.openflow.addListeners(self)
        log.info("AccessControlController started")
        log.info("Policy path: %s", policy_path)
        log.info("Policy mode: %s", self.policy.policy_mode)
        log.info("Authorized hosts: %s", sorted(self.policy.authorized_hosts))
        if self.policy.allowed_pairs:
            log.info("Allowed pairs: %s", sorted(self.policy.allowed_pairs))

    def _handle_ConnectionUp(self, event):
        self.mac_to_port[event.dpid] = {}
        dpid = dpid_to_str(event.dpid)
        log.info("Switch connected: %s", dpid)

        miss = of.ofp_flow_mod()
        miss.priority = 0
        miss.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(miss)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        dpid = event.dpid
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][packet.src] = event.port

        ip_packet = packet.find("ipv4")
        if ip_packet is None:
            self._forward_packet(event, packet)
            return

        src_ip = str(ip_packet.srcip)
        dst_ip = str(ip_packet.dstip)
        reason = self.policy.decision_reason(src_ip, dst_ip)

        if self.policy.allows(src_ip, dst_ip):
            log.info("ALLOW %s -> %s (%s)", src_ip, dst_ip, reason)
            self._install_allow_rule(event, packet, ip_packet)
            return

        log.warning("DENY %s -> %s (%s)", src_ip, dst_ip, reason)
        self._install_deny_rule(event, ip_packet)

    def _install_allow_rule(self, event, packet, ip_packet):
        out_port = self.mac_to_port[event.dpid].get(packet.dst, of.OFPP_FLOOD)

        flow = of.ofp_flow_mod()
        flow.priority = 100
        flow.idle_timeout = 20
        flow.hard_timeout = 120
        flow.match.dl_type = 0x0800
        flow.match.nw_src = ip_packet.srcip
        flow.match.nw_dst = ip_packet.dstip
        flow.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(flow)

        packet_out = of.ofp_packet_out()
        packet_out.data = event.ofp
        packet_out.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(packet_out)

    def _install_deny_rule(self, event, ip_packet):
        flow = of.ofp_flow_mod()
        flow.priority = 200
        flow.idle_timeout = 30
        flow.hard_timeout = 300
        flow.match.dl_type = 0x0800
        flow.match.nw_src = ip_packet.srcip
        # Use src+dst deny match so one denied destination does not block all
        # future traffic from the same source host in pair-based policies.
        flow.match.nw_dst = ip_packet.dstip
        event.connection.send(flow)

    def _forward_packet(self, event, packet):
        out_port = self.mac_to_port[event.dpid].get(packet.dst, of.OFPP_FLOOD)
        packet_out = of.ofp_packet_out()
        packet_out.data = event.ofp
        packet_out.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(packet_out)


def launch(policy_path="policy.json"):
    base_dir = os.path.dirname(__file__)
    resolved_path = policy_path
    if not os.path.isabs(policy_path):
        resolved_path = os.path.join(base_dir, policy_path)
    core.registerNew(AccessControlController, resolved_path)
