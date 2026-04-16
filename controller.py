"""POX controller for a whitelist-based SDN access control system."""

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
        self.load()

    def load(self):
        with open(self.policy_path, "r") as policy_file:
            payload = json.load(policy_file)
        self.authorized_hosts = set(payload.get("authorized_hosts", []))
        if not self.authorized_hosts:
            raise ValueError("Policy has no authorized hosts")

    def allows(self, src_ip, dst_ip):
        return src_ip in self.authorized_hosts and dst_ip in self.authorized_hosts


class AccessControlController(object):
    """OpenFlow 1.0 controller that enforces whitelist access policy."""

    def __init__(self, policy_path):
        self.mac_to_port = {}
        self.policy = AccessPolicy(policy_path)
        core.openflow.addListeners(self)
        log.info("AccessControlController started")
        log.info("Policy path: %s", policy_path)
        log.info("Authorized hosts: %s", sorted(self.policy.authorized_hosts))

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

        if self.policy.allows(src_ip, dst_ip):
            log.info("ALLOW %s -> %s", src_ip, dst_ip)
            self._install_allow_rule(event, packet, ip_packet)
            return

        log.warning("DENY %s -> %s", src_ip, dst_ip)
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
