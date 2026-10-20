#!/usr/bin/env python3
"""
Module 2 — Context-Aware Dynamic VLAN Assignment (Ryu / OpenFlow 1.3)

Core idea: VLAN membership is decided by looking up the SENDER'S MAC
address in a policy table (config/vlan_policy.json), not by which
physical switch port it happens to be plugged into. The same policy
file governs every switch in the topology, so a host is assigned the
same VLAN no matter where in the network it connects from -- this is
the concrete proof-of-concept for "dynamic, identity-based VLAN
assignment" vs. traditional static port-to-VLAN config.

Run:
    ryu-manager controller/vlan_controller.py
"""

import json
import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types

from ryu.app.wsgi import ControllerBase, WSGIApplication, route, Response

from vlan_manager import VLANManager
from mobility_manager import MobilityManager
from alert_store import AlertStore
from state_view import build_state

import re

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(BASE_DIR, "config", "vlan_policy.json")
DASHBOARD_PATH = os.path.join(BASE_DIR, "dashboard", "index.html")
PORTS_PATH = os.path.join(BASE_DIR, "config", "switch_ports.json")

FLOW_IDLE_TIMEOUT = 15
FLOW_PRIORITY_DIRECT = 10
FLOW_PRIORITY_TABLE_MISS = 0


class VlanController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(VlanController, self).__init__(*args, **kwargs)

        # { dpid: { mac: (port, vlan) } }  -- what the controller has learned
        self.mac_table = {}

        # { dpid: datapath }  -- needed so we can push flow-deletes to
        # EVERY switch when a host moves, not just the one it moved to/from.
        self.datapaths = {}

        self._load_config()
        with open(POLICY_PATH) as f:
            self.ips = {m.lower(): e.get("ip")
                        for m, e in json.load(f)["policy"].items()}
        self.alerts = AlertStore()
        self.quarantined = {}   # mac -> {"reason": str, "ts": float}
        self.vlan_manager = VLANManager({
            "policy": {
                mac: {
                    "vlan": vlan,
                    "role": self.roles.get(mac, "unauthenticated"),
                }
                for mac, vlan in self.policy.items()
            },
            "default_vlan": self.default_vlan,
            "default_role": "unauthenticated",
        })

        self.mobility_manager = MobilityManager(self.trunk_ports)

        # Module 4: expose the REST hook the anomaly detector calls.
        wsgi = kwargs["wsgi"]
        wsgi.register(QuarantineController, {"app": self})

        self.logger.info("[INIT] Loaded VLAN policy for %d known hosts",
                          len(self.policy))
        self.logger.info("[INIT] Default/unassigned-host VLAN = %s",
                          self.default_vlan)

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------
    def _load_config(self):
        with open(POLICY_PATH) as f:
            pdata = json.load(f)
        self.policy = {
            mac.lower(): entry["vlan"] for mac, entry in pdata["policy"].items()
        }
        self.roles = {
            mac.lower(): entry["role"] for mac, entry in pdata["policy"].items()
        }
        self.default_vlan = pdata.get("default_vlan", 99)

        with open(PORTS_PATH) as f:
            sdata = json.load(f)
        # { dpid(int): set(trunk_ports) }
        self.trunk_ports = {
            int(dpid): set(entry["trunk_ports"])
            for dpid, entry in sdata["switches"].items()
        }

    def _vlan_for(self, mac):
        mac = mac.lower()
        return self.policy.get(mac, self.default_vlan)

    def _role_for(self, mac):
        mac = mac.lower()
        return self.roles.get(mac, self.default_role_name())

    def default_role_name(self):
        return "unauthenticated"

    def _is_trunk(self, dpid, port):
        return port in self.trunk_ports.get(dpid, set())

    # ------------------------------------------------------------------
    # Switch connect -> install table-miss flow
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, FLOW_PRIORITY_TABLE_MISS, match, actions)

        self.mac_table.setdefault(datapath.id, {})
        self.datapaths[datapath.id] = datapath
        self.logger.info("[SWITCH] dpid=%s connected, table-miss flow installed",
                          datapath.id)

    def _flush_flows_for_mac(self, mac):
        """Delete any installed flow, on any switch, that matches this MAC
        as either source or destination. Called the moment mobility_manager
        confirms a host has moved, so a stale cached flow from its old
        location can never blackhole traffic -- the next packet for this
        host is forced back through packet_in for a fresh decision."""
        flushed = 0
        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            for match in (parser.OFPMatch(eth_src=mac), parser.OFPMatch(eth_dst=mac)):
                mod = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match,
                )
                datapath.send_msg(mod)
            flushed += 1
        self.logger.info("[MOBILITY] flushed cached flows for %s across %d switch(es)",
                          mac, flushed)

    # ------------------------------------------------------------------
    # Module 4: security-reactive response
    # ------------------------------------------------------------------
    def _set_host_vlan(self, mac, vlan, role):
        """Change a host's VLAN everywhere the controller tracks it:
        the policy manager, the learned table on every switch, and any
        cached flows. Shared by quarantine and release."""
        self.vlan_manager.update_assignment(mac, vlan, role=role)

        # Keep the learned table consistent so other hosts' unicast
        # lookups see the new VLAN immediately, not after the next packet.
        for dpid, table in self.mac_table.items():
            if mac in table:
                port, _ = table[mac]
                table[mac] = (port, vlan)

        self._flush_flows_for_mac(mac)

    def quarantine_host(self, mac, reason="unspecified"):
        mac = mac.lower()
        q_vlan = self.vlan_manager.default_vlan  # 99 by policy
        self._set_host_vlan(mac, q_vlan, role="quarantined")
        self.quarantined[mac] = {"reason": reason, "ts": time.time()}
        self.alerts.add_event("quarantine", "VLAN %s: %s" % (q_vlan, reason), mac=mac)
        self.logger.warning(
            "[QUARANTINE] host=%s moved to isolated VLAN=%s (reason: %s)",
            mac, q_vlan, reason,
        )
        return {"status": "quarantined", "mac": mac, "vlan": q_vlan, "reason": reason}

    def release_host(self, mac):
        mac = mac.lower()
        original_vlan = self.policy.get(mac, self.default_vlan)
        original_role = self.roles.get(mac, "unauthenticated")
        self._set_host_vlan(mac, original_vlan, role=original_role)
        self.quarantined.pop(mac, None)
        self.alerts.add_event("release", "restored to VLAN %s (%s)" % (original_vlan, original_role), mac=mac)
        self.logger.info(
            "[RELEASE] host=%s restored to policy VLAN=%s role=%s",
            mac, original_vlan, original_role,
        )
        return {"status": "released", "mac": mac, "vlan": original_vlan, "role": original_role}

    def state_snapshot(self):
        seen = {mac for table in self.mac_table.values() for mac in table}
        return build_state(
            self.vlan_manager, self.ips, self.policy,
            dict(self.mobility_manager.locations), self.quarantined,
            seen, self.datapaths.keys())

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
        )
        datapath.send_msg(mod)

    # ------------------------------------------------------------------
    # Packet-in: the core dynamic-VLAN decision logic
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # ignore LLDP / malformed frames

        src, dst = eth.src, eth.dst
        self.mac_table.setdefault(dpid, {})

        context = self.vlan_manager.get_context(src)
        src_vlan = context["vlan"]
        role = context["role"]

        # ---- Learn / detect mobility ----
        prev = self.mac_table[dpid].get(src)

        moved, previous = self.mobility_manager.update_location(
            src,
            dpid,
            in_port,
        )

        if moved:
            self.logger.info(
                "[MOBILITY] host=%s moved from dpid=%s port=%s "
                "to dpid=%s port=%s",
                src,
                previous["dpid"],
                previous["port"],
                dpid,
                in_port,
            )
            self.alerts.add_event(
                "mobility",
                "dpid %s port %s -> dpid %s port %s" % (
                    previous["dpid"], previous["port"], dpid, in_port),
                mac=src)
            # Any flow cached anywhere in the topology that references this
            # host's MAC (as either src or dst) now points at a stale port
            # and will silently blackhole traffic until it idle-times-out.
            # Flush it immediately instead of waiting on the timeout.
            self._flush_flows_for_mac(src)
            # Also drop the stale learned entry on the switch it left, so
            # that switch doesn't keep offering a dead port as a forwarding
            # target for this host.
            old_table = self.mac_table.get(previous["dpid"])
            if old_table is not None:
                old_table.pop(src, None)

        if prev is None or prev[0] != in_port or prev[1] != src_vlan:
            self.logger.info(
                "[VLAN-ASSIGN] host=%s role=%s -> VLAN=%s (dpid=%s port=%s)%s",
                src,
                role,
                src_vlan,
                dpid,
                in_port,
                " <-- re-learned (mobility)" if prev else "",
            )

        self.mac_table[dpid][src] = (in_port, src_vlan)

        # ---- Decide output ports, scoped strictly to src_vlan ----
        out_ports = self._resolve_output_ports(dpid, in_port, dst, src_vlan)

        if not out_ports:
            return  # nothing valid to forward to (e.g. isolated / unknown)

        actions = []

        for out_port in out_ports:
            actions.extend(
                self._vlan_actions(
                    parser,
                    dpid,
                    in_port,
                    out_port,
                    src_vlan,
                )
            )

        # If exactly one known unicast destination on this switch and it's
        # in the same VLAN, install a direct flow so future packets skip
        # the controller.
        if len(out_ports) == 1 and dst in self.mac_table[dpid]:
            dst_port, dst_vlan = self.mac_table[dpid][dst]
            if dst_vlan == src_vlan:
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst, vlan_vid=0)
                flow_actions = self._vlan_actions(parser, dpid, in_port, dst_port, src_vlan)
                self._add_flow(datapath, FLOW_PRIORITY_DIRECT, match, flow_actions,
                                idle_timeout=FLOW_IDLE_TIMEOUT)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def _resolve_output_ports(self, dpid, in_port, dst, src_vlan):
        """Return the list of ports to send a frame out of, enforcing
        that traffic only ever reaches ports belonging to the SAME
        VLAN as the sender -- this is the segmentation enforcement
        step. Trunk ports are always included (except the one the
        frame arrived on) so other switches can apply the same rule."""
        table = self.mac_table[dpid]

        # Known unicast destination on this switch
        if dst in table:
            dst_port, dst_vlan = table[dst]
            if dst_vlan != src_vlan:
                return []  # different VLAN on same switch -> blocked
            return [dst_port] if dst_port != in_port else []

        # Broadcast / multicast / unknown unicast -> flood within VLAN
        out_ports = []
        for mac, (port, vlan) in table.items():
            if port == in_port:
                continue
            if self._is_trunk(dpid, port):
                continue  # trunk ports handled separately below
            if vlan == src_vlan:
                out_ports.append(port)

        for port in self.trunk_ports.get(dpid, set()):
            if port != in_port:
                out_ports.append(port)

        return out_ports
    
    def _vlan_actions(self, parser, dpid, in_port, out_port, vlan):
        """
        Apply VLAN tagging when forwarding between access and trunk ports.
        """
        trunk_ports = self.trunk_ports.get(dpid, set())

        actions = []

        if in_port not in trunk_ports and out_port in trunk_ports:
            actions.append(parser.OFPActionPushVlan(0x8100))
            actions.append(parser.OFPActionSetField(vlan_vid=0x1000 | vlan))

        elif in_port in trunk_ports and out_port not in trunk_ports:
            actions.append(parser.OFPActionPopVlan())

        actions.append(parser.OFPActionOutput(out_port))
        return actions


class QuarantineController(ControllerBase):
    """REST API used by the sensor (detection/sensor.py) and the dashboard.
    POST /quarantine {"mac": "...", "reason": "..."}
    POST /release    {"mac": "..."}
    """

    def __init__(self, req, link, data, **config):
        super(QuarantineController, self).__init__(req, link, data, **config)
        self.app = data["app"]

    def _reply(self, status, payload):
        return Response(
            status=status,
            content_type="application/json",
            body=json.dumps(payload).encode("utf-8"),
        )

    def _parse(self, req):
        try:
            body = json.loads(req.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None, "body must be valid JSON"
        mac = str(body.get("mac", "")).lower()
        if not MAC_RE.match(mac):
            return None, "missing or malformed 'mac'"
        return body, mac

    @route("warden", "/quarantine", methods=["POST"])
    def quarantine(self, req, **kwargs):
        body, result = self._parse(req)
        if body is None:
            return self._reply(400, {"error": result})
        return self._reply(200, self.app.quarantine_host(
            result, reason=body.get("reason", "unspecified")))

    @route("warden", "/release", methods=["POST"])
    def release(self, req, **kwargs):
        body, result = self._parse(req)
        if body is None:
            return self._reply(400, {"error": result})
        return self._reply(200, self.app.release_host(result))

    # ---- Dashboard + read/write API (Priority 1) ----
    @route("warden", "/", methods=["GET"])
    def dashboard(self, req, **kwargs):
        try:
            with open(DASHBOARD_PATH, "rb") as f:
                body = f.read()
        except OSError:
            return Response(status=404, body=b"dashboard/index.html not found")
        return Response(content_type="text/html", charset="utf-8", body=body)

    @route("warden", "/state", methods=["GET"])
    def state(self, req, **kwargs):
        return self._reply(200, self.app.state_snapshot())

    @route("warden", "/alerts", methods=["GET"])
    def list_alerts(self, req, **kwargs):
        try:
            limit = int(req.GET.get("limit", 100))
        except ValueError:
            limit = 100
        store = self.app.alerts
        return self._reply(200, {"alerts": store.list_alerts(limit),
                                 "events": store.list_events(50),
                                 "counts": store.counts()})

    @route("warden", "/alerts", methods=["POST"])
    def add_alert(self, req, **kwargs):
        try:
            body = json.loads(req.body.decode("utf-8"))
            alert = self.app.alerts.add_alert(body)
        except (ValueError, UnicodeDecodeError) as e:
            return self._reply(400, {"error": str(e)})
        return self._reply(200, alert)

    @route("warden", "/alerts/clear", methods=["POST"])
    def clear_alerts(self, req, **kwargs):
        self.app.alerts.clear_alerts()
        return self._reply(200, {"status": "cleared"})