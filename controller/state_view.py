"""Builds the dashboard's /state payload from controller data.
Pure function (no Ryu imports) so it can be unit-tested."""


def build_state(vlan_manager, ips, policy_vlans, locations, quarantined,
                seen_macs, switches):
    """
    vlan_manager  object with get_vlan(mac) / get_role(mac)   (current values)
    ips           {mac: ip or None}                           (from policy)
    policy_vlans  {mac: vlan}                                 (policy values)
    locations     {mac: {"dpid": int, "port": int}}           (access ports only)
    quarantined   {mac: {"reason": str, "ts": float}}
    seen_macs     iterable of every MAC the controller has learned
    switches      iterable of connected dpids
    """
    macs = set(policy_vlans) | set(seen_macs) | set(locations) | set(quarantined)
    hosts = []
    for mac in sorted(macs):
        in_policy = mac in policy_vlans
        loc = locations.get(mac)
        if mac in quarantined:
            status = "quarantined"
        elif not in_policy:
            status = "unknown"
        elif loc:
            status = "online"
        else:
            status = "offline"
        hosts.append({
            "mac": mac,
            "ip": ips.get(mac),
            "role": vlan_manager.get_role(mac),
            "vlan": vlan_manager.get_vlan(mac),
            "policy_vlan": policy_vlans.get(mac),
            "status": status,
            "location": dict(loc) if loc else None,
            "reason": quarantined.get(mac, {}).get("reason"),
        })

    vlans = {}
    for h in hosts:
        if h["status"] != "offline":
            vlans[str(h["vlan"])] = vlans.get(str(h["vlan"]), 0) + 1

    return {
        "hosts": hosts,
        "quarantined": sorted(quarantined),
        "vlans": vlans,
        "switches": sorted(switches),
    }
