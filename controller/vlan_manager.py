class VLANManager:
    DEFAULT_VLAN = 99

    def __init__(self, policy):
        self.policy = policy
        self.mac_vlan = {}
        self.mac_role = {}

        for mac, info in policy.get("policy", {}).items():
            mac = mac.lower()
            self.mac_vlan[mac] = int(info["vlan"])
            self.mac_role[mac] = info.get("role", "unknown")

        self.default_vlan = int(
            policy.get("default_vlan", self.DEFAULT_VLAN)
        )
        self.default_role = policy.get("default_role", "unknown")

    def get_vlan(self, mac):
        return self.mac_vlan.get(mac.lower(), self.default_vlan)

    def get_role(self, mac):
        return self.mac_role.get(mac.lower(), self.default_role)

    def get_context(self, mac):
        mac = mac.lower()
        return {
            "mac": mac,
            "role": self.get_role(mac),
            "vlan": self.get_vlan(mac),
        }

    def update_assignment(self, mac, vlan, role=None):
        mac = mac.lower()
        self.mac_vlan[mac] = int(vlan)

        if role is not None:
            self.mac_role[mac] = role