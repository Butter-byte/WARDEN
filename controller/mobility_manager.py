class MobilityManager:
    def __init__(self, trunk_ports):
        self.locations = {}
        self.trunk_ports = trunk_ports

    def update_location(self, mac, dpid, port):
        mac = mac.lower()

        # Frames arriving on a trunk are transit traffic,
        # not evidence that the host moved.
        if port in self.trunk_ports.get(dpid, set()):
            return False, self.locations.get(mac)

        previous = self.locations.get(mac)

        self.locations[mac] = {
            "dpid": dpid,
            "port": port,
        }

        if previous and (
            previous["dpid"] != dpid or
            previous["port"] != port
        ):
            return True, previous

        return False, previous

    def get_location(self, mac):
        return self.locations.get(mac.lower())

    def remove(self, mac):
        self.locations.pop(mac.lower(), None)