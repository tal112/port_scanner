import json

class Port:
    def __init__(self, ip_address, port, state, name, product, version, info):
        self.ip_address = ip_address
        self.port = port
        self.state = state
        self.name = name
        self.product = product
        self.version = version
        self.info = info

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)