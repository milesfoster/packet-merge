import json
from insite_plugin import InsitePlugin
from packet_merge import PacketMergeCollector


class Plugin(InsitePlugin):
    def can_group(self):
        return True

    def fetch(self, hosts):

        try:

            self.collector

        except Exception:

            params = {"hosts": ["172.16.168.119"],
                        "decoders": [1, 2, 3, 4, 5, 6, 7, 8, 9],
                        "group": "test", # optional, only used if no decoder name provided in mapping
                        "mapping": { # optional, decoder number will still return if no mapping is provided
                        1: "dec1",
                        2: "dec2",
                        3: "dec3",
                        4: "dec4",
                        5: "dec5",
                        6: "dec6",
                        7: "dec7",
                        8: "dec8",
                        9: "dec9",
                        10: "dec10",
                        11: "dec11",
                        12: "dec12",
                        13: "dec13",
                        14: "dec14",
                        15: "dec15",
                        16: "dec16",
                        }}


            self.collector = PacketMergeCollector(**params)

        documents = []

        for host, data in self.collector.collect.items():
            # Handle host-level errors
            if data["error"]:
                documents.append({
                    "host": host,
                    "name": "merged",
                    "fields": {
                        "status": "error",
                        "error_message": data["error"]
                    }
                })
                continue

            # Handle successful data
            for _, params in data["decoders"].items():
                document = {
                    "fields": params, 
                    "host": host, 
                    "name": "merged",
                    "status": "success"
                }
                documents.append(document)

        return json.dumps(documents)