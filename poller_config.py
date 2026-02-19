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

            params = {"hosts": hosts, "decoders": [1, 2, 3, 4, 5, 6, 7, 8, 9]}

            self.collector = PacketMergeCollector(**params)

        documents = []

        for host, data in collector.collect.items():
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