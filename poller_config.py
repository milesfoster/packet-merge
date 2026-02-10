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

        for ip, decoders in self.collector.collect.items():

            for _, params in decoders.items():

                document = {"fields": params, "host": ip, "name": "merged"}

                documents.append(document)

        return json.dumps(documents)