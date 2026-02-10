import copy
import json
from threading import Thread

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()


class PacketMergeCollector:
    def __init__(self, **kwargs):

        self.decoders = []
        self.hosts = []
        self.proto = "http"

        self.link_select = {"id": "221.<replace>@i", "type": "integer", "name": "link_select"}
        self.playout_status = {"id": "224.<replace>@i", "type": "integer", "name": "playout_status"}
        self.main_drop = {
            "id": "801.<replace>.0@i",
            "type": "integer",
            "name": "l_main_packet_drop",
        }
        self.main_rate = {
            "id": "800.<replace>.0@i",
            "type": "integer",
            "name": "l_main_packet_rate",
        }
        self.main_multicast = {
            "id": "232.<replace>.0@s",
            "type": "string",
            "name": "s_main_multicast_address",
        }
        self.backup_drop = {
            "id": "801.<replace>.1@i",
            "type": "integer",
            "name": "l_backup_packet_drop",
        }
        self.backup_rate = {
            "id": "800.<replace>.1@i",
            "type": "integer",
            "name": "l_backup_packet_rate",
        }
        self.backup_multicast = {
            "id": "232.<replace>.1@s",
            "type": "string",
            "name": "s_backup_multicast_address",
        }
        self.hitless_drop = {
            "id": "801.<replace>.2@i",
            "type": "integer",
            "name": "l_hitless_packet_drop",
        }
        self.hitless_rate = {
            "id": "800.<replace>.2@i",
            "type": "integer",
            "name": "l_hitless_packet_rate",
        }
        self.skew_milliseconds = {
            "id": "223.<replace>@i",
            "type": "integer",
            "name": "l_skew_milliseconds",
        }

        self.link_select_lookup = {
            0: "Auto Packet Merge",
            1: "SFP 10G Main",
            2: "SFP 10G Backup",
            3: "Fail Over",
            4: "Dual Source Switch Mode",
        }
        self.status_lookup = {0: "Merged", 1: "Main", 2: "Backup"}

        self.parameters = []

        for key, value in kwargs.items():

            if "hosts" in key and value:

                self.hosts.extend(value)
                self.hosts_decoders_store = {host: {} for host in self.hosts}

            if "decoders" in key and value:
                self.decoders.extend(value)

            if "proto" in key and value:
                self.proto = value

        for decode in self.decoders:

            for template in [
                self.link_select,
                self.playout_status,
                self.main_drop,
                self.main_rate,
                self.main_multicast,
                self.backup_drop,
                self.backup_rate,
                self.backup_multicast,
                self.hitless_drop,
                self.hitless_rate,
                self.skew_milliseconds,
            ]:

                template_copy = copy.deepcopy(template)

                template_copy["id"] = template_copy["id"].replace("<replace>", str(decode - 1))

                self.parameters.append(template_copy)

    def fetch(self, host):

        try:

            with requests.Session() as session:

                ## get the session ID from accessing the login.php site
                resp = session.get(
                    "%s://%s/login.php" % (self.proto, host),
                    verify=False,
                    timeout=15.0,
                )

                session_id = resp.headers["Set-Cookie"].split(";")[0]

                payload = {
                    "jsonrpc": "2.0",
                    "method": "get",
                    "params": {"parameters": self.parameters},
                    "id": 1,
                }

                url = "%s://%s/cgi-bin/cfgjsonrpc" % (self.proto, host)

                headers = {
                    "Content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Cookie": session_id + "; webeasy-loggedin=true",
                }

                response = session.post(
                    url,
                    headers=headers,
                    data=json.dumps(payload),
                    verify=False,
                    timeout=15.0,
                )

                return json.loads(response.text)

        except Exception as error:
            return error

    def parse_results(self, host, collection):

        # inital tree
        host_decoders = {host: {}}

        # reference in
        decoders = host_decoders[host]

        results = self.fetch(host)

        # import response
        # from importlib import reload

        # reload(response)
        # results = copy.deepcopy(response.params)

        try:

            for result in results["result"]["parameters"]:

                # seperate "240.1@i" to "1" or 301.2.0@i to "2"
                _instance = result["id"].split(".")[1][:1]

                # upconvert base 0 to base 1
                _instance = int(_instance) + 1

                # convert to bit rate from kbps
                if "packet_rate" in result["name"]:
                    result["value"] = result["value"] * 1000

                # perform lookup for playout status enumeration
                elif "playout_status" in result["name"]:
                    result["value"] = self.status_lookup[result["value"]]

                # perform lookup for link select enumeration
                elif "link_select" in result["name"]:
                    result["value"] = self.link_select_lookup[result["value"]]

                if _instance not in decoders.keys():

                    decoders.update(
                        {
                            _instance: {
                                result["name"]: result["value"],
                                "i_decoder": _instance,
                                "as_ids": [result["id"]],
                            }
                        }
                    )

                else:

                    decoders[_instance].update({result["name"]: result["value"]})
                    decoders[_instance]["as_ids"].append(result["id"])

            decoders_store = self.hosts_decoders_store[host]

            for decode_num, params in decoders.items():

                if decode_num in decoders_store.keys():

                    for key in ["l_main_packet_drop", "l_backup_packet_drop", "l_hitless_packet_drop"]:

                        x = params[key]
                        y = decoders_store[decode_num][key]

                        params.update({"{}_delta".format(key): x - y if x > y else 0})

                    #decoders_store[decode_num].update(params)
                    
                    for key in ["s_main_multicast_address", "s_backup_multicast_address",]:

                        t = params[key]
                        u = decoders_store[decode_num][key]
                        v = "Yes"
                        z = "No"
                    
                        params.update({"{}_prev".format(key): u})
                        params.update({"{}_changed".format(key): z if t == u else v})
                        
                    decoders_store[decode_num].update(params)

                else:

                    decoders_store.update({decode_num: params})

            collection.update(host_decoders)

        except Exception as e:
            print(e)

    @property
    def collect(self):

        collection = {}

        threads = [
            Thread(
                target=self.parse_results,
                args=(
                    host,
                    collection,
                ),
            )
            for host in self.hosts
        ]

        for x in threads:
            x.start()

        for y in threads:
            y.join()

        return collection


def main():

    params = {"hosts": ["192.168.0.16"], "decoders": [1, 2, 3, 4, 5, 6, 7, 8, 9]}

    collector = PacketMergeCollector(**params)

    inputQuit = False

    while inputQuit is not "q":

        documents = []

        for host, decoders in collector.collect.items():

            for _, params in decoders.items():

                document = {"fields": params, "host": host, "name": "merged"}

                documents.append(document)

        print(json.dumps(documents, indent=1))

        inputQuit = input("\nType q to quit or just hit enter: ")


if __name__ == "__main__":
    main()