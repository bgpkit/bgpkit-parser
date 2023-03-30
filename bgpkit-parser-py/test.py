from pybgpkit_parser import Parser
import json

parser = Parser(
    url="https://spaces.bgpkit.org/parser/update-example",
    filters={"peer_ips": "185.1.8.65, 2001:7f8:73:0:3:fa4:0:1"},
    cache_dir="./cache"
)

for elem in parser:
    print(elem["origin_asns"])
    print(json.dumps(elem, indent=4))
    break
