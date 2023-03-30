# bgpkit-parser-py

Python binding for bgpkit-parser

## Example

```python
from pybgpkit_parser import Parser
import json

parser = Parser(
    url="https://spaces.bgpkit.org/parser/update-example",
    filters={"peer_ips": "185.1.8.65, 2001:7f8:73:0:3:fa4:0:1"},
)

for elem in parser:
    print(elem["origin_asns"])
    print(json.dumps(elem, indent=4))
    break
```

You can also add `cache_dir` to Parser to cache the downloaded files to a specified directory.

Here is an example:
```python
from pybgpkit_parser import Parser
import json

parser = Parser(
    url="https://spaces.bgpkit.org/parser/update-example",
    filters={"peer_ips": "185.1.8.65, 2001:7f8:73:0:3:fa4:0:1"},
    cache_dir="./"
)

for elem in parser:
    print(elem["origin_asns"])
    print(json.dumps(elem, indent=4))
    break
```

## Supported Python Version

- Python3.7
- Python3.8
- Python3.9
- Python3.10
- Python3.11

## Installation

```bash
python3 -m pip install pybgpkit-parser
```

## Develop

`maturin develop` builds local python module and add to the venv.

### Publish for Linux

Install multiple Python interpreters:

```bash
sudo apt install software-properties-common
sudo add-apt-repository ppa:deadsnakes/ppa
```

Build and upload for multiple interpreter versions:
```bash
maturin publish --interpreter python3.7 --skip-existing
maturin publish --interpreter python3.8 --skip-existing
maturin publish --interpreter python3.9 --skip-existing
maturin publish --interpreter python3.10 --skip-existing
maturin publish --interpreter python3.11 --skip-existing
```

#### Using docker

```
docker build -t bgpkit-builder:latest .
docker run --rm -it bgpkit-builder:latest bash

####
# TODO: copy the content of .pypirc to the root folder
####
git clone https://github.com/bgpkit/bgpkit-parser.git
cd bgpkit-parser/bgpkit-parser-py

maturin publish --interpreter python3.7 --skip-existing
maturin publish --interpreter python3.8 --skip-existing
maturin publish --interpreter python3.9 --skip-existing
maturin publish --interpreter python3.10 --skip-existing
maturin publish --interpreter python3.11 --skip-existing

```

### Publish for MacOS

```bash
maturin publish --skip-existing
```
