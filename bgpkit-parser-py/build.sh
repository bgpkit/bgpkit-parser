#!/bin/bash

set -e

sudo rm -rf target

docker build -t bgpkit-python-builder .

docker run --rm -v $(pwd):/io bgpkit-python-builder build --manylinux 2014 --release --interpreter python3.7
docker run --rm -v $(pwd):/io bgpkit-python-builder build --manylinux 2014 --release --interpreter python3.8
docker run --rm -v $(pwd):/io bgpkit-python-builder build --manylinux 2014 --release --interpreter python3.9
docker run --rm -v $(pwd):/io bgpkit-python-builder build --manylinux 2014 --release --interpreter python3.10
docker run --rm -v $(pwd):/io bgpkit-python-builder build --manylinux 2014 --release --interpreter python3.11