FROM debian:bookworm-slim

# CAIDA's packages are built for bookworm; newer Debian releases are not served.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg sudo lsb-release procps linux-perf gcc libc6-dev make

RUN curl -s https://pkg.caida.org/os/debian/bootstrap.sh | bash

RUN apt-get update && apt-get install -y --no-install-recommends bgpstream libbgpstream2-dev

COPY bgps_probe.c /work/bgps_probe.c
RUN gcc -O2 -o /usr/local/bin/bgps_probe /work/bgps_probe.c -lbgpstream

WORKDIR /work
