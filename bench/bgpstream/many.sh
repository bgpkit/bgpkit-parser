#!/bin/sh
# The broker-shaped workload through BGPStream: one bgpreader process per file, repeated.
#
#   bench/bgpstream/many.sh <directory of .gz files>
set -u
: "${1:?usage: many.sh <data directory>}"
DATA=$1
OUT=${OUT:-bench-out}
REPS=${REPS:-3}
mkdir -p "$OUT"
docker run --rm --privileged \
    -v "$DATA:/data:ro" \
    -v "$(cd "$(dirname "$0")" && pwd):/work:ro" \
    -v "$OUT:/bench:rw" \
    bgpstream-caida sh /work/many-inner.sh "$REPS"
echo "wrote $OUT/many-bgpstream.csv"
