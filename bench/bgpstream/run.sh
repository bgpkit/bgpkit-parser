#!/bin/sh
# Measure CAIDA BGPStream on the same file as bench/measure.sh, in the container that carries it.
#
#   bench/bgpstream/run.sh <directory containing the mrt file> [file name] [updates file name]
#
# Writes bench-out/bgpstream.csv next to the caller's working directory.
set -u

: "${1:?usage: run.sh <data directory> [rib file] [updates file]}"
DATA=$1
RIB=${2:-bview.20261014.0000.mrt}
UPD=${3:-}
OUT=${OUT:-bench-out}
REPS=${REPS:-3}

mkdir -p "$OUT"
csv="$OUT/bgpstream.csv"
: >"$csv"

docker run --rm --privileged \
    -v "$DATA:/data:ro" \
    -v "$OUT:/bench:rw" \
    bgpstream-caida \
    sh -c '
set -u
RIB=$1
UPD=$2
REPS=$3
csv=/bench/bgpstream.csv
measure() {
  label=$1
  shift
  perf stat -x, -e instructions,task-clock -o /tmp/bs.perf "$@" >/dev/null 2>/dev/null
  instr=$(awk -F, "\$3==\"instructions\"{printf \"%.0f\", \$1}" /tmp/bs.perf)
  task_ms=$(awk -F, "\$3==\"task-clock\"{printf \"%.0f\", \$1}" /tmp/bs.perf)
  echo "$label,$instr,$task_ms,0" >>"$csv"
  printf "  %-22s %8.1fG %7s ms cpu\n" "$label" "$(echo $instr | awk "{print \$1/1e9}")" "$task_ms"
}
repeat() {
  label=$1
  shift
  rep=1
  while [ "$rep" -le "$REPS" ]; do
    measure "$label-$rep" "$@"
    rep=$((rep + 1))
  done
}
repeat records bgps_probe rib "/data/$RIB" records
repeat elems bgps_probe rib "/data/$RIB" elems
repeat prefix bgps_probe rib "/data/$RIB" prefix
repeat aspath bgps_probe rib "/data/$RIB" aspath
repeat render bgpreader -d singlefile -t ribs -o "rib-file=/data/$RIB"
if [ -n "$UPD" ]; then
  repeat upd-elems bgps_probe upd "/data/$UPD" elems
  repeat upd-render bgpreader -d singlefile -t updates -o "upd-file=/data/$UPD"
fi
' sh "$RIB" "${UPD:-}" "$REPS"

echo "wrote $csv"
