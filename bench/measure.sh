#!/bin/bash
# Measure one side of the parser benchmarks. See README.md for what each mode covers.
#
#   BGPKIT_BIN=<path> RIB=<uncompressed mrt> [UPD=<updates file>] [OLD_BIN=<path>] \
#       bench/measure.sh <before-after|render|workloads|filters>
set -u

MODE=${1:-}
: "${BGPKIT_BIN:?set BGPKIT_BIN to the release binary}"
: "${RIB:?set RIB to an uncompressed MRT file}"
UPD=${UPD:-}
OLD_BIN=${OLD_BIN:-}
OUT=${OUT:-bench-out}
REPS=${REPS:-3}

mkdir -p "$OUT"
case "$MODE" in
before-after | render | workloads | filters) ;;
*)
    echo "usage: $0 <before-after|render|workloads|filters>" >&2
    exit 2
    ;;
esac

csv="$OUT/$MODE.csv"
: >"$csv"

# measure <label> <binary> [args...]
measure() {
    label=$1
    binary=$2
    shift 2
    # Wall time is taken around the same run the counters come from, so both describe one execution.
    start=$(date +%s%N)
    perf stat -x, -e instructions,task-clock -o /tmp/measure.perf \
        "$binary" "$@" >/dev/null 2>/dev/null
    end=$(date +%s%N)
    wall_ms=$(((end - start) / 1000000))
    instr=$(awk -F, '$3=="instructions"{printf "%.0f", $1}' /tmp/measure.perf)
    task_ms=$(awk -F, '$3=="task-clock"{printf "%.0f", $1}' /tmp/measure.perf)
    echo "$label,$instr,$task_ms,$wall_ms" >>"$csv"
    printf '  %-26s %8.1fG %7s ms cpu\n' "$label" "$(echo "$instr" | awk '{print $1/1e9}')" "$task_ms"
}

# repeat <label> <binary> [args...]
repeat() {
    label=$1
    binary=$2
    shift 2
    for rep in $(seq 1 "$REPS"); do
        measure "$label-$rep" "$binary" "$@"
    done
}

WORKLOAD_BIN=${WORKLOAD_BIN:-$(dirname "$BGPKIT_BIN")/examples/workload_bench}

case "$MODE" in
before-after)
    : "${OLD_BIN:?set OLD_BIN to the binary you are comparing against}"
    for rep in $(seq 1 "$REPS"); do
        for side in old new; do
            binary=$OLD_BIN
            [ "$side" = new ] && binary=$BGPKIT_BIN
            measure "rib-elems-mrt-$side-$rep" "$binary" -e "$RIB"
            measure "rib-psv-mrt-$side-$rep" "$binary" -F psv "$RIB"
            measure "rib-prefix-mrt-$side-$rep" "$binary" -e -p 8.8.8.0/24 "$RIB"
            measure "rib-origin-mrt-$side-$rep" "$binary" -e -o 15169 "$RIB"
        done
    done
    ;;
render)
    repeat render-all "$BGPKIT_BIN" -F psv "$RIB"
    repeat render-prefix "$BGPKIT_BIN" -F psv -p 8.8.8.0/24 "$RIB"
    repeat render-origin "$BGPKIT_BIN" -F psv -o 15169 "$RIB"
    if [ -n "$UPD" ]; then
        repeat render-updates "$BGPKIT_BIN" -F psv "$UPD"
    fi
    ;;
workloads)
    : "${WORKLOAD_BIN:?build the workload example: cargo build --release --example workload_bench}"
    repeat prefix-owned "$WORKLOAD_BIN" "$RIB" prefix-owned
    repeat prefix-view "$WORKLOAD_BIN" "$RIB" prefix-view
    repeat aspath-owned "$WORKLOAD_BIN" "$RIB" aspath-owned
    repeat aspath-view "$WORKLOAD_BIN" "$RIB" aspath-view
    ;;
filters)
    # count mode: no output cost, so the number is the filter's own price
    repeat no-filter "$BGPKIT_BIN" -e "$RIB"
    repeat prefix-one "$BGPKIT_BIN" -e -p 8.8.8.0/24 "$RIB"
    repeat prefix-all "$BGPKIT_BIN" -e -p 0.0.0.0/0 -S "$RIB"
    repeat origin "$BGPKIT_BIN" -e -o 15169 "$RIB"
    repeat community-anchored "$BGPKIT_BIN" -e -C '^15169:' "$RIB"
    repeat community-rare "$BGPKIT_BIN" -e -C '^13335:' "$RIB"
    repeat community-common "$BGPKIT_BIN" -e -C '^174:' "$RIB"
    repeat community-unanchored "$BGPKIT_BIN" -e -C '15169:' "$RIB"
    repeat aspath-rare "$BGPKIT_BIN" -e -a ' 65001 ' "$RIB"
    repeat aspath-common "$BGPKIT_BIN" -e -a ' 3356 ' "$RIB"
    ;;
esac

echo "wrote $csv"
