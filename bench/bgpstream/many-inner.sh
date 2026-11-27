#!/bin/sh
# Runs inside the container: one bgpreader process per file in /data, repeated, writing a CSV.
#
#   many-inner.sh <repetitions>
set -u
REPS=${1:-3}
csv=/bench/many-bgpstream.csv
: >"$csv"
files=$(ls /data/*.gz | sort)
count=$(echo "$files" | wc -l)

rep=1
while [ "$rep" -le "$REPS" ]; do
  perf stat -x, -e instructions,task-clock -o /tmp/bs.many sh -c '
    for f in /data/*.gz; do
      bgpreader -d singlefile -t updates -o "upd-file=$f" >/dev/null 2>/dev/null
    done
  ' >/dev/null 2>/dev/null
  instr=$(awk -F, '$3=="instructions"{printf "%.0f", $1}' /tmp/bs.many)
  task_ms=$(awk -F, '$3=="task-clock"{printf "%.0f", $1}' /tmp/bs.many)
  echo "many-render-$rep,$instr,$task_ms,0" >>"$csv"
  printf '  many-render-%s files=%s %8.1fG %7s ms cpu\n' \
    "$rep" "$count" "$(echo "$instr" | awk '{print $1/1e9}')" "$task_ms"
  rep=$((rep + 1))
done
