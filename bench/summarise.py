#!/usr/bin/env python3
"""Medians from the CSVs bench/measure.sh and bench/bgpstream/run.sh write.

Each row is ``case,instructions,task-clock_ms,wall_ms``. Case labels end in ``-<rep>`` (and, in the
before/after mode, ``-<side>-<rep>``), so the median is taken per label without the repetition.
"""
import sys
from collections import defaultdict
from pathlib import Path


def median(values):
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def load(paths):
    rows = defaultdict(list)
    for path in paths:
        for line in Path(path).read_text().splitlines():
            parts = line.split(",")
            if len(parts) != 4:
                continue
            label, instructions, task_ms, wall_ms = parts
            case = label.rsplit("-", 1)[0]
            rows[case].append((int(instructions), int(task_ms), int(wall_ms)))
    return rows


def main(paths):
    if not paths:
        print(__doc__)
        return 1
    rows = load(paths)
    print(f"{'case':34} {'G instr':>9} {'cpu s':>8} {'wall s':>8} {'cores':>6} {'n':>3}")
    for case in sorted(rows):
        instructions = median([row[0] for row in rows[case]])
        task_s = median([row[1] for row in rows[case]]) / 1000
        wall_s = median([row[2] for row in rows[case]]) / 1000
        print(
            f"{case:34} {instructions/1e9:9.1f} {task_s:8.2f} {wall_s:8.2f} "
            f"{task_s/wall_s if wall_s else 0:6.2f} {len(rows[case]):3}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
