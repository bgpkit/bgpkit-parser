# Parsing performance: benchmark revision, measured gains, BGPStream comparison

Recorded on branch `perf/parser-throughput`, November 2026. Every number below is reproducible with
the commands at the end.

## Summary

Parse-only instruction counts per full parse of the fixture (decompression excluded):

| workload | before | after | delta |
| --- | --- | --- | --- |
| RIB fixture, framing only (235306 records) | 0.252 G | 0.221 G | -12.1% |
| RIB fixture, record iteration | 2.815 G | 2.338 G | -16.9% |
| RIB fixture, elem iteration (470642 elems) | 3.718 G | 3.251 G | -12.6% |
| Updates fixture, record iteration (4290 records) | 35.15 M | 30.68 M | -12.7% |
| Updates fixture, elem iteration (8160 elems) | 50.02 M | 44.83 M | -10.4% |

End to end through the CLI on compressed archives (decompression included):

| workload | mode | before | after | delta |
| --- | --- | --- | --- | --- |
| rrc00 bview 2026-10-14, 420 MB gz | elems, 55.8 M | 463.1 G / 54.3 s | 392.4 G / 42.6 s | -15.3% instr, -21.5% wall |
| rrc00 bview 2026-10-14 | records, 1.43 M | 361.4 G / 42.3 s | 288.6 G / 29.8 s | -20.2% instr, -29.4% wall |
| RIS updates 2026-10-14 00:10, 4.5 MB gz | elems, 417788 | 5.04 G / 0.51 s | 4.89 G / 0.47 s | -3.0% instr, -7.8% wall |
| RIS updates 2026-10-14 00:10 | records, 150360 | 4.32 G / 0.41 s | 4.17 G / 0.40 s | -3.3% instr, -2.4% wall |

Allocations per item (counter wraps the global allocator):

| workload / mode | before | after |
| --- | --- | --- |
| RIB, record iteration | 14.00 allocs, 7218 B per record | 7.24 allocs, 3490 B per record |
| RIB, elem iteration | 9.00 allocs, 3667 B per elem | 5.61 allocs, 1866 B per elem |
| Updates, record iteration | 10.23 allocs, 5328 B per record | 5.55 allocs, 1887 B per record |
| Updates, elem iteration | 7.34 allocs, 2947 B per elem | 4.88 allocs, 1138 B per elem |

## What these numbers do and do not establish

- Instruction counts come from `perf stat` on a virtualized host whose PMU reports them; they are
  stable to 0.01% across runs of one binary and are used for A/B only, not as physical counts.
- Host wall times move by up to 18% between runs of the *same* binary because an unrelated archive
  backfill holds 10+ cores. Wall figures above are means of repeated alternating runs.
- Parse-only numbers exclude decompression by construction; the CLI rows include it. They are not
  interchangeable: the small updates fixture improves 10% parse-only but only 3% end to end.
- `bgpkit-parser -r` / `-e` are counting paths: they parse and drop, without formatting or writing
  output. These rows say nothing about export throughput.
- The fast framing path covers the default iterators. The fallible iterators still go through the
  raw-record chunking path (`src/parser/iters/mod.rs`) and the route iterator still calls
  `chunk_mrt_record` (`src/parser/iters/route.rs`), so they do not inherit the whole win.
- Fixture gains do not transfer one-to-one to a full RIB; the rrc00 row is the number to quote.

## Harness repairs

`cargo bench` could not run on a clean checkout, and where it ran it measured the wrong thing:

- the test-data download opened the destination with a decompressing reader and then truncated it,
  so every download failed with `decompression not finished but EOF reached`; the published md5 was
  also compared against decompressed bytes;
- the target directory was found by walking up for a literal `target/`, which panics whenever
  `CARGO_TARGET_DIR` or `build.target-dir` moves artifacts out of the tree (now
  `CARGO_TARGET_TMPDIR`);
- `bench_main` panicked when `target/release/bgpkit-parser` was missing, though `cargo bench` never
  builds that binary (`required-features = ["cli"]`);
- record modes were capped at 100k records while elem modes were capped at 100k elems, so the modes
  measured different amounts of work;
- the record-to-elem benchmark produced no elems for RIB records because its `Elementor` had no
  peer index table;
- `into_update_iter` divided by the record count instead of the update count, preload truncated a
  too-large corpus silently, and two benchmarks divided by a fabricated 1 when they produced
  nothing.

Every mode now parses the whole in-memory fixture, except the record-to-elem benchmark, which keeps
100k parsed records in memory between iterations and says so. Throughput is reported next to each
time, and the real-archive path streams a bounded number of elems
(`BGPKIT_BENCH_STREAM_ELEMS`, default 1M) from `BGPKIT_BENCH_RIB` / `BGPKIT_BENCH_UPDATES`.

## Changes

1. `perf(parser): cut attribute-path allocations` (993f61a)

   AS_PATH segments stay inline and ASNs decode straight into the segment `SmallVec` instead of
   growing a `Vec` and copying it; the attribute vector is sized from the section length with a
   realistic per-attribute floor instead of one slot per three bytes; RIB entries reserve one slot
   per entry instead of two.

2. `perf(mrt): keep record headers on the stack` (f742b18)

   Framing allocated a `Vec` for the captured header and a `Bytes` for the header on every record,
   only for the raw-record API and error reporting. The header now lives in a 16-byte stack buffer.

3. `perf(parser): decode AS_PATH from the record body` (7cf3b9e)

   AS_PATH is in essentially every announcement and was the last attribute still split out of the
   record body into its own `Bytes` before parsing.

4. `fix(mrt): keep partial extended-timestamp bytes on header I/O error` (be3ff0a)

   Found by an external review: the stack-header rewrite advanced the captured length only after a
   successful read, so an I/O error inside the 4-byte microsecond field dropped the bytes already
   read from the error report. Covered now at 13, 14 and 15 header bytes, for an I/O error and for
   a clean EOF.

5. `perf(parser): reserve eight attribute slots instead of four` (a8a5924)

   A floor of four made 71.4% of RIB entries grow their attribute vector (measured over all 470,642
   fixture entries); six leaves 3.7% short, so eight was chosen. Four, six and eight were measured
   against the same binary and stayed within 0.5% of each other on the fixtures; the end-to-end
   numbers quoted below were all measured with eight.

## Comparison with CAIDA BGPStream

Same files, both sides reading the compressed input, walking every record and (in `elems` mode)
every element, then discarding the result. The BGPStream probe and container are in
`benches/bgpstream-compare/`.

| workload | mode | BGPStream | bgpkit-parser | ratio |
| --- | --- | --- | --- | --- |
| rrc00 bview, 420 MB gz | records | 85.8 G / 5.28 s | 288.6 G / 29.8 s | 3.4x instr, 5.7x wall |
| rrc00 bview | elems (55.8 M) | 116.2 G / 9.06 s | 392.4 G / 42.6 s | 3.4x instr, 4.7x wall |
| RIS updates, 4.5 MB gz | records | 0.76 G / 0.09 s | 4.17 G / 0.40 s | 5.5x instr, 4.3x wall |
| RIS updates | elems (417788) | 0.93 G / 0.11 s | 4.89 G / 0.47 s | 5.3x instr, 4.2x wall |
| RIB fixture | records | 3.64 G / 0.61 s | 5.53 G / 0.71 s | 1.5x instr, 1.2x wall |
| RIB fixture | elems | 3.90 G / 0.58 s | 6.49 G / 0.85 s | 1.7x instr, 1.5x wall |

BGPStream is faster, and the gap is structural rather than a few instructions per record:

- BGPStream hands out elems as views into the record buffer; `bgpkit-parser` returns owned values
  (owned `AsPath`, owned community vector, owned origin list), so every elem allocates. That is an
  API contract difference and is most of the elem-mode gap.
- The record-mode gap on a real RIB (3.4x) is larger than on the small fixture (1.5x) because
  bgpkit parses and stores every attribute type eagerly, while BGPStream decodes on demand.

Caveats: element counts on a RIB match exactly (55,786,629), record counts differ by one (BGPStream
does not surface the PEER_INDEX_TABLE record), the updates fixture yields 8,183 elems for BGPStream
against 8,160 for bgpkit, and the probe never reads a field, so any lazily parsed BGPStream field is
not charged to it. All bgpkit numbers here are the counting paths (`-r` / `-e`): the default output
path also formats and writes every element, which roughly doubles the cost (12.35 G instead of
6.49 G on the RIB fixture, 12.36 G instead of 4.89 G on the updates file) and is a different
workload.

## What did not work

Routing all thirteen frequently-seen attribute parsers through one
`Option<Result<AttributeValue, _>>` slice dispatcher measured **+6.8% on RIB elems and +7.9% on RIB
records**. Removing the per-attribute `Bytes` split did not pay for the lost per-arm
specialization; the change was reverted. Only AS_PATH, whose parse stays inside the dispatch arm,
kept the slice treatment and gained.

## Directions not taken yet

Ranked by expected payoff per unit of risk, from an external review of this branch:

1. Skip the attribute-vector allocation for empty attribute sections (103 of the 4,139 UPDATEs in
   the updates fixture have none). Small, low risk.
2. Borrowed-slice parsing for ORIGIN, NEXT_HOP, MED and LOCAL_PREF, one inlined arm each. Small;
   the thirteen-way dispatcher result does not rule out per-arm slice parsing.
3. Dense peer lookup for RIB elems: `next_rib_elem` hashes a dense `u16` id per elem. A private
   cache inside the iterator has to be rebuilt when the peer table changes, and the public
   `Elementor` path must keep honoring caller mutation.
4. Structural: emit elems directly from the record body instead of building a full
   `Vec<RibEntry>`/`Attributes` set and then dismantling it. This is the direction that could close
   part of the BGPStream gap; it needs an internal streaming builder plus a batch/view API for
   shared attributes, not a change to `BgpElem`.
5. Reuse the per-record body buffer. Blocked on ownership: unknown, deprecated and failed attributes
   keep `Bytes` into the body, so the buffer cannot be recycled until those handles are bounded.
6. Measure decompression separately (decompress-only versus pre-decompressed parse) before
   optimizing it; there is no current phase breakdown for the final binary.

## Reproducing

```sh
# fixed-workload instruction counts (committed example)
cargo build --release --example perf_workload
perf stat -e instructions target/release/examples/perf_workload \
  /path/to/rib-example-small.bz2 elems 4     # also: records, raw; use 10 for the slope

# criterion suites
cargo build --release --features cli          # bench_main needs the CLI binary
cargo bench --bench internals                 # ~8 min, whole fixtures

# end-to-end on a real archive
perf stat -e instructions target/release/bgpkit-parser -e /path/to/bview.gz

# CAIDA BGPStream side of the comparison
cd benches/bgpstream-compare && docker build -t bgpstream-caida .
docker run --rm --privileged -v /path/to/bview.gz:/data/input.gz bgpstream-caida \
  bash -lc "perf stat -e instructions /usr/local/bin/bgps_probe rib /data/input.gz elems"
```

Parse-only cost is separated from fixed startup by running two iteration counts:
`P = (I(10) - I(4)) / 6`. Per-commit deltas quoted in the commit messages are totals at one fixed
iteration count (startup included) and are not compoundable into the table above.
