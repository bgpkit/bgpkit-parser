# Parsing performance: benchmark revision and measured gains

Recorded on branch `perf/parser-throughput`, November 2026. Every number here is reproducible with
the commands at the end.

## Summary

| corpus | metric | before | after | delta |
| --- | --- | --- | --- | --- |
| RIB fixture, elem iteration (235306 records, 470642 elems) | instructions per full parse | 3.717 G | 3.357 G | -9.7% |
| RIB fixture, record iteration | instructions per full parse | 2.814 G | 2.432 G | -13.6% |
| Updates fixture, elem iteration (4290 records, 8160 elems) | instructions per full parse | 50.0 M | 46.2 M | -7.7% |
| Updates fixture, record iteration | instructions per full parse | 35.1 M | 30.6 M | -12.8% |
| rrc00 bview 2026-10-14 (420 MB gz, 55.8 M elems), CLI | instructions | 463.1 G | 391.1 G | -15.6% |
| rrc00 bview 2026-10-14, CLI | wall time | 54.34 s | 42.06 s | -22.6% |
| RIS updates 2026-10-14 00:10 (4.5 MB gz, 150360 records), CLI | instructions | 4.320 G | 4.154 G | -3.8% |

Allocations per item:

| corpus / mode | before | after |
| --- | --- | --- |
| RIB, record iteration | 14.00 allocs, 7218 B per record | 8.94 allocs, 4566 B per record |
| RIB, elem iteration | 9.00 allocs, 3667 B per elem | 6.42 allocs, 2338 B per elem |
| Updates, record iteration | 10.23 allocs, 5328 B per record | 6.03 allocs, 2136 B per record |
| Updates, elem iteration | 7.34 allocs, 2947 B per elem | 5.13 allocs, 1269 B per elem |

## Why instruction counts

The development host runs other work (an archive backfill at 10+ cores during these measurements),
so Criterion wall times move by up to 18% between runs of the *same* binary. `perf stat -e
instructions` is stable to 0.01% across runs of the same binary on the same host and is unaffected
by that load, so it is the primary signal here; wall time is reported only for the end-to-end CLI
runs, with the caveat that single runs on a loaded host are indicative, not precise.

Instruction counts are a proxy for time, not time itself: they do not see cache behaviour or branch
mispredictions. The optimizations below all reduce work per record (allocations, refcount traffic,
copies), which is why the wall-time direction matches in every case.

The end-to-end rrc00 row averages five runs taken alternately in one session: 463.32, 463.02,
463.13, 463.03, 462.92 G before and 391.15, 391.06, 391.15, 391.07, 391.14 G after. The instruction
delta is reproducible to 0.03%, and the wall-time delta, while noisier, is not an artifact of
drift.

## Benchmark changes

`cargo bench` could not run on a clean checkout:

- The test-data download opened the target file with `get_reader` (which decompresses by suffix) and
  then truncated it with `File::create`, so every download ended in `decompression not finished but
  EOF reached`; the published md5 was also compared against decompressed bytes.
- The target directory was found by walking up for a literal `target/`, which panics whenever
  `CARGO_TARGET_DIR` or `build.target-dir` moves artifacts out of the tree.
- `bench_main` resolved `target/release/bgpkit-parser` and panicked when it was absent, though
  `cargo bench` never builds that binary (`required-features = ["cli"]`).

The `internals` target also measured different amounts of work per mode: `into_record_iter` was
capped at 100k *records* while `into_elem_iter` was capped at 100k *elems* (about 50k records), and
the record-to-elem benchmark silently produced no elems for RIB records because its `Elementor` had
no peer index table.

The revised target parses the whole in-memory fixture in every mode, reports throughput
(records/s or elems/s) next to each timing, seeds the record-to-elem benchmark with the peer table,
and accepts real archives through `BGPKIT_BENCH_RIB` / `BGPKIT_BENCH_UPDATES` (streamed from disk, so
decompression is included).

## Code changes

1. `perf(parser): cut attribute-path allocations` (993f61a)

   - AS_PATH segments stay inline and ASNs decode straight into the segment `SmallVec` instead of
     growing a `Vec` and copying it.
   - `parse_attributes` sized its attribute vector at one slot per three bytes of section, which
     over-allocated by an order of magnitude on short records; it now uses a realistic
     per-attribute floor.
   - `parse_rib_afi_entries` reserved two slots per entry instead of one.

   Instructions: updates records -2.9%, updates elems -2.0%, RIB records -2.0%, RIB elems -1.7%.

2. `perf(mrt): keep record headers on the stack` (f742b18)

   - Framing allocated a `Vec` for the captured header and a `Bytes` for the header on every record,
     only for the raw-record API and error reporting. The header now lives in a 16-byte stack
     buffer; the `Bytes` is built only for the raw API. Truncated headers still retain their partial
     bytes, so the partial-framing tests are unchanged.

   Instructions: updates records -7.1%, updates elems -3.5%, RIB records -3.2%, RIB elems -2.6%.

3. `perf(parser): decode AS_PATH from the record body` (7cf3b9e)

   - AS_PATH is in essentially every announcement and was the last attribute still split out of the
     record body into its own `Bytes` before parsing. It now decodes from a borrowed slice.

   Instructions: RIB records -3.1%, RIB elems -2.6%, updates records -3.2%, updates elems -2.4%.

## What did not work

Routing *all* frequently-seen attributes through one slice-based dispatcher
(`Option<Result<AttributeValue, _>>` fan-out over thirteen parsers) measured **+6.8% on RIB elems and
+7.9% on RIB records**. Removing per-attribute `Bytes` splits did not pay for the lost per-arm
specialization. The change was reverted; only AS_PATH, whose parse stays in the dispatch arm, kept
the slice treatment and gained. Any future attempt should keep one inlined arm per attribute.

## Remaining headroom

From the instruction profile of `into_elem_iter` on a RIB, before these changes:

- allocator + `Bytes` refcount traffic: about 19% of instructions;
- `parse_attributes` itself: about 10%;
- record-to-elem conversion (`get_relevant_attributes`, `next_rib_elem`): about 9%.

Per-record allocations are now 8.9 (records) and 6.4 (elems) on the RIB fixture; the body `Vec` and
the `Attributes` vector are the two that remain on every record. Eliminating them means changing
ownership (parsing from a reused buffer) or the public model types, not micro-tuning.

The other large lever is decompression, which this parser does not own: for compressed archives,
end-to-end time is split between decompression and parsing, and only the parsing half moved here.

## Reproducing

```sh
# fixtures, parse only, with a saved baseline
cargo build --release --features cli          # bench_main needs the CLI binary
cargo bench --bench internals -- --save-baseline before
# apply the branch, then:
cargo bench --bench internals -- --baseline before

# real archives, end to end (decompression included)
BGPKIT_BENCH_RIB=/path/to/bview.gz \
BGPKIT_BENCH_UPDATES=/path/to/updates.gz \
  cargo bench --bench internals -- "real"

# instruction counts for a fixed workload
perf stat -e instructions target/release/bgpkit-parser -e /path/to/bview.gz
```
