# Benchmarking

Two Criterion benchmark targets:

- `internals` measures the parser itself on an in-memory byte buffer, so decompression and I/O are
  excluded. It always covers the small update file and the small RIB fixture, and can stream real
  archives when pointed at them.
- `bench_main` compares the `bgpkit-parser` CLI against other parsers installed on the machine
  (`bgpdump`, `libparsebgp`, `bgpscanner`, `bgpgrep`, `mrt-parser`). Missing programs are skipped.

## Running

```sh
cargo bench --bench internals              # ~8 min, all fixtures
cargo bench --bench internals -- rib       # filter by benchmark id substring
cargo bench --bench bench_main             # needs `cargo build --release --features cli` first
```

Test data is downloaded on the first run into `<cargo target dir>/test_data` (the target directory
comes from `CARGO_TARGET_TMPDIR`, so `CARGO_TARGET_DIR` and `build.target-dir` are respected) and is
verified against the md5 sums in `data_source.rs`.

## Real archives

Point the benchmark at local MRT files to include decompression and a realistic corpus size. These
run only when the variables are set, and nothing is downloaded.

```sh
BGPKIT_BENCH_RIB=/data/bview.gz \
BGPKIT_BENCH_UPDATES=/data/updates.gz \
BGPKIT_BENCH_STREAM_ELEMS=1000000 \
  cargo bench --bench internals -- "real"
```

## Reading the numbers

- Record-oriented benchmarks report records/s, elem-oriented benchmarks report elems/s. The same
  corpus yields more elems than records (about 2x for a RIB dump), so compare a benchmark only with
  itself, never `into_record_iter` against `into_elem_iter`.
- The fixtures are small (4290 update records, 235306 RIB records). They are enough to compare
  revisions of the parser, not to predict wall time for a full archive.

## Comparing revisions

Criterion keeps named baselines under the target directory:

```sh
git switch main && cargo bench --bench internals -- --save-baseline before
git switch my-branch && cargo bench --bench internals -- --baseline before
```

The same command shape works for a before/after record on one machine; results from different
machines are not comparable.
