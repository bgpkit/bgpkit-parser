# Parallel element iteration

## 1. Problem

`bgpkit-parser` parses one MRT file on one thread. On the rrc00 bview of 2026-10-14 (420 MB
gz, 55,786,629 elems) that is 314.0 G instructions and 34.6 s wall with the current
`into_elem_iter`, against CAIDA BGPStream's 123.4 G / ~9 s on the same file with the same
work done (its probe was extended to read prefix, peer, origin, med, local_pref, the whole
AS path and the community count, which costs it 8% more than not reading them).

Two structural facts bound what can be won without changing the public data model:

- record parsing to owned `Attributes` costs 184.7 G of the 265.5 G an unfiltered elem scan
  spends on a decompressed copy of the same file; converting those attributes into elems
  costs the remaining 80.8 G. Both are single-threaded, and neither is dominated by one
  pathological loop, so no sequence of 10% changes closes a 2.5x gap.
- MRT is record framed: after the `PEER_INDEX_TABLE`, every record can be parsed
  independently. BGPStream does not use that; one instance parses on one thread and keeps a
  second thread (`wandio`'s `[ior]`) for reading and decompressing. Its concurrency model is
  "one stream per thread, merge above".

This design adds parallel parsing of one file to this crate, as an additive API.

## 2. Scope

In scope, first version: the default (skipping) element iterator over a single MRT file,
unfiltered, records of every type the sequential path handles.

Out of scope for this version, each a later PR: the fallible iterators, the route and
diagnostic iterators, BMP streams (a session is already a stream of messages and does not
benefit the same way), text dumps, filters, and the CLI flag that exposes the API (the CLI
flag lands with the measurement PR that proves the win).

## 3. Public API

```rust
impl<R: Read + Send + 'static> BgpkitParser<R> {
    /// Iterate elements using `threads` parser threads, yielding in file order.
    ///
    /// `threads == 0` or `1` runs the existing sequential iterator and spawns nothing.
    /// Requires `R: Send + 'static` because the reader moves to the producer thread.
    pub fn into_par_elem_iter(self, threads: usize) -> ParElemIter;
}
```

`ParElemIter` implements `Iterator<Item = BgpElem>` and derefs nothing else. It is not
`Send`; a caller that wants to spread one file further can already split the file by byte
range at record boundaries and use several iterators, and that stays the recommended way to
use more cores than one stream can feed.

No existing type changes. `into_elem_iter` keeps its behaviour and its performance.

## 4. Shape

Three roles, all `std::thread`. `crossbeam-channel` is already in the tree but only as a
dev-dependency; promote it to a real dependency if a bounded MPMC queue turns out to be the
simplest correct thing (workers need one shared receiver), otherwise `std::sync::mpsc` plus a
`Mutex` around the receiver is enough. Do not add anything that is not already vendored.

- **producer** owns the reader. It runs the existing fast framing path (`read_chunk`), and on
  a `PEER_INDEX_TABLE` record it parses the table itself and publishes a new snapshot.
  Everything else is forwarded as `(seq: u64, body: Vec<u8>, header: CommonHeader,
  table: Arc<PeerIndexTable>)`.
- **workers** (`threads - 1` of them, plus the caller's thread as the last worker) take one
  record at a time, build a worker-local `Elementor` with `Elementor::with_peer_table`
  (`PeerIndexTable` is `Clone`, so each worker can hold the table for the snapshot it was
  handed), parse the body into a `Vec<BgpElem>`, and send `(seq, Vec<BgpElem>)` to the
  consumer.
- **consumer** is the `next()` of `ParElemIter`: it buffers out-of-order results in a
  `BTreeMap<u64, Vec<BgpElem>>` and yields the elems of `seq`, `seq + 1`, ... in order.

The producer/worker queues are `std::sync::mpsc::sync_channel(bound)`; workers share the
receiver through a `Mutex` (contention at record granularity, one lock per record, is not
measurable against the per-record parse). The consumer queue is a plain `mpsc`.

## 5. Invariants

1. **Order.** The element sequence is identical to the sequential iterator's, byte for byte,
   including within a record. `PEER_INDEX_TABLE` records produce no elems and are not
   ordered against anything.
2. **Bounded memory.** At most `bound_records` records are in flight end to end, where
   `bound_records = 2 * threads` plus one record being framed. A record body is already
   capped at 16 MiB by `MAX_MRT_MESSAGE_LEN`, so the worst case is bounded and documented.
3. **Peer table.** A worker only ever parses a body with the snapshot carried in the same
   message. If a second `PEER_INDEX_TABLE` appears mid-file, the producer drains in-flight
   work, publishes the new snapshot, and continues; no record is parsed against a snapshot
   that was not current when it was framed. (MRT files carry one table; BMP conversions can
   repeat it.)
4. **Error policy.** Identical to the sequential default iterator: a record that fails to
   parse is logged, a core dump is written when `core_dump` is enabled and the error class
   asks for it, and iteration continues. `disable_warnings()` suppresses the same warnings
   it suppresses today. Warnings are emitted from worker threads; the `log` crate is
   thread-safe.
5. **Same numbers.** An unfiltered parallel run must produce exactly the sequential item
   count, and the hash of the rendered elems must match.

## 6. Failure modes and what each does

- A worker panics: the consumer sees the channel close and stops, returning `None` early.
  A panic in a parser is a bug, not a data condition; the crate must not silently truncate.
  The consumer distinguishes "channel closed with seq gaps" and logs an error naming the
  expected and observed sequence numbers.
- The reader fails mid-file: the producer forwards the error the same way the sequential
  path does (log, optional core dump, stop), after draining the records already sent, so the
  output prefix matches sequential.
- `threads` larger than the file has records: workers exit when the producer closes the
  queue; no busy waiting.
- A caller drops `ParElemIter` early: the producer and workers observe the closed queues in
  `Drop` and exit; `Drop` joins them so no thread outlives the iterator.

## 7. Rollback

The change is additive and behind no feature flag; `into_elem_iter` is untouched, so the
rollback is deleting the new module and its tests. Nothing in the existing paths changes, so
a bad parallel path cannot regress the sequential one, only the new API entry point.

## 8. Acceptance

Measured on the rrc00 bview 2026-10-14, both the 4.06 GB decompressed copy and the 420 MB
`.gz`, instructions from `perf stat`, wall from `/usr/bin/time`, alternating runs, same
host, nothing else running:

- `threads = 1` matches the sequential iterator within 2% on instructions and wall.
- `threads = 8` on 16 cores: **wall <= 0.25 x sequential** (>= 4x), instructions unchanged
  within 5% (parallelism must not add per-record work).
- item count and an FNV-1a hash of the rendered elems are identical for
  `threads in {1, 2, 4, 8, 16}`.
- peak RSS at 8 threads stays under sequential + 64 MiB on this file.

Correctness gates, which must all pass before any measurement is reported:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`
- a new test that iterates a RIB fixture and an updates fixture (including one with a
  truncated tail) at 1, 2 and 8 threads and compares the exact elem stream against the
  sequential iterator
- a test that a file with two `PEER_INDEX_TABLE` records parses correctly in parallel

## 9. Open questions to resolve while implementing

- Whether the producer should also inflate (it does, since it owns the reader) or hand
  compressed chunks to workers. Reading is one thread by construction, so the producer
  bounds the pipeline; on the `.gz` input the inflate cost (about 3.4 s of 35 s) sits on the
  producer and must stay below the workers' parse rate at 8 threads. The measurement above
  settles whether it does.
- Whether the worker-local `Elementor` can drop its own peer-table copy. It borrows the
  `Arc<PeerIndexTable>` per record today; if that shows up in the profile, a worker can hold
  the `Arc` for the table it was handed.
- Whether `threads = available_parallelism()` should be the default for the CLI flag once
  the API exists. Default stays 1 in the library; the CLI decision needs both measurements
  and a note in the README.

## 10. Implementation notes

Implemented in `src/parser/iters/parallel.rs` (`ParElemIter`, re-exported from the crate
root), with tests in `tests/par_elem_iter.rs` and the module's unit tests, and a measurement
example in `examples/par_elem_count.rs`. The only change to existing code is that
`parse_mrt_record_with_zebra_compat` is split into `read_chunk` (now `pub(crate)`) and a new
`#[inline] parse_chunk_with_zebra_compat`, so the producer frames and the workers parse with
exactly the code the sequential path runs, including the wire bytes attached to an error for
core dumps. The sequential CLI `-e` run is unchanged by this: 315.87 G instructions / 35.04 s
before the change, 315.58 G / 34.79 s after (best of two runs each).

### Choices left open by the design

- **Queues: `std::sync::mpsc` only.** `crossbeam-channel` stays a dev-dependency. Work goes
  through one `sync_channel` whose receiver the workers share behind a `Mutex`; results come
  back on an unbounded `channel`. The bound is enforced by a third channel used as a credit
  counter (pre-filled with `2 * threads` tokens; the producer takes one before it frames a
  batch, the consumer returns it when it removes that batch from the reorder buffer). The work
  queue's capacity alone cannot bound memory, because the results queue and the reorder
  buffer sit behind it.
- **The producer owns inflation.** It does not limit throughput on this file: 8 threads take
  7.6 s on the `.gz` and 7.6 s on the decompressed `.mrt`, and the producer is about 6% of
  CPU samples at 8 threads.
- **A worker-local `Elementor`, holding its own clone of the table.** Each worker keeps the
  `Arc<PeerIndexTable>` of the last table it used and clones the table into its `Elementor`
  only when a record carries a different `Arc` (`Arc::ptr_eq`). That is one clone per table per
  worker, and nothing per record.

### Where the implementation departs from the design, and why

1. **The error policy runs on the consumer, not on the workers.** Section 5.4 says warnings
   come from worker threads. That cannot be identical to the sequential iterator: "log the
   first parse error at `error`, later ones at `debug`", "warn about Zebra compatibility
   once", and "stop at the first `ParseError` when core dumps are on" all depend on file
   order. Workers attach failures and Zebra flags to their results as events, positioned by
   elem index, and the consumer replays them in file order through the same
   `handle_record_parse_error` and `warn_zebra_compat_once` the sequential iterator calls, on
   a `BgpkitParser<io::Empty>` that carries the caller's options and log-once state. The only
   messages still logged from workers come from `Elementor` itself (missing peer table, peer
   index not found). Their text is identical; only how they interleave with other log lines
   can differ.
2. **Records travel in batches** of up to 512 records or 128 KiB of bodies, and the bound
   counts batches: at most `2 * threads` batches in flight plus the one being yielded.
   Handing over one record at a time cost a futex wake-up per record on every hop (47 s of
   system time at 8 threads). Batching cut that to 26 s, with no change in wall time until
   the fix in item 3. At 8 threads peak RSS is 46 to 50 MB against 7 to 8 MB sequentially,
   inside section 8's "sequential + 64 MiB". A slow live input sees elems in bursts, because a
   batch is handed over only when it is full or the input ends.
3. **The caller yields copies of worker-built elems; the originals go back to the worker
   that built them.** This is the main finding. Without it, 8 threads took 31 s against 34.8 s
   sequential, and 37 s once the caller stopped parsing. Profiling showed the caller thread
   spending its time in `free` and futex calls: with glibc malloc, freeing a block from a
   thread other than the one that allocated it takes the owning arena's lock, which the
   allocating worker keeps taking for its own allocations. Dropping 55.8 M worker-built elems
   on the caller thread was slower than parsing them on one thread. With the same code linked
   against jemalloc (a throwaway crate under `target/`, not part of the change), 8 threads took
   5.79 s against 31.89 s sequential at +3.7% instructions. So the pipeline scales and the
   allocator was the limit. The library cannot choose its users' allocator, so `ParElemIter`
   now copies each elem on the caller's thread: the vectors are copied as slices, AS path
   segments with `SmallVec::from_slice`. The batch of originals goes back over a per-worker
   channel and is freed by the thread that allocated it. Every allocation is then freed on the
   thread that made it. Under glibc this gives 7.6 s at 8 threads. The cost is instructions;
   see the acceptance table. Under jemalloc the copy is pure overhead (6.15 s instead of
   5.79 s).
4. **The caller's thread parses while it waits**, as designed. It takes a batch from the work
   queue only when its next batch has not arrived and the queue lock is free. Measured before
   item 3: removing this made 8 threads slower (37 s against 31 s).
5. **No drain on a second `PEER_INDEX_TABLE`.** Section 5.3 asks the producer to drain
   in-flight work first. That is not needed: every record carries the `Arc` of the table that
   was current when it was framed, so records framed before and after the new table can be
   in flight together without mixing tables. The two-table test has 3,000 RIB records under
   each table and runs at 2, 3, 8 and 16 threads.
6. **Panics.** Workers and the producer wrap each record in `catch_unwind`. A panic becomes an
   in-order `Panicked` event: the consumer yields every elem before that record, logs an
   error, stops and joins its threads. The sequential iterator would propagate the panic
   instead; section 6 asks for the logged early stop. If the threads stop without a final
   result (which `catch_unwind` should rule out), the consumer logs the missing and buffered
   batch numbers, as section 6 describes.
7. **Thread spawning can fail, and then the sequential iterator is used.** The reader moves
   to the producer over a channel only after every thread has spawned. If any
   `thread::Builder::spawn` fails, the spawned threads are joined and the parser is rebuilt
   for `ElemIterator`. This also covers `wasm32-unknown-unknown`, where spawning returns an
   error: the API compiles there without `cfg` gating
   (`cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`
   passes) and degrades to sequential at run time.
8. **Smaller points.** `threads` is clamped to 256. Filters, text-dump parsers, `threads <= 1`
   and spawn failure all use the sequential iterator. `ParElemIter` is made `!Send` with a
   `PhantomData<*const ()>`, as section 3 specifies. `Drop` closes the credit and result
   channels and joins every thread; if the producer is blocked inside the reader's `read`, the
   drop waits for that read to return.

### Acceptance (section 8), rrc00 bview 2026-10-14, 16 cores, glibc malloc

`par_elem_count <file> <threads> count` drops every elem as it arrives, the same work as
`bgpkit-parser -e`. `threads = 1` is the sequential `ElemIterator`. Two alternating rounds;
wall times from `/usr/bin/time`, instructions from `perf stat` (all threads).

| input | run | wall (s) r1 / r2 | instructions (G) | vs sequential | max RSS (MB) |
|---|---|---|---|---|---|
| .gz | CLI `-e`, before this change | 41.28 / 34.79 | 315.6 | | 7.6 |
| .gz | CLI `-e`, after | 35.04 / 35.04 | 315.9 | | 8.0 |
| .gz | threads = 1 (sequential) | 33.57 / 33.52 | 295.0 | 1.00x | 7.0 |
| .gz | threads = 2 | 23.36 / 23.57 | 349.7 | 0.70x | 19 |
| .gz | threads = 4 | 13.51 / 13.68 | 361.6 | 0.40x | 27 |
| .gz | threads = 8 | 7.64 / 7.60 | 369.2 | **0.227x** | 46 to 50 |
| .gz | threads = 16 | 8.09 / 8.48 | 371.4 | 0.25x | 105 to 110 |
| .mrt | CLI `-e`, after | 32.43 / 32.56 | 274.5 | | 7.6 |
| .mrt | threads = 1 | 32.33 / 32.75 | 276.4 | 1.00x | 6.8 |
| .mrt | threads = 8 | 7.73 / 7.55 | 351.0 | 0.236x | 48 to 51 |

- `threads = 1` matches the sequential iterator because it *is* the sequential iterator.
- Wall at 8 threads: 0.227x of the same-binary sequential run on `.gz` (0.217x of CLI `-e`),
  and 0.236x on `.mrt`. **Met.**
- Instructions at 8 threads: +25% over the same-binary sequential run on `.gz` (+17% over
  CLI `-e`), +27% on `.mrt`. **Not met** (target: within 5%). Almost all of the increase
  appears between 1 and 2 threads, so it is per-elem handoff cost, not per-thread cost: the
  copy in item 3 (one more malloc and free for each of `origin_asns` and `communities`, plus
  the copy itself), and moving batches between threads. With glibc and an iterator that
  yields owned elems, the choice is between this copy and cross-thread frees, and the latter
  made the parallel path slower than the sequential one. With jemalloc and no copy, the
  increase was +3.7%.
- Peak RSS at 8 threads: +39 to 43 MB over sequential. **Met** (target: under +64 MiB).
- Identical output: FNV-1a of every elem rendered as PSV plus `Debug`, 55,786,629 elems,
  `38d1bf21c638da54` for threads 1, 2, 4 and 8 (16: see below). Rendering on the caller
  thread then dominates (250 s sequential, 224 s parallel), so hash runs are a correctness
  check only.
- **Where scaling stops:** 16 threads is no faster than 8 (8.1 to 8.5 s), and the `.mrt` and
  `.gz` times are the same, so neither the workers nor inflation are the limit. The serial
  stage is the caller thread: it takes 136 ns per elem to copy the elem, yield it and drop
  it. Getting past about 7.5 s on this file needs that per-elem work to shrink: a cheaper
  copy, an allocator with cheap cross-thread frees, or an API that hands elems over in
  batches the caller can process on several threads.

### Open after this PR

- The CLI flag, and whether the CLI binary should link jemalloc or mimalloc: with that, the
  copy could be skipped, but the library cannot detect the global allocator.
- Filtered parallel iteration: filters would run on the workers, which also shrinks what the
  caller copies.
