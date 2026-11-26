/*!
Parallel element iteration over a single MRT stream.

[`BgpkitParser::into_par_elem_iter`] splits the work of the default element iterator over
three roles:

- a **producer** thread owns the reader (and therefore any decompression), frames records with
  the same code the sequential path uses, parses `PEER_INDEX_TABLE` records itself, and hands
  the other records to the workers in batches tagged with a sequence number; every record in a
  batch carries the peer-table snapshot that was current when it was framed;
- **workers** (`threads - 1` spawned threads, plus the caller's thread whenever it would
  otherwise wait) parse the records of a batch and convert them into elems;
- the **consumer**, which is [`ParElemIter::next`] on the caller's thread, puts batches back in
  file order and applies the parser's error policy to each record in that order.

The error policy runs on the consumer, in file order, through the same
`handle_record_parse_error` function the sequential iterator uses, so "log once" warnings,
core dumps and "stop at the first error when core dumps are enabled" behave exactly as they do
sequentially.

Records travel in batches of up to [`BATCH_MAX_RECORDS`] records or [`BATCH_MAX_BYTES`] of
record bodies, whichever fills first, so that channel operations, thread wake-ups and result
vectors are paid once per batch rather than once per record.

Memory is bounded by credits: the producer takes one credit before it starts a batch, and the
consumer returns it when it takes that batch's result out of the reorder buffer. At most
`2 * threads` batches are therefore being framed, queued, parsed or waiting for their turn at
any time, plus the one batch whose elems the caller is currently draining.

Elems a worker built are yielded as copies made on the caller's thread, and the originals go
back to the worker that allocated them to be freed (see `Draining`). Without that, the caller
frees every worker-built elem when it drops it, and with glibc's malloc those cross-thread frees
serialise on the workers' arena locks badly enough that eight threads ran slower than one.
*/
use crate::error::ParserErrorWithBytes;
use crate::models::{AsPath, AsPathSegment, Asn, MetaCommunity, PeerIndexTable, TableDumpV2Type};
use crate::models::{BgpElem, CommonHeader, EntryType, MrtMessage, MrtRecord, TableDumpV2Message};
use crate::parser::iters::default::ElemIterator;
use crate::parser::iters::handle_record_parse_error;
use crate::parser::mrt::mrt_record::{parse_chunk_with_zebra_compat, read_chunk, ChunkedRecord};
use crate::parser::{BgpkitParser, ParserError};
use crate::Elementor;
use log::error;
use smallvec::SmallVec;
use std::collections::{BTreeMap, VecDeque};
use std::io::Read;
use std::marker::PhantomData;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{
    channel, sync_channel, Receiver, RecvError, Sender, SyncSender, TryRecvError,
};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread::JoinHandle;

/// Thread counts above this are clamped: one framing thread cannot feed more parsers than this,
/// and the reorder bound (`2 * threads` batches) must stay small.
const MAX_THREADS: usize = 256;

/// Batches allowed in flight per parser thread (see the module documentation).
const BATCHES_IN_FLIGHT_PER_THREAD: usize = 2;

/// A batch is closed once it holds this many records...
const BATCH_MAX_RECORDS: usize = 512;

/// ...or this many bytes of record bodies, whichever comes first.
const BATCH_MAX_BYTES: usize = 128 * 1024;

/// Iterator over [`BgpElem`]s parsed by several threads, yielded in file order.
///
/// Created by [`BgpkitParser::into_par_elem_iter`]. The element sequence is identical to the one
/// [`BgpkitParser::into_elem_iter`] yields for the same input.
///
/// Dropping the iterator stops and joins every thread it started. If the producer is blocked
/// inside a `read` call of the underlying reader, the drop waits for that call to return.
///
/// Each element is copied on the calling thread before it is yielded, so the memory of the
/// elements you receive is allocated by the thread that will drop it; the parser threads free
/// their own copies. This costs some extra instructions per element but avoids cross-thread
/// frees, which glibc's allocator handles poorly.
///
/// The iterator is deliberately not `Send`: split a file by byte range at record boundaries and
/// use one iterator per range to spread work further.
pub struct ParElemIter {
    inner: Inner,
    _not_send: PhantomData<*const ()>,
}

enum Inner {
    Sequential(Box<dyn Iterator<Item = BgpElem>>),
    Parallel(Box<Pipeline>),
}

impl Iterator for ParElemIter {
    type Item = BgpElem;

    fn next(&mut self) -> Option<BgpElem> {
        match &mut self.inner {
            Inner::Sequential(iter) => iter.next(),
            Inner::Parallel(pipeline) => pipeline.next_elem(),
        }
    }
}

impl<R: Read + Send + 'static> BgpkitParser<R> {
    /// Iterate elements using `threads` parser threads, yielding in file order.
    ///
    /// The elements, their order, and the logging, warning and core-dump behaviour are the same
    /// as [`into_elem_iter`](Self::into_elem_iter)'s. One extra thread owns the reader (and
    /// decompression) and frames records; `threads - 1` threads parse them, and the calling
    /// thread parses too whenever the next element in file order is not ready yet.
    ///
    /// `threads == 0` or `1` runs the existing sequential iterator and spawns nothing.
    /// Requires `R: Send + 'static` because the reader moves to the producer thread.
    ///
    /// The sequential iterator is also used, with no threads spawned, when:
    /// - the parser has filters set (filtered parallel iteration is not supported yet);
    /// - the parser reads a text dump rather than MRT;
    /// - the platform cannot spawn threads (for example `wasm32-unknown-unknown`), or spawning
    ///   fails for any other reason.
    ///
    /// Records are handed to the parser threads in batches of up to 512 records or 128 KiB of
    /// record bodies. At most `2 * threads` batches are buffered between the reader and the
    /// caller, plus the batch whose elements are being yielded; a single record body is capped
    /// at 16 MiB by the framing code. Because a batch is only handed over once it is full (or
    /// the input ends), a slow, live input sees elements in bursts. `threads` above 256 is
    /// treated as 256.
    ///
    /// If a parser thread panics, the panic message is printed by the panic hook, an error
    /// naming the record is logged, and iteration ends after the elements that precede that
    /// record.
    ///
    /// # Example
    /// ```no_run
    /// use bgpkit_parser::BgpkitParser;
    ///
    /// let parser = BgpkitParser::new("rib.20261014.0000.bz2").unwrap();
    /// let count = parser.into_par_elem_iter(8).count();
    /// println!("{count} elems");
    /// ```
    pub fn into_par_elem_iter(self, threads: usize) -> ParElemIter {
        let threads = threads.min(MAX_THREADS);
        let inner = if threads <= 1 || !self.filters.is_empty() || self.text_dump_iter.is_some() {
            Inner::Sequential(Box::new(ElemIterator::new(self)))
        } else {
            match Pipeline::start(self, threads) {
                Ok(pipeline) => Inner::Parallel(Box::new(pipeline)),
                Err(parser) => Inner::Sequential(Box::new(ElemIterator::new(parser))),
            }
        };
        ParElemIter {
            inner,
            _not_send: PhantomData,
        }
    }
}

/*********
Messages
**********/

/// One record of a batch, in file order.
enum Item {
    /// A framed record for a worker to parse with the peer table current when it was framed.
    Parse {
        chunk: ChunkedRecord,
        table: Option<Arc<PeerIndexTable>>,
    },
    /// A record the producer already parsed (only a `PEER_INDEX_TABLE`-subtype record that did
    /// not parse to a peer table, which the parser never produces) for a worker to convert.
    Convert {
        record: MrtRecord,
        used_zebra_compat: bool,
        table: Option<Arc<PeerIndexTable>>,
    },
    /// A framing or peer-table parse failure, for the consumer's error policy.
    Failed(ParserErrorWithBytes),
    /// The producer panicked while framing this record.
    Panicked,
}

struct Batch {
    seq: u64,
    items: Vec<Item>,
}

/// Something the consumer must do, in order, before yielding the elem at `position`.
enum Event {
    /// The record was recovered with the Zebra BGP4MP compatibility path.
    ZebraCompat,
    Failed(ParserErrorWithBytes),
    Panicked,
}

/// The elems of every record of a batch, in order, with the per-record events placed by elem
/// position, so the consumer replays exactly the sequential order of warnings, errors and elems.
struct BatchResult {
    elems: Vec<BgpElem>,
    events: VecDeque<(usize, Event)>,
    /// Where the elems go back to be freed: the worker thread that allocated them. `None` for a
    /// batch the consumer parsed itself.
    home: Option<Sender<Vec<BgpElem>>>,
}

/*********
Workers
**********/

/// A worker's elementor, holding a private copy of the peer-table snapshot it was last handed.
///
/// The copy is refreshed only when a record carries a different snapshot (compared by `Arc`
/// identity), which is once per `PEER_INDEX_TABLE` per worker.
#[derive(Default)]
struct WorkerState {
    table: Option<Arc<PeerIndexTable>>,
    elementor: Elementor,
}

impl WorkerState {
    fn use_table(&mut self, table: &Option<Arc<PeerIndexTable>>) {
        let current = match (&self.table, table) {
            (None, None) => true,
            (Some(have), Some(want)) => Arc::ptr_eq(have, want),
            _ => false,
        };
        if !current {
            self.elementor = match table {
                Some(table) => Elementor::with_peer_table(PeerIndexTable::clone(table)),
                None => Elementor::new(),
            };
            self.table = table.clone();
        }
    }

    /// Append a parsed record's elems exactly as `ElemIterator` yields them.
    fn convert(
        &mut self,
        record: MrtRecord,
        used_zebra_compat: bool,
        table: &Option<Arc<PeerIndexTable>>,
        out: &mut BatchResult,
    ) {
        if used_zebra_compat {
            out.events.push_back((out.elems.len(), Event::ZebraCompat));
        }
        self.use_table(table);
        let mut pending = self.elementor.ingest(record);
        while let Some(elem) = pending.next_elem(self.elementor.peer_table.as_ref()) {
            out.elems.push(elem);
        }
    }

    fn process_item(&mut self, item: Item, out: &mut BatchResult) {
        match item {
            Item::Parse { chunk, table } => match parse_chunk_with_zebra_compat(chunk) {
                Ok((record, used_zebra_compat)) => {
                    self.convert(record, used_zebra_compat, &table, out)
                }
                Err(error) => out
                    .events
                    .push_back((out.elems.len(), Event::Failed(error))),
            },
            Item::Convert {
                record,
                used_zebra_compat,
                table,
            } => self.convert(record, used_zebra_compat, &table, out),
            Item::Failed(error) => out
                .events
                .push_back((out.elems.len(), Event::Failed(error))),
            Item::Panicked => out.events.push_back((out.elems.len(), Event::Panicked)),
        }
    }

    /// Process a whole batch. A panic on one record ends the batch at that record with
    /// [`Event::Panicked`]; the consumer stops there, so the rest of the batch is not needed.
    fn run(&mut self, batch: Batch) -> (u64, BatchResult) {
        let mut out = BatchResult {
            elems: Vec::new(),
            events: VecDeque::new(),
            home: None,
        };
        for item in batch.items {
            let position = out.elems.len();
            let events = out.events.len();
            if catch_unwind(AssertUnwindSafe(|| self.process_item(item, &mut out))).is_err() {
                // drop whatever the panicking record left behind
                out.elems.truncate(position);
                out.events.truncate(events);
                out.events.push_back((position, Event::Panicked));
                *self = WorkerState::default();
                break;
            }
        }
        (batch.seq, out)
    }
}

fn lock_batches(batches: &Mutex<Receiver<Batch>>) -> MutexGuard<'_, Receiver<Batch>> {
    // Nothing panics while holding this lock (parsing happens after it is released), and a
    // `Receiver` has no invariant a panic could break, so a poisoned lock is still usable.
    batches
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn worker_loop(batches: Arc<Mutex<Receiver<Batch>>>, results: Sender<(u64, BatchResult)>) {
    let mut state = WorkerState::default();
    // Elems come back here once the consumer has copied them, so this thread frees what it
    // allocated (see `Draining`).
    let (home, returned) = channel::<Vec<BgpElem>>();
    loop {
        // the guard is a temporary: the lock is released before the batch is parsed
        let batch = match lock_batches(&batches).recv() {
            Ok(batch) => batch,
            // the producer finished or the consumer shut the pipeline down
            Err(RecvError) => return,
        };
        let (seq, mut result) = state.run(batch);
        result.home = Some(home.clone());
        if results.send((seq, result)).is_err() {
            // the consumer is gone
            return;
        }
        returned.try_iter().for_each(drop);
    }
}

/*********
Producer
**********/

fn is_peer_index_table(header: &CommonHeader) -> bool {
    header.entry_type == EntryType::TABLE_DUMP_V2
        && header.entry_subtype == u16::from(TableDumpV2Type::PeerIndexTable)
}

/// Whether the producer must stop reading after a framing error.
///
/// These are the classes after which the sequential iterator stops whatever the parser options:
/// the stream ended, failed, or lost record alignment. Every other error is forwarded and the
/// producer keeps framing; the consumer's error policy decides whether iteration continues.
fn framing_error_is_terminal(error: &ParserError) -> bool {
    match error {
        ParserError::EofExpected
        | ParserError::IoError(_)
        | ParserError::EofError(_)
        | ParserError::OversizedRecord { .. }
        | ParserError::FilterError(_) => true,
        #[cfg(feature = "oneio")]
        ParserError::OneIoError(_) => true,
        _ => false,
    }
}

struct Producer<R> {
    reader: R,
    /// The peer table snapshot later records are framed under.
    table: Option<Arc<PeerIndexTable>>,
}

impl<R: Read> Producer<R> {
    /// Frame the next record into `items`. Returns the body bytes added and whether the stream
    /// has ended.
    fn frame_one(&mut self, items: &mut Vec<Item>) -> (usize, bool) {
        let chunk = match read_chunk(&mut self.reader) {
            Ok(chunk) => chunk,
            Err(error) => {
                let terminal = framing_error_is_terminal(&error.error);
                items.push(Item::Failed(ParserErrorWithBytes {
                    error: error.error,
                    bytes: error.bytes,
                }));
                return (0, terminal);
            }
        };
        let bytes = chunk.body.len();
        if !is_peer_index_table(&chunk.common_header) {
            items.push(Item::Parse {
                chunk,
                table: self.table.clone(),
            });
            return (bytes, false);
        }
        // A peer table changes how every later record converts, so it is parsed here, in order,
        // and published as a new snapshot that later records carry.
        match parse_chunk_with_zebra_compat(chunk) {
            Ok((
                MrtRecord {
                    message: MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(pit)),
                    ..
                },
                _,
            )) => self.table = Some(Arc::new(pit)),
            Ok((record, used_zebra_compat)) => items.push(Item::Convert {
                record,
                used_zebra_compat,
                table: self.table.clone(),
            }),
            Err(error) => items.push(Item::Failed(error)),
        }
        (bytes, false)
    }

    /// Frame records until a batch is full or the stream ends.
    fn fill(&mut self, items: &mut Vec<Item>) -> bool {
        let mut bytes = 0;
        while items.len() < BATCH_MAX_RECORDS && bytes < BATCH_MAX_BYTES {
            let framed = catch_unwind(AssertUnwindSafe(|| self.frame_one(items)));
            match framed {
                Ok((added, false)) => bytes += added,
                Ok((_, true)) => return true,
                Err(_) => {
                    items.push(Item::Panicked);
                    return true;
                }
            }
        }
        false
    }
}

fn producer_loop<R: Read>(reader: Receiver<R>, credits: Receiver<()>, batches: SyncSender<Batch>) {
    // The reader arrives only once every thread has been spawned; if spawning failed the
    // sender is dropped and the reader goes back to a sequential iterator instead.
    let Ok(reader) = reader.recv() else {
        return;
    };
    let mut producer = Producer {
        reader,
        table: None,
    };
    let mut seq: u64 = 0;
    loop {
        // one credit per batch bounds everything downstream
        if credits.recv().is_err() {
            return;
        }
        let mut items = Vec::new();
        let ended = producer.fill(&mut items);
        // never blocks: the queue holds as many batches as there are credits
        if batches.send(Batch { seq, items }).is_err() || ended {
            return;
        }
        seq += 1;
    }
}

/*********
Consumer
**********/

/// The batch the consumer is yielding from.
///
/// Elems a worker built are cloned on the caller's thread, and the batch of originals goes back
/// to that worker to be freed there. With glibc's malloc, freeing a block on a thread other
/// than the one that allocated it takes the owning arena's lock, which the allocating worker
/// keeps taking for its own allocations; a caller freeing tens of millions of worker-built
/// elems (which is what dropping them does) serialises on those locks and ends up slower than
/// the sequential iterator. The copy keeps every allocation and its free on one thread, for the
/// price of one clone per elem.
enum Draining {
    /// Elems the caller's thread built itself.
    Owned(std::vec::IntoIter<BgpElem>),
    /// Elems a worker built, yielded as copies.
    Copied {
        elems: Vec<BgpElem>,
        next: usize,
        home: Sender<Vec<BgpElem>>,
    },
}

impl Default for Draining {
    fn default() -> Self {
        Draining::Owned(Vec::new().into_iter())
    }
}

/// A copy of `elem` whose heap allocations belong to the calling thread.
///
/// Equal to `elem.clone()`, but copies the `Copy` element vectors and inline AS path segments
/// as slices instead of element by element: this runs once per elem on the caller's thread,
/// which is the one serial stage of the pipeline.
fn copy_elem(elem: &BgpElem) -> BgpElem {
    BgpElem {
        timestamp: elem.timestamp,
        elem_type: elem.elem_type,
        peer_ip: elem.peer_ip,
        peer_asn: elem.peer_asn,
        peer_bgp_id: elem.peer_bgp_id,
        prefix: elem.prefix,
        next_hop: elem.next_hop,
        as_path: elem.as_path.as_ref().map(copy_path),
        origin_asns: elem.origin_asns.as_deref().map(<[Asn]>::to_vec),
        origin: elem.origin,
        local_pref: elem.local_pref,
        med: elem.med,
        communities: elem.communities.as_deref().map(<[MetaCommunity]>::to_vec),
        atomic: elem.atomic,
        aggr_asn: elem.aggr_asn,
        aggr_ip: elem.aggr_ip,
        only_to_customer: elem.only_to_customer,
        unknown: elem.unknown.clone(),
        deprecated: elem.deprecated.clone(),
    }
}

fn copy_path(path: &AsPath) -> AsPath {
    let segments = path
        .segments
        .iter()
        .map(|segment| match segment {
            AsPathSegment::AsSequence(asns) => {
                AsPathSegment::AsSequence(SmallVec::from_slice(asns))
            }
            AsPathSegment::AsSet(asns) => AsPathSegment::AsSet(SmallVec::from_slice(asns)),
            AsPathSegment::ConfedSequence(asns) => {
                AsPathSegment::ConfedSequence(SmallVec::from_slice(asns))
            }
            AsPathSegment::ConfedSet(asns) => AsPathSegment::ConfedSet(SmallVec::from_slice(asns)),
        })
        .collect();
    AsPath { segments }
}

impl Draining {
    fn new(elems: Vec<BgpElem>, home: Option<Sender<Vec<BgpElem>>>) -> Self {
        match home {
            Some(home) => Draining::Copied {
                elems,
                next: 0,
                home,
            },
            None => Draining::Owned(elems.into_iter()),
        }
    }

    fn next(&mut self) -> Option<BgpElem> {
        match self {
            Draining::Owned(elems) => elems.next(),
            Draining::Copied { elems, next, .. } => {
                let elem = copy_elem(elems.get(*next)?);
                *next += 1;
                Some(elem)
            }
        }
    }

    /// Hand the originals back to the worker that built them.
    fn release(&mut self) {
        if let Draining::Copied { elems, home, .. } = std::mem::take(self) {
            // a worker that has exited cannot take them back; they are freed here instead
            let _ = home.send(elems);
        }
    }
}

struct Pipeline {
    /// The caller's parser without its reader: options, core-dump flag and log-once state for
    /// the error policy, which runs here in file order.
    policy: BgpkitParser<std::io::Empty>,
    /// `None` once the pipeline has been shut down.
    results: Option<Receiver<(u64, BatchResult)>>,
    credits: Option<SyncSender<()>>,
    batches: Option<Arc<Mutex<Receiver<Batch>>>>,
    /// Lets the caller's thread parse while it waits.
    local: WorkerState,
    /// Results that arrived before their turn.
    reorder: BTreeMap<u64, BatchResult>,
    next_seq: u64,
    /// The batch being drained.
    current: Draining,
    events: VecDeque<(usize, Event)>,
    /// Elems of `current` yielded so far.
    yielded: usize,
    handles: Vec<JoinHandle<()>>,
}

impl Pipeline {
    /// Spawn the producer and `threads - 1` workers, or give the parser back if any spawn fails.
    fn start<R: Read + Send + 'static>(
        parser: BgpkitParser<R>,
        threads: usize,
    ) -> Result<Pipeline, BgpkitParser<R>> {
        let BgpkitParser {
            reader,
            core_dump,
            filters,
            options,
            text_dump_iter,
        } = parser;
        let policy = BgpkitParser {
            reader: std::io::empty(),
            core_dump,
            filters,
            options,
            text_dump_iter,
        };

        let bound = threads.saturating_mul(BATCHES_IN_FLIGHT_PER_THREAD);
        let (credit_tx, credit_rx) = sync_channel::<()>(bound);
        for _ in 0..bound {
            // cannot fail: the receiver is alive and the channel has room for `bound` credits
            let _ = credit_tx.try_send(());
        }
        let (batch_tx, batch_rx) = sync_channel::<Batch>(bound);
        let batch_rx = Arc::new(Mutex::new(batch_rx));
        let (result_tx, result_rx) = channel::<(u64, BatchResult)>();
        let (reader_tx, reader_rx) = sync_channel::<R>(1);

        let mut pipeline = Pipeline {
            policy,
            results: Some(result_rx),
            credits: Some(credit_tx),
            batches: Some(Arc::clone(&batch_rx)),
            local: WorkerState::default(),
            reorder: BTreeMap::new(),
            next_seq: 0,
            current: Draining::default(),
            events: VecDeque::new(),
            yielded: 0,
            handles: Vec::with_capacity(threads),
        };

        let mut spawned = std::thread::Builder::new()
            .name("bgpkit-par-producer".to_string())
            .spawn(move || producer_loop(reader_rx, credit_rx, batch_tx))
            .map(|handle| pipeline.handles.push(handle));
        for i in 1..threads {
            if spawned.is_err() {
                break;
            }
            let batches = Arc::clone(&batch_rx);
            let results = result_tx.clone();
            spawned = std::thread::Builder::new()
                .name(format!("bgpkit-par-worker-{i}"))
                .spawn(move || worker_loop(batches, results))
                .map(|handle| pipeline.handles.push(handle));
        }
        // only the workers may hold result senders, so the consumer sees a disconnect when the
        // last of them exits
        drop(result_tx);
        drop(batch_rx);

        let handed_over = match spawned {
            Ok(()) => reader_tx.send(reader).map_err(|returned| returned.0),
            Err(_) => Err(reader),
        };
        match handed_over {
            Ok(()) => Ok(pipeline),
            Err(reader) => {
                drop(reader_tx);
                pipeline.shutdown();
                let policy = std::mem::replace(
                    &mut pipeline.policy,
                    BgpkitParser::from_reader(std::io::empty()),
                );
                Err(BgpkitParser {
                    reader,
                    core_dump: policy.core_dump,
                    filters: policy.filters,
                    options: policy.options,
                    text_dump_iter: policy.text_dump_iter,
                })
            }
        }
    }

    fn next_elem(&mut self) -> Option<BgpElem> {
        loop {
            // events belong before the elem at their position
            while self
                .events
                .front()
                .is_some_and(|(position, _)| *position <= self.yielded)
            {
                let Some((_, event)) = self.events.pop_front() else {
                    break;
                };
                if !self.handle(event) {
                    self.shutdown();
                    return None;
                }
            }
            if let Some(elem) = self.current.next() {
                self.yielded += 1;
                return Some(elem);
            }
            let batch = self.next_batch()?;
            self.current.release();
            self.current = Draining::new(batch.elems, batch.home);
            self.events = batch.events;
            self.yielded = 0;
        }
    }

    /// Apply the sequential iterator's policy to one event. `false` ends iteration.
    fn handle(&mut self, event: Event) -> bool {
        match event {
            Event::ZebraCompat => {
                self.policy.warn_zebra_compat_once();
                true
            }
            Event::Failed(error) => {
                handle_record_parse_error(&mut self.policy, error.error, error.bytes)
            }
            Event::Panicked => {
                error!(
                    "parallel elem iterator: a parser thread panicked on a record of batch {}; \
                     stopping after the elems before it",
                    self.next_seq.saturating_sub(1)
                );
                false
            }
        }
    }

    /// The result of batch `next_seq`, waiting for it (and parsing on this thread meanwhile)
    /// if needed. `None` once the pipeline is shut down or its threads stopped early.
    fn next_batch(&mut self) -> Option<BatchResult> {
        loop {
            if let Some(result) = self.reorder.remove(&self.next_seq) {
                self.next_seq += 1;
                if let Some(credits) = &self.credits {
                    // never blocks; fails only once the producer has finished, which is fine
                    let _ = credits.try_send(());
                }
                return Some(result);
            }
            let results = self.results.as_ref()?;
            let received = match results.try_recv() {
                Ok(result) => Ok(result),
                Err(TryRecvError::Disconnected) => Err(()),
                Err(TryRecvError::Empty) => match self.try_take_batch() {
                    Some(batch) => Ok(self.local.run(batch)),
                    None => results.recv().map_err(|_| ()),
                },
            };
            match received {
                Ok((seq, result)) => {
                    self.reorder.insert(seq, result);
                }
                Err(()) => {
                    self.report_disconnect();
                    self.shutdown();
                    return None;
                }
            }
        }
    }

    fn try_take_batch(&self) -> Option<Batch> {
        let batches = self.batches.as_ref()?;
        match batches.try_lock() {
            Ok(guard) => guard.try_recv().ok(),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().try_recv().ok(),
            // a worker is waiting on the queue and will take the next batch
            Err(TryLockError::WouldBlock) => None,
        }
    }

    fn report_disconnect(&self) {
        let buffered = match (self.reorder.keys().next(), self.reorder.keys().next_back()) {
            (Some(first), Some(last)) => format!("batches {first}..={last} are buffered"),
            _ => "nothing is buffered".to_string(),
        };
        error!(
            "parallel elem iterator: parser threads stopped before batch {} was delivered \
             ({buffered}); stopping early",
            self.next_seq
        );
    }

    /// Stop every thread and wait for them. Idempotent.
    fn shutdown(&mut self) {
        // The producer wakes from waiting on a credit, the workers from waiting on the batch
        // queue once the producer has dropped it, and anything mid-batch exits when its result
        // cannot be delivered.
        self.credits = None;
        self.results = None;
        self.batches = None;
        self.reorder.clear();
        self.current.release();
        self.events.clear();
        for handle in self.handles.drain(..) {
            // threads catch their own panics, so a join error is not expected; there is nothing
            // further to do with one
            let _ = handle.join();
        }
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sequential(iter: &ParElemIter) -> bool {
        matches!(iter.inner, Inner::Sequential(_))
    }

    #[test]
    fn zero_and_one_threads_take_the_sequential_path() {
        for threads in [0, 1] {
            let iter = BgpkitParser::from_reader(Cursor::new(Vec::<u8>::new()))
                .into_par_elem_iter(threads);
            assert!(sequential(&iter), "threads = {threads} spawned a pipeline");
        }
        let iter = BgpkitParser::from_reader(Cursor::new(Vec::<u8>::new())).into_par_elem_iter(2);
        assert!(!sequential(&iter), "threads = 2 did not start a pipeline");
    }

    #[test]
    fn filters_take_the_sequential_path() {
        let iter = BgpkitParser::from_reader(Cursor::new(Vec::<u8>::new()))
            .add_filter("type", "w")
            .unwrap()
            .into_par_elem_iter(4);
        assert!(sequential(&iter));
    }

    #[test]
    fn empty_input_ends_without_elems() {
        let mut iter =
            BgpkitParser::from_reader(Cursor::new(Vec::<u8>::new())).into_par_elem_iter(4);
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }

    /// The producer stops reading exactly where the sequential policy stops regardless of the
    /// parser options; everything else it forwards.
    #[test]
    fn terminal_framing_errors_are_the_ones_the_policy_always_stops_at() {
        let errors = || {
            vec![
                ParserError::EofExpected,
                ParserError::IoError(std::io::Error::other("io")),
                ParserError::EofError(std::io::Error::other("eof")),
                ParserError::OversizedRecord { length: u32::MAX },
                ParserError::FilterError("filter".to_string()),
                ParserError::ParseError("parse".to_string()),
                ParserError::TruncatedMsg("truncated".to_string()),
                ParserError::Unsupported("unsupported".to_string()),
                ParserError::InvalidPrefix,
                ParserError::TruncatedPrefix,
            ]
        };
        for (error, again) in errors().into_iter().zip(errors()) {
            let mut parser = BgpkitParser::from_reader(std::io::empty()).disable_warnings();
            // no bytes, so no core dump is written
            let continues = handle_record_parse_error(&mut parser, again, None);
            assert_eq!(
                framing_error_is_terminal(&error),
                !continues,
                "producer and policy disagree on {error:?}"
            );
        }
    }

    /// A reader that panics stops the iterator instead of hanging it.
    #[test]
    fn producer_panic_stops_iteration() {
        struct PanickingReader;
        impl Read for PanickingReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                panic!("reader exploded");
            }
        }
        let mut iter = BgpkitParser::from_reader(PanickingReader).into_par_elem_iter(3);
        assert!(!sequential(&iter));
        assert!(iter.next().is_none());
    }

    /// Events are replayed before the elem at their position, and a stopping event discards
    /// the rest of the batch, as the sequential iterator never reaches those records.
    #[test]
    fn events_are_replayed_in_elem_order() {
        let mut pipeline = match Pipeline::start(
            BgpkitParser::from_reader(Cursor::new(Vec::<u8>::new())).disable_warnings(),
            2,
        ) {
            Ok(pipeline) => pipeline,
            Err(_) => return, // no threads on this platform
        };
        // drain the real (empty) stream first
        assert!(pipeline.next_elem().is_none());
        let elem = BgpElem::default();
        let (home, returned) = channel();
        pipeline.current = Draining::new(vec![elem.clone(), elem.clone(), elem], Some(home));
        pipeline.yielded = 0;
        pipeline.events = VecDeque::from(vec![
            (0, Event::ZebraCompat),
            (
                2,
                Event::Failed(ParserErrorWithBytes {
                    error: ParserError::IoError(std::io::Error::other("stop")),
                    bytes: None,
                }),
            ),
        ]);
        assert!(pipeline.next_elem().is_some());
        assert!(pipeline.next_elem().is_some());
        // the failure sits before the third elem and stops iteration
        assert!(pipeline.next_elem().is_none());
        assert!(pipeline.next_elem().is_none());
        // the originals went back to their (here: this test's) home to be freed
        assert_eq!(returned.try_recv().map(|elems| elems.len()), Ok(3));
    }

    /// The copy the caller yields is the elem the worker built, field for field.
    #[test]
    fn copied_elems_equal_their_originals() {
        use crate::models::{
            AttrRaw, Community, ElemType, ExtendedCommunity, LargeCommunity, NetworkPrefix,
        };
        use std::str::FromStr;
        let long_path: Vec<u32> = (1..=40).collect();
        let elem = BgpElem {
            timestamp: 1.5,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: "2001:db8::1".parse().unwrap(),
            peer_asn: Asn::new_32bit(65000),
            peer_bgp_id: Some("192.0.2.1".parse().unwrap()),
            prefix: NetworkPrefix::from_str("2001:db8::/32").unwrap(),
            next_hop: Some("2001:db8::2".parse().unwrap()),
            as_path: Some(AsPath::from_segments(vec![
                AsPathSegment::AsSequence(long_path.iter().map(|asn| Asn::from(*asn)).collect()),
                AsPathSegment::AsSet([7u32, 8].iter().map(|asn| Asn::from(*asn)).collect()),
                AsPathSegment::ConfedSequence([9u32].iter().map(|asn| Asn::from(*asn)).collect()),
                AsPathSegment::ConfedSet([10u32].iter().map(|asn| Asn::from(*asn)).collect()),
            ])),
            origin_asns: Some(vec![Asn::from(40u32)]),
            origin: None,
            local_pref: Some(100),
            med: Some(5),
            communities: Some(vec![
                MetaCommunity::Plain(Community::NoExport),
                MetaCommunity::Large(LargeCommunity::new(1, [2, 3])),
                MetaCommunity::Extended(ExtendedCommunity::Raw([0; 8])),
            ]),
            atomic: true,
            aggr_asn: Some(Asn::from(1u32)),
            aggr_ip: Some("192.0.2.9".parse().unwrap()),
            only_to_customer: Some(Asn::from(2u32)),
            unknown: Some(vec![AttrRaw {
                code: 250,
                bytes: bytes::Bytes::from_static(b"unknown"),
            }]),
            deprecated: Some(vec![AttrRaw {
                code: 28,
                bytes: bytes::Bytes::from_static(b"deprecated"),
            }]),
        };
        assert_eq!(copy_elem(&elem), elem);
        assert_eq!(format!("{:?}", copy_elem(&elem)), format!("{elem:?}"));
        let empty = BgpElem::default();
        assert_eq!(copy_elem(&empty), empty);
    }
}
