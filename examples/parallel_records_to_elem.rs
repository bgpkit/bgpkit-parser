use bgpkit_parser::BgpkitParser;
use bgpkit_parser::Elementor;
use std::sync::Mutex;

const CHUNK_SIZE: usize = 16_384;

/// This example demonstrates parallel processing of MRT records using the immutable Elementor API.
///
/// The key insight is that once the Elementor is initialized with a PeerIndexTable (for RIB dumps),
/// it can be shared across threads for parallel parsing. This example shows:
///
/// 1. Sequential processing using the default `into_elem_iter()` API
/// 2. Sequential processing using `record_to_elems()` with a mutable Elementor
/// 3. Parallel processing using `record_to_elems_iter()` with an immutable shared Elementor
///
/// The parallel processing achieves significant speedup (typically 4-8x on multi-core systems)
/// by distributing the CPU-intensive parsing work across multiple threads.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = "https://data.ris.ripe.net/rrc00/2026.02/bview.20260208.0800.gz";

    // =========================================================================
    // Approach 1: Sequential processing using default iterator
    // =========================================================================
    // The simplest approach: use `into_elem_iter()` which handles everything internally.
    // This is convenient but single-threaded.
    let parser = BgpkitParser::new_cached(url, "/tmp").unwrap();
    let t0 = std::time::Instant::now();
    let cnt = parser.into_elem_iter().count();

    println!("Total number of routes (sequential default): {cnt}");
    println!("Time elapsed: {:?}", t0.elapsed());

    // =========================================================================
    // Approach 2: Sequential processing with mutable Elementor
    // =========================================================================
    // For more control, manually parse records and use `record_to_elems()`.
    // The Elementor is mutable because it needs to consume and store the PeerIndexTable.
    let parser = BgpkitParser::new_cached(url, "/tmp").unwrap();
    let mut elementor = Elementor::new();

    let t0 = std::time::Instant::now();
    let mut cnt = 0;
    for raw_record in parser.into_raw_record_iter() {
        if let Ok(record) = raw_record.parse() {
            cnt += elementor.record_to_elems(record).len();
        }
    }
    println!("\nTotal number of routes (sequential mutable Elementor): {cnt}");
    println!(
        "Time elapsed: {:?} (parser -> RawRecord -> Elementor::record_to_elems)",
        t0.elapsed()
    );

    // =========================================================================
    // Approach 3: Parallel processing with immutable shared Elementor
    // =========================================================================
    // For maximum performance, use `into_elementor_and_raw_records()` to:
    // 1. Extract the PeerIndexTable from the first record
    // 2. Create an immutable Elementor
    // 3. Process records in parallel across multiple threads
    //
    // Key design:
    // - `into_elementor_and_raw_records()` handles the peek/consume logic for you
    // - The returned Elementor is immutable (`&self`) and can be shared across threads
    // - `record_to_elems_iter()` returns a lazy iterator, avoiding Vec allocation
    // - `std::thread::scope()` allows borrowing data without requiring 'static lifetime
    let parser = BgpkitParser::new_cached(url, "/tmp").unwrap();

    // This method:
    // - Peeks at the first record to check for PeerIndexTable
    // - If found, creates an Elementor with that table
    // - Returns (Elementor, iterator over remaining raw records)
    let (elementor, raw_records) = parser.into_elementor_and_raw_record_iter();

    let t0 = std::time::Instant::now();

    // Wrap in a Mutex to allow multiple threads to safely take chunks
    let iter = Mutex::new(raw_records.peekable());
    let num_threads = std::thread::available_parallelism()?.get();

    let total: u64 = std::thread::scope(|s| {
        let elementor = &elementor;
        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                s.spawn(|| {
                    let mut local_count: u64 = 0;
                    loop {
                        // Lock the iterator and take a chunk of records
                        let chunk: Vec<_> = {
                            let mut it = iter.lock().unwrap();
                            it.by_ref().take(CHUNK_SIZE).collect()
                        };
                        if chunk.is_empty() {
                            break;
                        }
                        for record in chunk {
                            // Parse the raw record and convert to BgpElems
                            if let Ok(record) = record.parse() {
                                if let Ok(elems) = elementor.record_to_elems_iter(record) {
                                    local_count += elems.count() as u64;
                                }
                            }
                        }
                    }
                    local_count
                })
            })
            .collect();

        handles.into_iter().map(|h| h.join().unwrap()).sum()
    });

    println!("\nTotal records (parallel immutable Elementor): {total}");
    println!(
        "Time elapsed: {:?} (parallel processing across {num_threads} threads)",
        t0.elapsed()
    );

    Ok(())
}
