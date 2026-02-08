use bgpkit_parser::models::*;
use bgpkit_parser::BgpkitParser;
use bgpkit_parser::Elementor;
use std::sync::Mutex;

const CHUNK_SIZE: usize = 16_384;

/// an very simple example that reads a remote BGP data file and print out the message count.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = "https://data.ris.ripe.net/rrc00/2026.02/bview.20260208.0800.gz";

    // Iterate over the file in order
    let parser = BgpkitParser::new_cached(url, "/tmp").unwrap();
    let t0 = std::time::Instant::now();
    let cnt = parser.into_elem_iter().count();

    println!("Total number of routes: {cnt}");
    println!("Time elapsed: {:?}", t0.elapsed());

    // Scan the raw records
    let parser = BgpkitParser::new_cached(url, "/tmp").unwrap();

    let t0 = std::time::Instant::now();
    let cnt = parser.into_raw_record_iter().count();
    println!("Total number of records: {cnt}");
    println!(
        "Time elapsed: {:?}s (to chunk into raw records)",
        t0.elapsed()
    );

    // Iterate over the BGPElem's after parsing with Elementor, using the default pattern where we mutate the elementor.
    let parser = BgpkitParser::new_cached(url, "/tmp").unwrap();
    let mut elementor = Elementor::new();

    let t0 = std::time::Instant::now();
    let mut cnt = 0;
    for raw_record in parser.into_raw_record_iter() {
        if let Ok(record) = raw_record.parse() {
            cnt += elementor.record_to_elems(record).iter().count();
        }
    }
    println!("Total number of routes: {cnt}");
    println!(
        "Time elapsed: {:?}s (parse to RawRecord, turn into BgpElem using Elementor)",
        t0.elapsed()
    );

    // Producer-consumer parallel iteration: a dedicated producer thread reads
    // and decompresses chunks, sending them through a channel to worker threads
    // that parse and convert records in parallel.
    let parser = BgpkitParser::new_cached(url, "/tmp").unwrap();

    let mut record_iter = parser.into_raw_record_iter().peekable();

    let t0 = std::time::Instant::now();

    // Peek to see if the first element is a peer index table. If so, consume it and set it.
    let elementor = match record_iter.peek().cloned().and_then(|r| r.parse().ok()) {
        Some(MrtRecord {
            message: MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(pit)),
            ..
        }) => {
            record_iter.next();
            Elementor::with_peer_table(pit)
        }
        _ => Elementor::new(),
    };

    let num_threads = std::thread::available_parallelism()?.get();
    let iter = Mutex::new(record_iter);

    let total: u64 = std::thread::scope(|s| {
        let elementor = &elementor;
        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                s.spawn(|| {
                    let mut local_count: u64 = 0;
                    loop {
                        // lock the iterator and take a chunk of records.
                        let chunk: Vec<_> = {
                            let mut it = iter.lock().unwrap();
                            it.by_ref().take(CHUNK_SIZE).collect()
                        };
                        if chunk.is_empty() {
                            break;
                        }
                        for record in chunk {
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

    println!("Total records: {total}");
    println!(
        "Time elapsed: {:?} (set peer index table on Elementor, iterate in parallel over chunks)",
        t0.elapsed()
    );
    Ok(())
}
