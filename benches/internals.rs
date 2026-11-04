//! In-process parsing benchmarks.
//!
//! Every benchmark parses an in-memory MRT byte buffer, so decompression and I/O are excluded by
//! design and the numbers describe the parser itself. Two corpora are always measured: the small
//! update file and the small RIB fixture. Real archives can be added without touching the code:
//!
//! ```sh
//! BGPKIT_BENCH_RIB=/path/to/bview.gz BGPKIT_BENCH_UPDATES=/path/to/updates.gz \
//!   cargo bench --bench internals -- --save-baseline main
//! ```
//!
//! Those opt-in corpora are streamed from the file (so decompression is included) and are read
//! with `BGPKIT_BENCH_STREAM_ELEMS` elements per iteration (default 1,000,000).
//!
//! Each benchmark reports throughput next to the wall time. Record-oriented benchmarks report
//! records/s and elem-oriented benchmarks report elems/s; the two are not interchangeable, so
//! compare a benchmark only with itself.

use bgpkit_parser::models::{MrtMessage, TableDumpV2Message};
use bgpkit_parser::{BgpkitParser, Elementor};
use bzip2::bufread::BzDecoder;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use flate2::bufread::GzDecoder;
use std::fs::File;
use std::hint::black_box;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Duration;

mod data_source;

/// Upper bound on the decompressed bytes held in memory for a corpus. The fixtures are far
/// smaller; the bound only protects against pointing an opt-in variable at a full RIB archive.
const MAX_PRELOAD_BYTES: usize = 64 * 1024 * 1024;

/// How many records the record-to-elem benchmark keeps in memory between iterations.
const ELEMENTOR_RECORDS: usize = 100_000;

/// Default number of elems streamed per iteration for the opt-in file corpora.
const STREAM_ELEMS: usize = 1_000_000;

fn preload<R: Read>(input_reader: R) -> Vec<u8> {
    let mut buffer = Vec::new();
    input_reader
        .take(MAX_PRELOAD_BYTES as u64)
        .read_to_end(&mut buffer)
        .expect("read corpus");
    buffer
}

/// Items each iteration of a parse mode yields for `data`.
struct Counts {
    records: u64,
    elems: u64,
    updates: u64,
    routes: u64,
}

fn count_items(data: &[u8]) -> Counts {
    let records = BgpkitParser::from_reader(black_box(data)).into_record_iter().count() as u64;
    let elems = BgpkitParser::from_reader(black_box(data)).into_elem_iter().count() as u64;
    let updates = BgpkitParser::from_reader(black_box(data))
        .into_update_iter()
        .count() as u64;
    let routes = BgpkitParser::from_reader(black_box(data))
        .into_route_iter()
        .count() as u64;
    Counts {
        records,
        elems,
        updates,
        routes,
    }
}

fn bench_corpus(c: &mut Criterion, label: &str, data: &[u8]) {
    let counts = count_items(data);
    println!(
        "{label}: {} bytes in memory, {} records, {} elems, {} updates, {} routes",
        data.len(),
        counts.records,
        counts.elems,
        counts.updates,
        counts.routes
    );

    let mut group = c.benchmark_group(label);
    group.measurement_time(Duration::from_secs(30));

    group.throughput(Throughput::Elements(counts.records));
    group.bench_function("into_raw_record_iter", |b| {
        b.iter(|| {
            let mut reader = black_box(data);
            BgpkitParser::from_reader(&mut reader)
                .into_raw_record_iter()
                .for_each(|x| {
                    black_box(x);
                });
        })
    });
    group.bench_function("into_record_iter", |b| {
        b.iter(|| {
            let mut reader = black_box(data);
            BgpkitParser::from_reader(&mut reader)
                .into_record_iter()
                .for_each(|x| {
                    black_box(x);
                });
        })
    });
    group.bench_function("into_update_iter", |b| {
        b.iter(|| {
            let mut reader = black_box(data);
            BgpkitParser::from_reader(&mut reader)
                .into_update_iter()
                .for_each(|x| {
                    black_box(x);
                });
        })
    });

    group.throughput(Throughput::Elements(counts.elems));
    group.bench_function("into_elem_iter", |b| {
        b.iter(|| {
            let mut reader = black_box(data);
            BgpkitParser::from_reader(&mut reader)
                .into_elem_iter()
                .for_each(|x| {
                    black_box(x);
                });
        })
    });

    group.throughput(Throughput::Elements(counts.routes));
    group.bench_function("into_route_iter", |b| {
        b.iter(|| {
            let mut reader = black_box(data);
            BgpkitParser::from_reader(&mut reader)
                .into_route_iter()
                .for_each(|x| {
                    black_box(x);
                });
        })
    });

    // Record-to-elem conversion on its own: the records are parsed during setup, so only the
    // Elementor is timed.
    //
    // TableDumpV2 RIB records can only be converted when the Elementor holds the peer index
    // table, so the table record is lifted out of the parsed prefix and given to one Elementor.
    let mut records: Vec<_> = BgpkitParser::from_reader(black_box(data))
        .into_record_iter()
        .take(ELEMENTOR_RECORDS)
        .collect();
    let peer_table = records.iter().position(|record| {
        matches!(
            &record.message,
            MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(_))
        )
    });
    let elementor = match peer_table {
        Some(index) => match records.remove(index).message {
            MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(table)) => {
                Elementor::with_peer_table(table)
            }
            _ => Elementor::new(),
        },
        None => Elementor::new(),
    };
    let elem_count: u64 = records
        .iter()
        .map(|record| {
            elementor
                .record_to_elems_iter(record.clone())
                .map(|iter| iter.count() as u64)
                .unwrap_or(0)
        })
        .sum();
    println!("elementor: {} records, {} elems", records.len(), elem_count);
    group.throughput(Throughput::Elements(elem_count.max(1)));
    group.bench_function("elementor record_to_elems_iter", |b| {
        b.iter_batched(
            || records.clone(),
            |records| {
                for record in records {
                    if let Ok(elems) = elementor.record_to_elems_iter(record) {
                        elems.for_each(|x| {
                            black_box(x);
                        });
                    }
                }
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// End-to-end benchmark against a real archive: open, decompress, parse, but stop after a fixed
/// number of elems so the iteration time stays bounded.
fn bench_file(c: &mut Criterion, label: &str, path: &Path, elems: usize) {
    let path_str = path
        .to_str()
        .expect("corpus path is valid UTF-8")
        .to_string();
    let available = BgpkitParser::new(path_str.as_str())
        .expect("open corpus")
        .into_elem_iter()
        .take(elems)
        .count() as u64;
    println!(
        "{label}: {} ({:.1} MiB on disk), streaming {} elems per iteration",
        path.display(),
        std::fs::metadata(path).map(|m| m.len() as f64 / 1_048_576.0).unwrap_or(0.0),
        available
    );

    let mut group = c.benchmark_group(label);
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    group.throughput(Throughput::Elements(available.max(1)));
    group.bench_function("into_elem_iter (file)", |b| {
        b.iter(|| {
            let parser = BgpkitParser::new(black_box(path_str.as_str())).expect("open corpus");
            parser.into_elem_iter().take(elems).for_each(|x| {
                black_box(x);
            });
        })
    });
    group.finish();
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let update_data = data_source::test_data_file("update-example.gz");
    let rib_data = data_source::test_data_file("rib-example-small.bz2");

    println!("Decompressing input data and loading into memory...");
    let updates = preload(GzDecoder::new(BufReader::new(
        File::open(&update_data).expect("open update fixture"),
    )));
    let rib_dump = preload(BzDecoder::new(BufReader::new(
        File::open(&rib_data).expect("open rib fixture"),
    )));
    println!(
        "Update file: {} ({} bytes decompressed)",
        update_data.display(),
        updates.len()
    );
    println!(
        "RIB file: {} ({} bytes decompressed)",
        rib_data.display(),
        rib_dump.len()
    );

    bench_corpus(c, "updates", &updates);
    bench_corpus(c, "rib", &rib_dump);

    let stream_elems = std::env::var("BGPKIT_BENCH_STREAM_ELEMS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(STREAM_ELEMS);
    if let Some(path) = data_source::env_corpus("BGPKIT_BENCH_RIB") {
        bench_file(c, "real rib", &path, stream_elems);
    }
    if let Some(path) = data_source::env_corpus("BGPKIT_BENCH_UPDATES") {
        bench_file(c, "real updates", &path, stream_elems);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(30));
    targets = criterion_benchmark
}
criterion_main!(benches);
