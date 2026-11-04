//! Fixed-workload parse loop used to measure parser changes.
//!
//! Decompresses the corpus once, then parses the in-memory buffer `iters` times, so the reported
//! cost covers parsing only. Run it under `perf stat -e instructions` (or `/usr/bin/time`) and
//! compare revisions on the same machine:
//!
//! ```sh
//! cargo build --release --example perf_workload
//! perf stat -e instructions target/release/examples/perf_workload \
//!   /path/to/rib-example-small.bz2 elems 10   # or records, raw
//! ```
//!
//! Fixed startup (open, decompress) is included once; run two iteration counts and use
//! `P = (I(10) - I(2)) / 8` to get the per-parse cost without it.

use bgpkit_parser::BgpkitParser;
use std::hint::black_box;
use std::io::Read;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("usage: perf_workload <file> <records|elems> <iters>");
    let mode = args.next().expect("records or elems");
    let iters: usize = args.next().unwrap_or_else(|| "1".into()).parse().unwrap();

    let mut data = Vec::new();
    oneio::get_reader(&path)
        .expect("open corpus")
        .read_to_end(&mut data)
        .expect("read corpus");

    let mut total = 0usize;
    for _ in 0..iters {
        match mode.as_str() {
            "raw" => {
                let mut reader = black_box(data.as_slice());
                total += BgpkitParser::from_reader(&mut reader)
                    .into_raw_record_iter()
                    .count();
            }
            "records" => {
                let mut reader = black_box(data.as_slice());
                total += BgpkitParser::from_reader(&mut reader)
                    .into_record_iter()
                    .count();
            }
            "elems" => {
                let mut reader = black_box(data.as_slice());
                total += BgpkitParser::from_reader(&mut reader)
                    .into_elem_iter()
                    .map(|elem| {
                        black_box(elem);
                        1
                    })
                    .sum::<usize>();
            }
            other => panic!("unknown mode {other}"),
        }
    }
    black_box(total);
}
