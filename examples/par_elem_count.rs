//! Count, or hash, the elems of one MRT file with `into_par_elem_iter`.
//!
//! Used to measure the parallel element iterator against the sequential one:
//!
//! ```sh
//! cargo build --release --example par_elem_count
//! target/release/examples/par_elem_count <file> <threads> [count|hash]
//! ```
//!
//! `threads = 1` runs the sequential iterator. `count` drops every elem as it
//! arrives (the work `bgpkit-parser -e` does); `hash` renders every elem as
//! PSV plus its `Debug` form and folds them into a 64-bit FNV-1a hash, so two
//! runs with different thread counts can be compared for identical output.

use bgpkit_parser::BgpkitParser;
use std::io::Write;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn main() {
    let mut args = std::env::args().skip(1);
    let usage = "usage: par_elem_count <file> <threads> [count|hash]";
    let path = args.next().expect(usage);
    let threads: usize = args.next().expect(usage).parse().expect(usage);
    let mode = args.next().unwrap_or_else(|| "count".to_string());

    let parser = BgpkitParser::new(&path).expect("open input");
    let elems = parser.into_par_elem_iter(threads);
    match mode.as_str() {
        "count" => println!("total elems: {}", elems.count()),
        "hash" => {
            let mut hash = FNV_OFFSET;
            let mut count = 0u64;
            let mut line = Vec::with_capacity(1024);
            for elem in elems {
                line.clear();
                writeln!(line, "{elem}\n{elem:?}").expect("render elem");
                hash = fnv1a(hash, &line);
                count += 1;
            }
            println!("total elems: {count}  fnv1a: {hash:016x}");
        }
        other => panic!("unknown mode {other}; {usage}"),
    }
}
