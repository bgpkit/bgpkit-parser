//! Benchmark harness for comparing `next_record_elems` against `into_elem_iter` on RIB files.
//!
//! Modes:
//! - `view-count`: count-only walk via `next_record_elems` (`for _ in rec.iter()`)
//! - `view-fields`: walk reading `prefix + peer + as_path + origin_asns` via `next_record_elems`
//! - `owned-count`: count-only walk via `into_elem_iter`
//! - `owned-fields`: walk reading `prefix + peer + as_path + origin_asns` via `into_elem_iter`

use bgpkit_parser::BgpkitParser;
use std::hint::black_box;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("usage: elem_view_bench <file> <view-count|view-fields|owned-count|owned-fields>");
    let mode = args.next().expect("missing mode");

    match mode.as_str() {
        "view-count" => {
            let mut parser = BgpkitParser::new(&path).expect("open input");
            let mut count = 0usize;
            while let Some(mut rec) = parser.next_record_elems() {
                for elem in rec.iter() {
                    black_box(&elem);
                    count += 1;
                }
            }
            println!("elems: {count}");
        }
        "view-fields" => {
            let mut parser = BgpkitParser::new(&path).expect("open input");
            let mut count = 0usize;
            let mut acc = 0u64;
            while let Some(mut rec) = parser.next_record_elems() {
                for elem in rec.iter() {
                    black_box(elem.prefix());
                    black_box(elem.peer_ip());
                    acc = acc.wrapping_add(u32::from(elem.peer_asn()) as u64);
                    for asn in elem.as_path() {
                        acc = acc.wrapping_add(u32::from(asn) as u64);
                    }
                    for origin in elem.origin_asns() {
                        acc = acc.wrapping_add(u32::from(origin) as u64);
                    }
                    count += 1;
                }
            }
            black_box(acc);
            println!("elems: {count} (checksum: {acc})");
        }
        "owned-count" => {
            let parser = BgpkitParser::new(&path).expect("open input");
            let mut count = 0usize;
            for elem in parser.into_elem_iter() {
                black_box(&elem);
                count += 1;
            }
            println!("elems: {count}");
        }
        "owned-fields" => {
            let parser = BgpkitParser::new(&path).expect("open input");
            let mut count = 0usize;
            let mut acc = 0u64;
            for elem in parser.into_elem_iter() {
                black_box(elem.prefix);
                black_box(elem.peer_ip);
                acc = acc.wrapping_add(u32::from(elem.peer_asn) as u64);
                if let Some(path) = &elem.as_path {
                    for asn in path.iter_segments().flatten() {
                        acc = acc.wrapping_add(u32::from(*asn) as u64);
                    }
                }
                if let Some(origins) = &elem.origin_asns {
                    for origin in origins {
                        acc = acc.wrapping_add(u32::from(*origin) as u64);
                    }
                }
                count += 1;
            }
            black_box(acc);
            println!("elems: {count} (checksum: {acc})");
        }
        other => panic!("unknown mode: {other}"),
    }
}
