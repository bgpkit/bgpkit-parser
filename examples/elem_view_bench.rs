//! Benchmark harness for comparing `next_record_elems` against `into_elem_iter` on RIB files.
//!
//! Modes:
//! - `view-count`: count-only walk via `next_record_elems` (`for _ in rec.iter()`)
//! - `view-fields`: walk reading `prefix + peer + as_path + origin_asns` via `next_record_elems`
//! - `owned-count`: count-only walk via `into_elem_iter`
//! - `owned-fields`: walk reading `prefix + peer + as_path + origin_asns` via `into_elem_iter`
//! - `owned-echo`: walk materialising every owned elem and mixing all its fields

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
            while let Some(rec) = parser.next_record_elems() {
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
            while let Some(rec) = parser.next_record_elems() {
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
        "owned-echo" => {
            let parser = BgpkitParser::new(&path).expect("open input");
            let mut count = 0usize;
            let mut acc = 0u64;
            for elem in parser.into_elem_iter() {
                acc = mix_elem(&elem, acc);
                count += 1;
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

/// Mix every elem field so neither path can be optimised away, and so both paths are compared on
/// exactly the same amount of consumer work.
fn mix_elem(elem: &bgpkit_parser::BgpElem, mut acc: u64) -> u64 {
    acc = acc.wrapping_add(elem.prefix.prefix.addr().to_string().len() as u64);
    acc = acc.wrapping_add(u32::from(elem.peer_asn) as u64);
    acc = acc.wrapping_add(elem.peer_ip.to_string().len() as u64);
    acc = acc.wrapping_add(elem.next_hop.map_or(0, |hop| hop.to_string().len() as u64));
    if let Some(path) = &elem.as_path {
        for segment in &path.segments {
            let asns = match segment {
                bgpkit_parser::models::AsPathSegment::AsSequence(values)
                | bgpkit_parser::models::AsPathSegment::AsSet(values)
                | bgpkit_parser::models::AsPathSegment::ConfedSequence(values)
                | bgpkit_parser::models::AsPathSegment::ConfedSet(values) => values,
            };
            acc = acc.wrapping_add(asns.len() as u64);
            for asn in asns {
                acc = acc.wrapping_add(u32::from(*asn) as u64);
            }
        }
    }
    if let Some(origins) = &elem.origin_asns {
        for asn in origins {
            acc = acc.wrapping_add(u32::from(*asn) as u64);
        }
    }
    if let Some(communities) = &elem.communities {
        acc = acc.wrapping_add(communities.len() as u64);
    }
    acc = acc.wrapping_add(elem.med.unwrap_or(0) as u64);
    acc = acc.wrapping_add(elem.local_pref.unwrap_or(0) as u64);
    acc = acc.wrapping_add(elem.origin.map_or(0, u8::from) as u64);
    acc
}
