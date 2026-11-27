//! Application-level workloads over one RIB file: no rendering, only the fields a task needs.
//!
//! Modes: `prefix-owned`, `prefix-view`, `aspath-owned`, `aspath-view`.
//! The owned modes iterate `into_elem_iter()`; the view modes iterate `next_record_elems()`.
//! Both report the same checksum, so the two paths can be shown to do the same work.

use bgpkit_parser::BgpkitParser;
use std::hint::black_box;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn prefix_bytes(prefix: &bgpkit_parser::models::NetworkPrefix) -> (Vec<u8>, u8) {
    use std::net::IpAddr;
    let net = prefix.prefix;
    let addr: IpAddr = net.addr();
    let bytes = match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    (bytes, net.prefix_len())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: workload_bench <file> <mode>");
    let mode = args.next().expect("missing mode");

    let mut count = 0usize;
    match mode.as_str() {
        "prefix-owned" | "aspath-owned" => {
            let parser = BgpkitParser::new(&path).expect("open input");
            let mut hash = FNV_OFFSET;
            let mut asn_sum = 0u64;
            for elem in parser.into_elem_iter() {
                if mode == "prefix-owned" {
                    let (bytes, mask) = prefix_bytes(&elem.prefix);
                    hash = fnv(hash, &bytes);
                    hash = fnv(hash, &[mask]);
                } else if let Some(path) = &elem.as_path {
                    for segment in &path.segments {
                        asn_sum += segment.len() as u64;
                    }
                }
                count += 1;
            }
            if mode == "prefix-owned" {
                println!("elems: {count} prefix_hash: {hash}");
            } else {
                println!("elems: {count} asn_sum: {asn_sum}");
            }
        }
        "prefix-view" | "aspath-view" => {
            let mut parser = BgpkitParser::new(&path).expect("open input");
            let mut hash = FNV_OFFSET;
            let mut asn_sum = 0u64;
            while let Some(mut record) = parser.next_record_elems() {
                for elem in record.iter() {
                    if mode == "prefix-view" {
                        let (bytes, mask) = prefix_bytes(&elem.prefix());
                        hash = fnv(hash, &bytes);
                        hash = fnv(hash, &[mask]);
                    } else {
                        for segment in elem.as_path().segments() {
                            asn_sum += segment.len() as u64;
                        }
                    }
                    count += 1;
                }
            }
            if mode == "prefix-view" {
                println!("elems: {count} prefix_hash: {hash}");
            } else {
                println!("elems: {count} asn_sum: {asn_sum}");
            }
        }
        other => panic!("unknown mode {other}"),
    }
    black_box(count);
}
