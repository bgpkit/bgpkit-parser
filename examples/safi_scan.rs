//! Scan MRT update files for NLRI AFI/SAFI usage and rare path attributes.
//!
//! Purpose: check which of the issue-#301 target attributes/SAFIs appear in real
//! RIS/RouteViews data. Attribute counts for the full corpus live in
//! spectrum.update_file_attribute (terrier PG18); this tool adds SAFI visibility,
//! which the file-level attribute tally does not capture.
//!
//! Run: cargo run --release --all-features --example safi_scan -- <url-or-path>...

use std::collections::BTreeMap;

use bgpkit_parser::models::{AttributeValue, Bgp4MpEnum, Bgp4MpMessage, BgpMessage, MrtMessage};
use bgpkit_parser::BgpkitParser;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: safi_scan <mrt-url-or-path>...");
        std::process::exit(2);
    }
    let mut safi_counts: BTreeMap<(u16, u8), u64> = BTreeMap::new();
    let mut attr_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut records = 0u64;
    let mut updates = 0u64;
    for input in &args {
        let parser = match BgpkitParser::new(input) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("skip {input}: {e}");
                continue;
            }
        };
        for record in parser.into_record_iter() {
            records += 1;
            let MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(m)) = record.message else {
                continue;
            };
            let Bgp4MpMessage { bgp_message, .. } = m;
            let BgpMessage::Update(u) = bgp_message else {
                continue;
            };
            updates += 1;
            for attr in &u.attributes {
                *attr_counts
                    .entry(format!("{:?}", attr.attr_type()))
                    .or_default() += 1;
                if let AttributeValue::MpReachNlri(nlri) | AttributeValue::MpUnreachNlri(nlri) =
                    attr
                {
                    *safi_counts
                        .entry((u16::from(nlri.afi), u8::from(nlri.safi)))
                        .or_default() += 1;
                }
            }
        }
    }
    println!(
        "== files: {} records: {} updates: {}",
        args.len(),
        records,
        updates
    );
    println!("== AFI/SAFI (count of MP_REACH/MP_UNREACH attributes seen):");
    for ((afi, safi), n) in &safi_counts {
        println!("  afi={afi} safi={safi}: {n}");
    }
    println!("== attribute tallies:");
    for (t, n) in &attr_counts {
        println!("  {t}: {n}");
    }
}
