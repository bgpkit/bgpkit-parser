//! Tally AS4_PATH / AS4_AGGREGATOR occurrences and the peers that emit them.
//!
//! AS4_PATH (RFC 6793) is carried by a speaker only when it must send AS_PATH
//! information to a 2-byte-only peer: the 2-byte AS_PATH replaces 4-byte ASNs
//! with AS_TRANS (23456) and the original tail is preserved in AS4_PATH. Seeing
//! AS4_PATH in a RouteViews/RIPE RIS UPDATE file therefore singles out peers
//! whose session with the collector negotiated without the 4-byte AS capability.
//!
//! Background measurement (spectrum telemetry over ~85k parsed update files,
//! 2026-08-11..18): AS4_PATH appears in ~0.01% of announcements and in only
//! 3 of ~100 collectors, each time from a single legacy peer (AS40864 at
//! route-views7, AS61292 at rrc00, AS13760 at route-views.flix), with the
//! expected `23456` in AS_PATH where AS4_PATH carries the real 4-byte ASN.
//!
//! This example uses the distinct `AttributeValue::AsPath` / `As4Path` variants
//! (post-#330 API) with record-level iteration, because `BgpElem` exposes only
//! the RFC 6793-merged path and drops the peer attribution of the raw attrs.
//!
//! ```sh
//! cargo run --all-features --example as4_tally -- <url-or-path> [...]
//! ```
use bgpkit_parser::models::{
    AttributeValue, Bgp4MpEnum, Bgp4MpMessage, BgpMessage, MrtMessage, MrtRecord,
};
use bgpkit_parser::BgpkitParser;
use std::collections::HashMap;
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: as4_tally <url-or-path> [...]");
        std::process::exit(2);
    }
    let mut as4_path = 0u64;
    let mut as4_agg = 0u64;
    let mut as_path = 0u64;
    let mut total_records = 0u64;
    // peer ASN -> UPDATEs carrying AS4_PATH
    let mut peers: HashMap<u32, u64> = HashMap::new();
    let mut samples = 0u32;
    let mut out = std::io::stdout();
    for url in &args {
        let parser = match BgpkitParser::new(url) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("skip {url}: {e}");
                continue;
            }
        };
        for record in parser.into_record_iter() {
            total_records += 1;
            let Some((peer_asn, msg)) = extract(record) else {
                continue;
            };
            let BgpMessage::Update(u) = &msg else {
                continue;
            };
            let mut has_as4 = false;
            let mut as4_sample: Option<String> = None;
            let mut as_sample: Option<String> = None;
            for attr in &u.attributes {
                match attr {
                    AttributeValue::As4Path(p) => {
                        as4_path += 1;
                        has_as4 = true;
                        if as4_sample.is_none() {
                            as4_sample = Some(format!("{p:?}"));
                        }
                    }
                    AttributeValue::As4Aggregator { .. } => as4_agg += 1,
                    AttributeValue::AsPath(p) => {
                        as_path += 1;
                        if as_sample.is_none() {
                            as_sample = Some(format!("{p:?}"));
                        }
                    }
                    _ => {}
                }
            }
            if has_as4 && samples < 3 {
                samples += 1;
                let _ = writeln!(
                    out,
                    "sample: peer AS{peer_asn} as_path={:?} as4_path={:?}",
                    as_sample, as4_sample
                );
            }
            if has_as4 {
                *peers.entry(peer_asn).or_insert(0) += 1;
            }
        }
    }
    let _ = writeln!(out, "inputs: {}", args.len());
    let _ = writeln!(out, "mrt_records: {total_records}");
    let _ = writeln!(out, "AS_PATH: {as_path}");
    let _ = writeln!(out, "AS4_PATH: {as4_path}");
    let _ = writeln!(out, "AS4_AGGREGATOR: {as4_agg}");
    let _ = writeln!(out, "peers_emitting_AS4_PATH (peer_asn updates):");
    let mut v: Vec<(u32, u64)> = peers.into_iter().collect();
    v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    for (asn, c) in v {
        let _ = writeln!(out, "  AS{asn} {c}");
    }
}

/// Pull (peer ASN, BGP message) from a BGP4MP MESSAGE record; `None` for other shapes.
fn extract(record: MrtRecord) -> Option<(u32, BgpMessage)> {
    let MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(m)) = record.message else {
        return None;
    };
    let Bgp4MpMessage {
        peer_asn,
        bgp_message,
        ..
    } = m;
    Some((peer_asn.to_u32(), bgp_message))
}
