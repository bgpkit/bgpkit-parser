//! Full-fidelity RIS Live raw parsing: `parse_ris_live_message_raw_full`.
//!
//! Unlike the elem-only RIS Live APIs, the full parser preserves everything
//! the elem conversion drops: originator ID, cluster list, AIGP, BGP
//! Prefix-SID, raw-retained BGPSEC_PATH/ATTR_SET, and every other path
//! attribute, plus RFC 7606 validation warnings from the parse itself.
//!
//! The example embeds a real RIS Live `ris_message` captured with
//! `socketOptions.includeRaw = true` (the same fixture used by the wasm
//! test suite), prints the elements, then the attributes the elems dropped.
//!
//! For live streaming see `real_time_ris_live_websocket.rs`; for the
//! JSON-projected fields without `includeRaw`, use `parse_ris_live_message`
//! or the wasm `parseRisLiveMessageJson` export.

use bgpkit_parser::parse_ris_live_message_raw_full;

const RIS_MESSAGE: &str = r#"{
    "type": "ris_message",
    "data": {
        "timestamp": 1636245154.8,
        "peer": "2001:7f8:b:100:1d1:a520:1333:74",
        "peer_asn": "201333",
        "id": "10-183678-175313836",
        "host": "rrc10",
        "type": "UPDATE",
        "raw": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0086020000006F4001010040021202040003127500001A6A000000AE00004FF980040400000000C008081A6A001E1A6A3840800E4100020120200107F8000B010001D1A52013330074FE800000000000000217A3FFFEFE290500302A0E97C70000302A0E97C600FE302A10CC4217B7302A10CC421FEB"
    }
}"#;

fn main() {
    let full = parse_ris_live_message_raw_full(RIS_MESSAGE)
        .unwrap_or_else(|error| panic!("fixture must parse: {error}"));

    println!(
        "host={} peer AS{} at {}",
        full.meta.host, full.meta.peer_asn, full.meta.timestamp
    );
    for elem in &full.elems {
        println!(
            "  {:?} {} via {:?}",
            elem.elem_type, elem.prefix, elem.next_hop
        );
    }

    println!("\nfull attribute set (fields the elem conversion drops stay visible here):");
    for value in &full.attributes {
        println!("  {:?}", value.attr_type());
    }

    if full.validation_warnings.is_empty() {
        println!("\nno RFC 7606 validation warnings");
    } else {
        println!("\nRFC 7606 validation warnings:");
        for warning in &full.validation_warnings {
            println!("  {warning:?}");
        }
    }
}
