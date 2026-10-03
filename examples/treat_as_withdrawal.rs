//! # RFC 7606 error handling: treat-as-withdraw and friends
//!
//! RFC 7606 replaces "reset the session on any UPDATE error" with per-attribute
//! approaches, from weakest to strongest:
//!
//! 1. **Attribute discard**: drop the malformed attribute, keep the routes.
//! 2. **Treat-as-withdraw**: withdraw every route the UPDATE announces.
//! 3. **AFI/SAFI disable**: stop accepting the family the error concerns.
//! 4. **Session reset**: send a NOTIFICATION and reset the session.
//!
//! When an UPDATE has several errors, the strongest approach wins (§3(h)).
//!
//! bgpkit-parser records every finding as a `BgpValidationWarning`, classifies it with
//! `BgpValidationWarning::error_handling_approach`, and combines them per UPDATE with
//! `BgpUpdateMessage::error_handling_approach`. MRT data does not record whether a session
//! was iBGP or eBGP; route collectors peer over eBGP, so the classification assumes eBGP.
//!
//! This example scans an updates file twice:
//!
//! - over records, printing each UPDATE that has an approach and the finding behind it;
//! - over elements with `enable_rfc7606_error_handling()`, counting the announcements a
//!   compliant speaker would not have installed.
//!
//! Run with:
//! ```sh
//! cargo run --example treat_as_withdrawal --features="local"
//! ```

use bgpkit_parser::models::{
    Bgp4MpEnum, BgpMessage, ElemType, ErrorHandlingApproach, MrtMessage, MrtRecord,
};
use bgpkit_parser::BgpkitParser;
use std::collections::BTreeMap;

fn update_of(record: &MrtRecord) -> Option<&bgpkit_parser::models::BgpUpdateMessage> {
    match &record.message {
        MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(msg)) => match &msg.bgp_message {
            BgpMessage::Update(update) => Some(update),
            _ => None,
        },
        _ => None,
    }
}

fn main() {
    // Point this at a collector and time window where malformed messages are suspected.
    let url = "https://data.ris.ripe.net/rrc00/2026.07/updates.20260727.0000.gz";

    println!("Scanning {url} for UPDATE errors...\n");

    let parser = match BgpkitParser::new(url) {
        Ok(p) => p.disable_warnings(),
        Err(e) => {
            eprintln!("Failed to create parser: {e}");
            return;
        }
    };

    let mut by_approach: BTreeMap<ErrorHandlingApproach, u64> = BTreeMap::new();
    for record in parser.into_record_iter() {
        let Some(update) = update_of(&record) else {
            continue;
        };
        let Some(approach) = update.error_handling_approach() else {
            continue;
        };
        *by_approach.entry(approach).or_default() += 1;

        println!("--- {approach:?} at {} ---", record.common_header.timestamp);
        for warning in update.attributes.validation_warnings() {
            let marker = match warning.error_handling_approach() {
                Some(a) if a == approach => "→",
                _ => " ",
            };
            println!("  {marker} {warning}");
        }
        println!();
    }

    println!("=== UPDATEs per approach ===");
    for (approach, count) in &by_approach {
        println!("  {approach:?}: {count}");
    }

    // The same file as elements, with RFC 7606 applied.
    let parser = match BgpkitParser::new(url) {
        Ok(p) => p.disable_warnings().enable_rfc7606_error_handling(),
        Err(e) => {
            eprintln!("Failed to create parser: {e}");
            return;
        }
    };
    let mut withdrawn = 0u64;
    let mut reset = 0u64;
    let mut discarded = 0u64;
    for elem in parser {
        match (elem.elem_type, elem.error_handling) {
            (ElemType::WITHDRAW, Some(ErrorHandlingApproach::TreatAsWithdraw)) => withdrawn += 1,
            (ElemType::RESET, _) => reset += 1,
            (ElemType::ANNOUNCE, Some(ErrorHandlingApproach::AttributeDiscard)) => discarded += 1,
            _ => {}
        }
    }

    println!("\n=== Elements with RFC 7606 applied ===");
    println!("  announcements treated as withdrawn:     {withdrawn}");
    println!("  announcements in session-reset UPDATEs: {reset}");
    println!("  announcements with attributes dropped:  {discarded}");
}
