//! # RFC 7606 Treat-as-Withdrawal Emulation
//!
//! This example demonstrates how to detect malformed BGP UPDATE messages and
//! apply RFC 7606 "treat-as-withdrawal" semantics using bgpkit-parser's
//! validation warning system.
//!
//! RFC 7606 defines two error-handling approaches for malformed UPDATE messages:
//!
//! - **attribute discard**: discard the offending attribute, keep the route
//! - **treat-as-withdrawal**: withdraw all routes carried in the UPDATE
//!
//! bgpkit-parser automatically applies "attribute discard" for bad optional
//! transitive attributes. For malformed NLRI (RFC 7606 §5.3), the parser
//! records a [`BgpValidationWarning::MalformedNlri`] and returns the UPDATE
//! with empty prefix lists. The caller decides whether to also withdraw
//! previously-installed routes that may have been in the malformed NLRI.
//!
//! Run with:
//! ```sh
//! cargo run --example treat_as_withdrawal --features="local"
//! ```

use bgpkit_parser::error::BgpValidationWarning;
use bgpkit_parser::models::{Bgp4MpEnum, BgpMessage, MrtMessage};
use bgpkit_parser::BgpkitParser;

fn main() {
    // Use a real MRT updates file. Replace with a URL to a file containing
    // malformed messages, or use a known-good file to see the "no warnings"
    // path. For a real incident investigation, point this at the collector
    // and time window where session resets were observed.
    let url = "https://data.ris.ripe.net/rrc00/2026.07/updates.20260727.0000.gz";

    println!("Scanning {} for RFC 7606 validation issues...\n", url);

    let parser = match BgpkitParser::new(url) {
        Ok(p) => p.disable_warnings(),
        Err(e) => {
            eprintln!("Failed to create parser: {}", e);
            return;
        }
    };

    let mut total_records = 0u64;
    let mut records_with_warnings = 0u64;
    let mut treat_as_withdrawal_count = 0u64;
    let mut attribute_discard_count = 0u64;

    for result in parser.into_fallible_record_iter() {
        match result {
            Ok(record) => {
                total_records += 1;

                // Extract validation warnings from the BGP UPDATE message
                let warnings = extract_validation_warnings(&record);

                if warnings.is_empty() {
                    continue;
                }

                records_with_warnings += 1;

                // Classify each warning by RFC 7606 error-handling category
                let has_taw = warnings
                    .iter()
                    .any(|w| matches!(w, BgpValidationWarning::MalformedNlri { .. }));

                let has_attr_discard = warnings.iter().any(|w| {
                    matches!(
                        w,
                        BgpValidationWarning::PartialAttributeError { .. }
                            | BgpValidationWarning::OptionalAttributeError { .. }
                    )
                });

                if has_taw {
                    treat_as_withdrawal_count += 1;
                    println!("--- TREAT-AS-WITHDRAWAL (record #{}) ---", total_records);

                    for w in warnings {
                        if let BgpValidationWarning::MalformedNlri {
                            nlri_type,
                            reason,
                            raw_bytes,
                        } = w
                        {
                            println!("  Malformed NLRI ({}): {}", nlri_type, reason);
                            println!(
                                "  Raw NLRI bytes ({} bytes): {:02x?}",
                                raw_bytes.len(),
                                &raw_bytes[..raw_bytes.len().min(32)]
                            );
                            println!("  → All routes in this UPDATE treated as withdrawn");
                        }
                    }
                }

                if has_attr_discard {
                    attribute_discard_count += 1;
                    if !has_taw {
                        println!("--- ATTRIBUTE DISCARD (record #{}) ---", total_records);
                    }
                    for w in warnings {
                        match w {
                            BgpValidationWarning::PartialAttributeError { attr_type, reason } => {
                                println!("  Partial attribute error {:?}: {}", attr_type, reason);
                                println!("  → Attribute discarded, route retained");
                            }
                            BgpValidationWarning::OptionalAttributeError { attr_type, reason } => {
                                println!("  Optional attribute error {:?}: {}", attr_type, reason);
                                println!("  → Attribute discarded, route retained");
                            }
                            _ => {}
                        }
                    }
                }

                // Report structural warnings (missing mandatory, malformed AS_PATH, etc.)
                for w in warnings {
                    if !matches!(
                        w,
                        BgpValidationWarning::MalformedNlri { .. }
                            | BgpValidationWarning::PartialAttributeError { .. }
                            | BgpValidationWarning::OptionalAttributeError { .. }
                    ) {
                        println!("  Other validation warning: {}", w);
                    }
                }
            }
            Err(e) => {
                total_records += 1;
                // Parse error: the record could not be parsed at all.
                // Raw bytes may be available for forensic analysis.
                if let Some(bytes) = &e.bytes {
                    eprintln!(
                        "Record #{}: FATAL parse error: {} ({} raw bytes preserved)",
                        total_records,
                        e,
                        bytes.len()
                    );
                } else {
                    eprintln!("Record #{}: FATAL parse error: {}", total_records, e);
                }
            }
        }
    }

    println!("\n=== Summary ===");
    println!("Total records scanned: {}", total_records);
    println!(
        "Records with validation warnings: {}",
        records_with_warnings
    );
    println!(
        "  - Treat-as-withdrawal (malformed NLRI): {}",
        treat_as_withdrawal_count
    );
    println!(
        "  - Attribute discard (bad optional attr): {}",
        attribute_discard_count
    );
}

/// Extract validation warnings from an MrtRecord by drilling into the
/// BGP UPDATE message's attributes.
fn extract_validation_warnings(
    record: &bgpkit_parser::models::MrtRecord,
) -> &[BgpValidationWarning] {
    let bgp_message = match &record.message {
        MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(msg)) => &msg.bgp_message,
        _ => return &[],
    };

    let update = match bgp_message {
        BgpMessage::Update(u) => u,
        _ => return &[],
    };

    update.attributes.validation_warnings()
}
