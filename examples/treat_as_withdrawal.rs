//! # RFC 7606 Treat-as-Withdrawal and Junos-style Error Classification
//!
//! This example demonstrates how to detect malformed BGP UPDATE messages and
//! apply RFC 7606 error-handling semantics using bgpkit-parser's validation
//! warning system. It classifies messages into the three severity tiers used
//! by Junos OS `bgp-error-tolerance`, applying the "most severe wins" rule.
//!
//! ## Three-tier error handling (Junos model)
//!
//! 1. **Notification** (session reset): the most severe. Triggered by
//!    malformed MP_REACH/MP_UNREACH, unparseable NLRI, or attribute
//!    length/value mismatch. The BGP session is reset.
//!
//! 2. **Treat-as-withdrawal**: all routes in the UPDATE are withdrawn.
//!    Triggered by malformed well-known mandatory attributes (ORIGIN,
//!    AS_PATH, NEXT_HOP), plus LOCAL_PREF, MED, communities, and others.
//!
//! 3. **Attribute discard**: the bad attribute is dropped, route retained.
//!    Triggered by malformed optional transitive attributes (AS4_PATH,
//!    AGGREGATOR, AS4_AGGREGATOR, ATOMIC_AGGREGATE) and duplicate attributes.
//!
//! When multiple attributes are malformed in one UPDATE, the **most severe**
//! approach triggered by any single attribute is applied to the entire message.
//!
//! ## Important caveats
//!
//! - bgpkit-parser parses MRT data (offline captures), not live sessions. It
//!   provides the detection signals; this example applies the classification
//!   policy that a router like Junos would apply.
//! - bgpkit-parser always recovers what it can: framing errors are fatal, but
//!   bad NLRI and bad attributes produce warnings + partial data. A real
//!   router additionally *acts* on the classification (hide route, reset
//!   session, etc.).
//!
//! Run with:
//! ```sh
//! cargo run --example treat_as_withdrawal --features="local"
//! ```

use bgpkit_parser::error::BgpValidationWarning;
use bgpkit_parser::models::{AttrType, Bgp4MpEnum, BgpMessage, MrtMessage};
use bgpkit_parser::BgpkitParser;

/// Severity tiers in decreasing order of severity (Junos model).
/// When multiple attributes are malformed, the most severe tier wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ErrorTier {
    /// Session reset (fatal). MP_REACH/MP_UNREACH malformed, unparseable NLRI.
    Notification,
    /// Withdraw all routes in the UPDATE. Bad mandatory + some optional attrs.
    TreatAsWithdrawal,
    /// Drop the bad attribute, keep the route. Bad optional transitive attrs.
    AttributeDiscard,
}

/// Classify a single validation warning into a severity tier and human-readable
/// attribute name, following the Junos per-attribute mapping.
fn classify_warning(w: &BgpValidationWarning) -> Option<(ErrorTier, &'static str)> {
    match w {
        // --- Notification level ---
        // Malformed NLRI: Junos treats unparseable NLRI as notification-level.
        BgpValidationWarning::MalformedNlri { .. } => Some((ErrorTier::Notification, "NLRI")),
        // Malformed attribute list (well-known mandatory parse failure):
        // Junos treats these as notification-level (can't parse the UPDATE).
        BgpValidationWarning::MalformedAttributeList { .. } => {
            Some((ErrorTier::Notification, "attribute list"))
        }
        // Missing well-known mandatory: if ORIGIN, AS_PATH, or NEXT_HOP is
        // missing, Junos uses treat-as-withdrawal.
        BgpValidationWarning::MissingWellKnownAttribute { attr_type } => {
            Some((ErrorTier::TreatAsWithdrawal, attr_label(*attr_type)))
        }
        // --- Treat-as-withdrawal level ---
        BgpValidationWarning::InvalidOriginAttribute { .. } => {
            Some((ErrorTier::TreatAsWithdrawal, "ORIGIN"))
        }
        BgpValidationWarning::MalformedAsPath { .. } => {
            Some((ErrorTier::TreatAsWithdrawal, "AS_PATH"))
        }
        BgpValidationWarning::InvalidNextHopAttribute { .. } => {
            Some((ErrorTier::TreatAsWithdrawal, "NEXT_HOP"))
        }
        // Partial attribute errors for well-known mandatory attrs → TAW
        BgpValidationWarning::PartialAttributeError { attr_type, .. } => {
            let tier = if is_taw_attribute(*attr_type) {
                ErrorTier::TreatAsWithdrawal
            } else {
                ErrorTier::AttributeDiscard
            };
            Some((tier, attr_label(*attr_type)))
        }
        BgpValidationWarning::OptionalAttributeError { attr_type, .. } => {
            let tier = if is_taw_attribute(*attr_type) {
                ErrorTier::TreatAsWithdrawal
            } else {
                ErrorTier::AttributeDiscard
            };
            Some((tier, attr_label(*attr_type)))
        }
        // --- Attribute discard level ---
        // These attributes get "attribute discard" treatment in Junos
        BgpValidationWarning::AttributeFlagsError { attr_type, .. } => {
            let tier = if is_taw_attribute(*attr_type) {
                ErrorTier::TreatAsWithdrawal
            } else {
                ErrorTier::AttributeDiscard
            };
            Some((tier, attr_label(*attr_type)))
        }
        BgpValidationWarning::AttributeLengthError { attr_type, .. } => {
            let tier = if is_taw_attribute(*attr_type) {
                ErrorTier::TreatAsWithdrawal
            } else {
                ErrorTier::AttributeDiscard
            };
            Some((tier, attr_label(*attr_type)))
        }
        BgpValidationWarning::DuplicateAttribute { attr_type } => {
            // Junos: duplicate attributes → discard all but the first
            Some((ErrorTier::AttributeDiscard, attr_label(*attr_type)))
        }
        // Structural issues
        BgpValidationWarning::InvalidNetworkField { .. } => {
            Some((ErrorTier::TreatAsWithdrawal, "network field"))
        }
        BgpValidationWarning::UnrecognizedWellKnownAttribute { .. } => {
            Some((ErrorTier::Notification, "unrecognized well-known"))
        } // Partial attribute for optional transitive → attribute discard
        _ => None,
    }
}

/// Attributes that trigger treat-as-withdrawal in Junos when malformed.
/// Everything else with a validation warning defaults to attribute discard.
fn is_taw_attribute(attr_type: AttrType) -> bool {
    matches!(
        attr_type,
        AttrType::ORIGIN
            | AttrType::AS_PATH
            | AttrType::NEXT_HOP
            | AttrType::MULTI_EXIT_DISCRIMINATOR
            | AttrType::LOCAL_PREFERENCE
            | AttrType::COMMUNITIES
            | AttrType::EXTENDED_COMMUNITIES
            | AttrType::ORIGINATOR_ID
            | AttrType::CLUSTER_LIST
            | AttrType::AIGP
            | AttrType::PMSI_TUNNEL
            | AttrType::ATTR_SET
    )
}

/// Human-readable attribute name for display.
fn attr_label(attr_type: AttrType) -> &'static str {
    match attr_type {
        AttrType::ORIGIN => "ORIGIN",
        AttrType::AS_PATH => "AS_PATH",
        AttrType::NEXT_HOP => "NEXT_HOP",
        AttrType::MULTI_EXIT_DISCRIMINATOR => "MULTI_EXIT_DISC",
        AttrType::LOCAL_PREFERENCE => "LOCAL_PREF",
        AttrType::ATOMIC_AGGREGATE => "ATOMIC_AGGREGATE",
        AttrType::AGGREGATOR => "AGGREGATOR",
        AttrType::COMMUNITIES => "COMMUNITIES",
        AttrType::ORIGINATOR_ID => "ORIGINATOR_ID",
        AttrType::CLUSTER_LIST => "CLUSTER_LIST",
        AttrType::MP_REACHABLE_NLRI => "MP_REACH_NLRI",
        AttrType::MP_UNREACHABLE_NLRI => "MP_UNREACH_NLRI",
        AttrType::EXTENDED_COMMUNITIES => "EXT_COMMUNITIES",
        AttrType::AS4_PATH => "AS4_PATH",
        AttrType::AS4_AGGREGATOR => "AS4_AGGREGATOR",
        AttrType::AIGP => "AIGP",
        AttrType::PMSI_TUNNEL => "PMSI_TUNNEL",
        AttrType::ATTR_SET => "ATTR_SET",
        AttrType::ONLY_TO_CUSTOMER => "OTC",
        _ => "UNKNOWN",
    }
}

fn tier_label(tier: ErrorTier) -> &'static str {
    match tier {
        ErrorTier::Notification => "NOTIFICATION (session reset)",
        ErrorTier::TreatAsWithdrawal => "TREAT-AS-WITHDRAWAL",
        ErrorTier::AttributeDiscard => "ATTRIBUTE DISCARD",
    }
}

fn main() {
    // Point this at a collector and time window where malformed messages
    // are suspected. For the Qrator OTC incident, look for UPDATEs from
    // the affected ASes during the incident window.
    let url = "https://data.ris.ripe.net/rrc00/2026.07/updates.20260727.0000.gz";

    println!("Scanning {} for BGP error-handling issues...\n", url);

    let parser = match BgpkitParser::new(url) {
        Ok(p) => p.disable_warnings(),
        Err(e) => {
            eprintln!("Failed to create parser: {}", e);
            return;
        }
    };

    let mut total_records = 0u64;
    let mut records_with_issues = 0u64;
    let mut by_tier = [0u64; 3]; // [notification, taw, attr_discard]

    for result in parser.into_fallible_record_iter() {
        match result {
            Ok(record) => {
                total_records += 1;

                let warnings = extract_validation_warnings(&record);
                if warnings.is_empty() {
                    continue;
                }
                records_with_issues += 1;

                // Classify each warning and find the most severe tier
                // (Junos "most severe wins" rule)
                let findings: Vec<(ErrorTier, &str, &BgpValidationWarning)> = warnings
                    .iter()
                    .filter_map(|w| classify_warning(w).map(|(t, name)| (t, name, w)))
                    .collect();

                if findings.is_empty() {
                    continue;
                }

                // Most severe tier for this record (min ordinal = most severe)
                let overall_tier = findings.iter().map(|(t, _, _)| *t).min().unwrap();
                by_tier[overall_tier as usize] += 1;

                println!(
                    "--- {} (record #{}) ---",
                    tier_label(overall_tier),
                    total_records
                );

                for (tier, name, warning) in &findings {
                    let marker = if *tier == overall_tier { "→" } else { " " };
                    let action = match tier {
                        ErrorTier::Notification => "session reset",
                        ErrorTier::TreatAsWithdrawal => "routes withdrawn",
                        ErrorTier::AttributeDiscard => "attribute discarded",
                    };
                    println!("  {marker} [{name}] {warning}");
                    println!("    action: {action}");

                    // Show raw NLRI bytes if available
                    if let BgpValidationWarning::MalformedNlri { raw_bytes, .. } = warning {
                        let display_len = raw_bytes.len().min(32);
                        println!(
                            "    raw NLRI ({} bytes): {:02x?}",
                            display_len,
                            &raw_bytes[..display_len]
                        );
                    }
                }
                println!();
            }
            Err(e) => {
                total_records += 1;
                by_tier[ErrorTier::Notification as usize] += 1;
                if let Some(bytes) = &e.bytes {
                    eprintln!(
                        "Record #{}: FATAL ({} raw bytes preserved): {}",
                        total_records,
                        bytes.len(),
                        e
                    );
                } else {
                    eprintln!("Record #{}: FATAL: {}", total_records, e);
                }
            }
        }
    }

    println!("=== Summary ===");
    println!("Total records scanned: {}", total_records);
    println!("Records with issues: {}", records_with_issues);
    println!(
        "  Notification (session reset): {}",
        by_tier[ErrorTier::Notification as usize]
    );
    println!(
        "  Treat-as-withdrawal:          {}",
        by_tier[ErrorTier::TreatAsWithdrawal as usize]
    );
    println!(
        "  Attribute discard:            {}",
        by_tier[ErrorTier::AttributeDiscard as usize]
    );
}

/// Extract validation warnings from an MrtRecord.
fn extract_validation_warnings(
    record: &bgpkit_parser::models::MrtRecord,
) -> &[BgpValidationWarning] {
    let bgp_message = match &record.message {
        MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(msg)) => &msg.bgp_message,
        _ => return &[],
    };

    match bgp_message {
        BgpMessage::Update(u) => u.attributes.validation_warnings(),
        _ => &[],
    }
}
