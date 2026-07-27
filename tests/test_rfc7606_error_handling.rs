//! Tests for RFC 7606 revised error handling: non-fatal NLRI parsing,
//! raw byte preservation on parse failures, and treat-as-withdrawal support.
//!
//! These tests exercise the parser's ability to return partial UPDATE
//! messages with [`BgpValidationWarning`]s instead of failing hard on
//! malformed NLRI data.

use bgpkit_parser::error::{BgpValidationWarning, ParserError, ParserErrorWithBytes};
use bgpkit_parser::models::*;
use bgpkit_parser::parser::bgp::messages::parse_bgp_update_message;
use bgpkit_parser::parser::mrt::mrt_record::parse_mrt_record;
use bytes::Bytes;
use std::io::Cursor;

/// Build a minimal valid BGP UPDATE message body (the bytes after the
/// 16-byte marker + 2-byte length + 1-byte type of the BGP message header).
///
/// Layout:
///   u16 withdrawn_length | withdrawn_bytes | u16 attr_length | attr_bytes | nlri
fn build_update_body(withdrawn: &[u8], attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
    msg.extend_from_slice(withdrawn);
    msg.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    msg.extend_from_slice(attrs);
    msg.extend_from_slice(nlri);
    msg
}

/// Build minimal attributes: ORIGIN(IGP) + AS_PATH(empty) + NEXT_HOP
fn build_valid_attrs() -> Vec<u8> {
    let mut attrs = Vec::new();
    // ORIGIN = IGP
    attrs.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
    // AS_PATH = empty
    attrs.extend_from_slice(&[0x40, 0x02, 0x00]);
    // NEXT_HOP = 1.2.3.4
    attrs.extend_from_slice(&[0x40, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04]);
    attrs
}

/// A valid NLRI encoding 10.0.0.0/24: prefix_len=24, prefix=0x0A000000 (3 bytes)
fn valid_nlri_prefix() -> Vec<u8> {
    vec![0x18, 0x0A, 0x00, 0x00]
}

/// Malformed NLRI: 2 bytes starting with prefix_len=200 (0xC8), impossible for IPv4.
/// Must be >= 2 bytes to avoid the 1-byte guard in read_nlri.
fn malformed_nlri() -> Vec<u8> {
    vec![0xC8, 0x01]
}

// ========================================================================
// Test 1: Malformed announced NLRI produces a warning, not an error
// ========================================================================

#[test]
fn test_malformed_announced_nlri_produces_warning_not_error() {
    let asn_len = AsnLength::Bits32;
    let body = build_update_body(&[], &build_valid_attrs(), &malformed_nlri());
    let result = parse_bgp_update_message(Bytes::from(body), false, &asn_len);

    let update = result.expect("malformed NLRI should not be fatal");
    assert!(
        update.announced_prefixes.is_empty(),
        "prefixes should be empty"
    );
    assert!(
        update.attributes.has_validation_warnings(),
        "should have validation warnings"
    );

    let warnings = update.attributes.validation_warnings();
    assert!(
        warnings.iter().any(|w| matches!(
            w,
            BgpValidationWarning::MalformedNlri {
                nlri_type: "announced",
                ..
            }
        )),
        "expected MalformedNlri warning for announced NLRI, got: {:?}",
        warnings
    );
}

// ========================================================================
// Test 2: Malformed NLRI preserves raw bytes in the warning
// ========================================================================

#[test]
fn test_malformed_announced_nlri_preserves_raw_bytes_in_warning() {
    let asn_len = AsnLength::Bits32;
    let nlri = malformed_nlri();
    let body = build_update_body(&[], &build_valid_attrs(), &nlri);
    let update = parse_bgp_update_message(Bytes::from(body), false, &asn_len).unwrap();

    let warnings = update.attributes.validation_warnings();
    let nlri_warning = warnings.iter().find_map(|w| match w {
        BgpValidationWarning::MalformedNlri {
            nlri_type: "announced",
            raw_bytes,
            ..
        } => Some(raw_bytes),
        _ => None,
    });
    assert_eq!(
        nlri_warning,
        Some(&nlri),
        "raw NLRI bytes should be preserved"
    );
}

// ========================================================================
// Test 3: Malformed withdrawn NLRI produces a warning, not an error
// ========================================================================

#[test]
fn test_malformed_withdrawn_nlri_produces_warning_not_error() {
    let asn_len = AsnLength::Bits32;
    let body = build_update_body(&malformed_nlri(), &build_valid_attrs(), &[]);
    let result = parse_bgp_update_message(Bytes::from(body), false, &asn_len);

    let update = result.expect("malformed withdrawn NLRI should not be fatal");
    assert!(
        update.withdrawn_prefixes.is_empty(),
        "withdrawn prefixes should be empty"
    );

    let warnings = update.attributes.validation_warnings();
    assert!(
        warnings.iter().any(|w| matches!(
            w,
            BgpValidationWarning::MalformedNlri {
                nlri_type: "withdrawn",
                ..
            }
        )),
        "expected MalformedNlri warning for withdrawn NLRI, got: {:?}",
        warnings
    );
}

// ========================================================================
// Test 4: Attributes survive NLRI parse failure (partial recovery)
// ========================================================================

#[test]
fn test_attributes_survive_nlri_parse_failure() {
    let asn_len = AsnLength::Bits32;
    let body = build_update_body(&[], &build_valid_attrs(), &malformed_nlri());
    let update = parse_bgp_update_message(Bytes::from(body), false, &asn_len).unwrap();

    assert!(update.attributes.has_attr(AttrType::ORIGIN));
    assert!(update.attributes.has_attr(AttrType::AS_PATH));
    assert!(update.attributes.has_attr(AttrType::NEXT_HOP));
}

#[test]
fn test_valid_withdrawn_survives_malformed_announced_nlri() {
    let asn_len = AsnLength::Bits32;
    let body = build_update_body(
        &valid_nlri_prefix(),
        &build_valid_attrs(),
        &malformed_nlri(),
    );
    let update = parse_bgp_update_message(Bytes::from(body), false, &asn_len).unwrap();

    // Withdrawn prefix should survive
    assert_eq!(update.withdrawn_prefixes.len(), 1);
    // Announced should be empty (recovered as partial)
    assert!(
        update.announced_prefixes.is_empty(),
        "malformed announced NLRI should produce no prefixes"
    );
    assert!(
        update.attributes.has_validation_warnings(),
        "should have validation warnings for the malformed announced NLRI"
    );
}

// ========================================================================
// Test 5: Normal valid UPDATE still parses without warnings
// ========================================================================

#[test]
fn test_valid_update_still_parses_clean() {
    let asn_len = AsnLength::Bits32;
    let body = build_update_body(&[], &build_valid_attrs(), &valid_nlri_prefix());
    let update = parse_bgp_update_message(Bytes::from(body), false, &asn_len).unwrap();

    assert_eq!(update.announced_prefixes.len(), 1);
    assert!(
        !update.attributes.has_validation_warnings(),
        "valid UPDATE should have no validation warnings"
    );
}

// ========================================================================
// Test 6: Attribute framing errors are still fatal
// ========================================================================

#[test]
fn test_attribute_length_exceeding_available_bytes_is_fatal() {
    let asn_len = AsnLength::Bits32;

    let mut msg = Vec::new();
    msg.extend_from_slice(&0x0000u16.to_be_bytes()); // withdrawn length = 0
    msg.extend_from_slice(&0x03E8u16.to_be_bytes()); // attr length = 1000
    msg.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]); // only 4 bytes

    let result = parse_bgp_update_message(Bytes::from(msg), false, &asn_len);
    assert!(result.is_err(), "truncated attribute data should be fatal");
}

// ========================================================================
// Test 7: Raw bytes preserved on MRT body-parse failure
// ========================================================================

#[test]
fn test_parse_mrt_record_preserves_raw_bytes_on_failure() {
    // Build an MRT record with entry_type=12 (TABLE_DUMP, a valid type),
    // but a body that will fail to parse (truncated/invalid for that type).
    let mut data = Vec::new();

    // MRT common header: timestamp(4) + type(2) + subtype(2) + length(4)
    data.extend_from_slice(&0x00000000u32.to_be_bytes()); // timestamp
    data.extend_from_slice(&0x000Cu16.to_be_bytes()); // entry type = 12 (TABLE_DUMP)
    data.extend_from_slice(&0x0000u16.to_be_bytes()); // subtype
    data.extend_from_slice(&0x00000004u32.to_be_bytes()); // length = 4
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // invalid body

    let mut cursor = Cursor::new(data);
    let result = parse_mrt_record(&mut cursor);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.bytes.is_some(),
        "raw bytes should be preserved on parse failure"
    );
    let bytes = err.bytes.unwrap();
    assert!(!bytes.is_empty(), "preserved bytes should not be empty");
}

// ========================================================================
// Test 8: Malformed OTC attribute scenario (Qrator blog incident)
//
// An OTC attribute (type 35) with the Extended Length flag incorrectly set.
// The parser reads a 2-byte length = 0x0400 = 1024, but only 4 bytes of
// value follow. This mismatch is caught by the attribute error handler.
// ========================================================================

#[test]
fn test_malformed_otc_attribute_extended_length_mismatch() {
    let asn_len = AsnLength::Bits32;

    let mut attrs = build_valid_attrs();
    attrs.extend_from_slice(&[
        0xF0, // flags: Optional | Transitive | Partial | Extended Length
        0x23, // type: 35 = OTC
        0x04, 0x00, // Extended length: 0x0400 = 1024 bytes claimed
    ]);
    attrs.extend_from_slice(&0x0000FE4Cu32.to_be_bytes()); // OTC value = 65100

    let body = build_update_body(&[], &attrs, &valid_nlri_prefix());
    let result = parse_bgp_update_message(Bytes::from(body), false, &asn_len);

    match result {
        Ok(update) => {
            // NLRI should still be present (attribute error does not destroy NLRI)
            assert_eq!(
                update.announced_prefixes.len(),
                1,
                "NLRI should survive bad optional attribute"
            );
            assert!(
                update.attributes.has_validation_warnings(),
                "expected validation warnings for malformed OTC attribute"
            );
        }
        Err(e) => panic!("malformed OTC attribute should not be fatal: {}", e),
    }
}

// ========================================================================
// Test 9: Treat-as-withdrawal emulation pattern
//
// Demonstrates the caller pattern for detecting malformed NLRI and treating
// the affected routes as withdrawn per RFC 7606 §5.3.
// ========================================================================

#[test]
fn test_treat_as_withdrawal_emulation() {
    let asn_len = AsnLength::Bits32;

    // Build an UPDATE with valid attributes and malformed announced NLRI
    let bad_nlri = malformed_nlri();
    let bad_body = build_update_body(&[], &build_valid_attrs(), &bad_nlri);

    let bad_update = parse_bgp_update_message(Bytes::from(bad_body), false, &asn_len).unwrap();

    // RFC 7606 treat-as-withdrawal: when NLRI is malformed, all routes in
    // the UPDATE should be treated as withdrawn.
    let needs_taw = bad_update
        .attributes
        .validation_warnings()
        .iter()
        .any(|w| matches!(w, BgpValidationWarning::MalformedNlri { .. }));

    assert!(
        needs_taw,
        "malformed NLRI should be detectable via warnings"
    );

    // Caller actions:
    // 1. Do not install any routes (announced_prefixes is empty)
    assert!(bad_update.announced_prefixes.is_empty());

    // 2. Raw bytes are available for forensic extraction
    let raw_nlri = bad_update
        .attributes
        .validation_warnings()
        .iter()
        .find_map(|w| match w {
            BgpValidationWarning::MalformedNlri { raw_bytes, .. } => Some(raw_bytes),
            _ => None,
        });
    assert_eq!(
        raw_nlri,
        Some(&bad_nlri),
        "raw NLRI bytes should be available for extraction"
    );
}

// ========================================================================
// Test 10: BgpValidationWarning::MalformedNlri Display formatting
// ========================================================================

#[test]
fn test_malformed_nlri_warning_display() {
    let warning = BgpValidationWarning::MalformedNlri {
        nlri_type: "announced",
        reason: "invalid prefix length".to_string(),
        raw_bytes: vec![0xC8, 0x01],
    };
    let display = format!("{}", warning);
    assert!(display.contains("announced"));
    assert!(display.contains("invalid prefix length"));
}

// ========================================================================
// Test 11: ParserErrorWithBytes Display formatting
// ========================================================================

#[test]
fn test_parser_error_with_bytes_display() {
    let err = ParserErrorWithBytes {
        error: ParserError::ParseError("test error".to_string()),
        bytes: Some(vec![0x01, 0x02]),
    };
    let display = format!("{}", err);
    assert!(display.contains("test error"));
}

// ========================================================================
// Test 12: 1-byte NLRI field is now treated as malformed (was silently
//          skipped before — Copilot review comment on PR #309)
// ========================================================================

#[test]
fn test_one_byte_nlri_produces_warning_not_silent_skip() {
    let asn_len = AsnLength::Bits32;

    // A 1-byte NLRI field in the announced section — previously this was
    // silently skipped (Ok(vec![])), now it produces a MalformedNlri warning.
    let one_byte_nlri = vec![0xFF];
    let body = build_update_body(&[], &build_valid_attrs(), &one_byte_nlri);
    let update = parse_bgp_update_message(Bytes::from(body), false, &asn_len).unwrap();

    assert!(update.announced_prefixes.is_empty());
    assert!(
        update.attributes.has_validation_warnings(),
        "1-byte NLRI should produce a MalformedNlri warning"
    );
    assert!(update
        .attributes
        .validation_warnings()
        .iter()
        .any(|w| matches!(
            w,
            BgpValidationWarning::MalformedNlri {
                nlri_type: "announced",
                ..
            }
        )));
}
