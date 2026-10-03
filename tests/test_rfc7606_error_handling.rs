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
    // RFC 7606 §5.3: unparseable NLRI leave nothing to withdraw, so the
    // approach is a session reset, which also withdraws the routes
    assert!(bad_update.is_treat_as_withdraw());
    assert_eq!(
        bad_update.error_handling_approach(),
        Some(ErrorHandlingApproach::SessionReset)
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
// Test 12: 1-byte NLRI with invalid prefix length is treated as malformed.
//          A 1-byte NLRI with value 0x00 (default route /0) is valid and
//          must NOT be flagged. (Copilot review comment on PR #309)
// ========================================================================

#[test]
fn test_one_byte_nlri_invalid_prefix_produces_warning() {
    let asn_len = AsnLength::Bits32;

    // A 1-byte NLRI with value 0xFF (prefix length 255) is invalid for IPv4.
    let invalid_one_byte = vec![0xFF];
    let body = build_update_body(&[], &build_valid_attrs(), &invalid_one_byte);
    let update = parse_bgp_update_message(Bytes::from(body), false, &asn_len).unwrap();

    assert!(update.announced_prefixes.is_empty());
    assert!(
        update.attributes.has_validation_warnings(),
        "1-byte NLRI with invalid prefix length should produce a warning"
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

// ========================================================================
// Test 13: 1-byte NLRI encoding default route (0.0.0.0/0) is valid
// ========================================================================

#[test]
fn test_one_byte_nlri_default_route_is_valid() {
    let asn_len = AsnLength::Bits32;

    // A 1-byte NLRI with value 0x00 encodes the default route (prefix
    // length 0, no prefix octets). This is valid and must parse cleanly.
    let default_route_nlri = vec![0x00];
    let body = build_update_body(&[], &build_valid_attrs(), &default_route_nlri);
    let update = parse_bgp_update_message(Bytes::from(body), false, &asn_len).unwrap();

    assert_eq!(
        update.announced_prefixes.len(),
        1,
        "default route 0.0.0.0/0 should be parsed"
    );
    assert!(
        !update.attributes.has_validation_warnings(),
        "valid default route NLRI must not produce warnings"
    );
}

// ========================================================================
// Test 14: Malformed announced NLRI still triggers mandatory-attr validation
//         (Copilot review: is_announcement must reflect wire-level NLRI
//         presence, not parse success)
// ========================================================================

#[test]
fn test_malformed_nlri_still_triggers_mandatory_attr_check() {
    let asn_len = AsnLength::Bits32;

    // Build an UPDATE with malformed announced NLRI but NO mandatory
    // attributes (no ORIGIN, no AS_PATH, no NEXT_HOP). The mandatory-attr
    // check should still fire because the UPDATE clearly intended to
    // announce routes (NLRI bytes were present on the wire).
    let malformed_nlri = vec![0xC8, 0x01];
    let body = build_update_body(&[], &[], &malformed_nlri);
    let update = parse_bgp_update_message(Bytes::from(body), false, &asn_len).unwrap();

    let warnings = update.attributes.validation_warnings();

    // Should have MalformedNlri
    assert!(
        warnings.iter().any(|w| matches!(
            w,
            BgpValidationWarning::MalformedNlri {
                nlri_type: "announced",
                ..
            }
        )),
        "expected MalformedNlri warning"
    );

    // Should ALSO have missing mandatory attribute warnings — the UPDATE
    // carried NLRI bytes (intent to announce) but lacked ORIGIN/AS_PATH/NEXT_HOP
    assert!(
        warnings.iter().any(|w| matches!(
            w,
            BgpValidationWarning::MissingWellKnownAttribute {
                attr_type: AttrType::ORIGIN
            }
        )),
        "expected MissingWellKnownAttribute(ORIGIN) — mandatory check must fire even with malformed NLRI, got: {:?}",
        warnings
    );
    assert!(
        warnings.iter().any(|w| matches!(
            w,
            BgpValidationWarning::MissingWellKnownAttribute {
                attr_type: AttrType::AS_PATH
            }
        )),
        "expected MissingWellKnownAttribute(AS_PATH)"
    );
    assert!(
        warnings.iter().any(|w| matches!(
            w,
            BgpValidationWarning::MissingWellKnownAttribute {
                attr_type: AttrType::NEXT_HOP
            }
        )),
        "expected MissingWellKnownAttribute(NEXT_HOP)"
    );
}

// ========================================================================
// RFC 7606 error handling applied to elements
//
// These tests wrap an UPDATE body in a BGP4MP_MESSAGE_AS4 MRT record and
// parse it with `BgpkitParser`, once as encoded and once with
// `enable_rfc7606_error_handling()`.
// ========================================================================

/// Wrap an UPDATE body in a BGP message and a BGP4MP_MESSAGE_AS4 MRT record
/// from peer AS 65000 at 192.0.2.1.
fn bgp4mp_update_record(update_body: &[u8]) -> Vec<u8> {
    let mut bgp = vec![0xff; 16];
    bgp.extend_from_slice(&((19 + update_body.len()) as u16).to_be_bytes());
    bgp.push(2); // UPDATE
    bgp.extend_from_slice(update_body);

    let mut body = Vec::new();
    body.extend_from_slice(&65000u32.to_be_bytes()); // peer AS
    body.extend_from_slice(&65001u32.to_be_bytes()); // local AS
    body.extend_from_slice(&0u16.to_be_bytes()); // interface index
    body.extend_from_slice(&1u16.to_be_bytes()); // AFI IPv4
    body.extend_from_slice(&[192, 0, 2, 1]); // peer IP
    body.extend_from_slice(&[192, 0, 2, 2]); // local IP
    body.extend_from_slice(&bgp);

    let mut record = Vec::new();
    record.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    record.extend_from_slice(&16u16.to_be_bytes()); // BGP4MP
    record.extend_from_slice(&4u16.to_be_bytes()); // BGP4MP_MESSAGE_AS4
    record.extend_from_slice(&(body.len() as u32).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

fn elems_of(update_body: &[u8], rfc7606: bool) -> Vec<BgpElem> {
    let parser =
        bgpkit_parser::BgpkitParser::from_reader(Cursor::new(bgp4mp_update_record(update_body)));
    let parser = if rfc7606 {
        parser.enable_rfc7606_error_handling()
    } else {
        parser
    };
    parser.into_elem_iter().collect()
}

/// ORIGIN, empty AS_PATH and NEXT_HOP, with ORIGIN set to `origin`.
fn attrs_with_origin(origin: u8) -> Vec<u8> {
    let mut attrs = build_valid_attrs();
    attrs[3] = origin;
    attrs
}

/// 10.0.0.0/24 and 10.0.1.0/24
fn two_prefixes() -> Vec<u8> {
    vec![0x18, 10, 0, 0, 0x18, 10, 0, 1]
}

/// IPv6 unicast MP_REACH_NLRI announcing 2001:db8::/32 via 2001:db8::1.
fn ipv6_mp_reach() -> Vec<u8> {
    let mut value = vec![0x00, 0x02, 0x01, 16];
    value.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    value.push(0); // reserved
    value.extend_from_slice(&[32, 0x20, 0x01, 0x0d, 0xb8]);
    let mut attr = vec![0x80, 0x0e, value.len() as u8];
    attr.extend_from_slice(&value);
    attr
}

#[test]
fn test_treat_as_withdraw_mode_withdraws_announced_prefixes() {
    let body = build_update_body(&[], &attrs_with_origin(3), &two_prefixes());

    // as encoded: the announcements are kept and carry no verdict
    let elems = elems_of(&body, false);
    assert_eq!(elems.len(), 2);
    assert!(elems
        .iter()
        .all(|e| e.elem_type == ElemType::ANNOUNCE && e.error_handling.is_none()));

    // RFC 7606 §7.1: an undefined ORIGIN value is treat-as-withdraw
    let elems = elems_of(&body, true);
    assert_eq!(elems.len(), 2);
    for elem in &elems {
        assert_eq!(elem.elem_type, ElemType::WITHDRAW);
        assert_eq!(
            elem.error_handling,
            Some(ErrorHandlingApproach::TreatAsWithdraw)
        );
        assert_eq!(elem.as_path, None);
        assert_eq!(elem.next_hop, None);
        assert_eq!(elem.unknown, None);
    }
}

#[test]
fn test_treat_as_withdraw_mode_covers_mp_reach_prefixes() {
    let mut attrs = vec![0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x00];
    attrs.extend_from_slice(&ipv6_mp_reach());
    // COMMUNITIES of 6 bytes: not a multiple of 4 (RFC 7606 §7.8)
    attrs.extend_from_slice(&[0xc0, 0x08, 0x06, 0, 1, 0, 1, 0, 2]);
    let body = build_update_body(&[], &attrs, &[]);

    let elems = elems_of(&body, true);
    assert_eq!(elems.len(), 1);
    assert_eq!(elems[0].prefix.to_string(), "2001:db8::/32");
    assert_eq!(elems[0].elem_type, ElemType::WITHDRAW);
    assert_eq!(
        elems[0].error_handling,
        Some(ErrorHandlingApproach::TreatAsWithdraw)
    );
}

#[test]
fn test_attribute_discard_mode_keeps_routes_and_drops_attributes() {
    let mut attrs = build_valid_attrs();
    attrs.extend_from_slice(&[0x40, 0x06, 0x01, 0x00]); // ATOMIC_AGGREGATE with a value byte
    attrs.extend_from_slice(&[0xc0, 0x07, 0x07, 0, 0, 0xfd, 0xe8, 10, 0, 0]); // AGGREGATOR, 7 bytes
    attrs.extend_from_slice(&[0xc0, 0x08, 0x04, 0, 1, 0, 1]); // COMMUNITIES 1:1
    attrs.extend_from_slice(&[0xc0, 0x08, 0x04, 0, 2, 0, 2]); // repeated COMMUNITIES 2:2
    let body = build_update_body(&[], &attrs, &valid_nlri_prefix());

    // as encoded: the malformed values show up and the last COMMUNITIES wins
    let elems = elems_of(&body, false);
    assert_eq!(elems.len(), 1);
    assert!(elems[0].atomic);
    assert!(elems[0].unknown.is_some(), "AGGREGATOR kept raw");

    let elems = elems_of(&body, true);
    assert_eq!(elems.len(), 1);
    let elem = &elems[0];
    assert_eq!(elem.elem_type, ElemType::ANNOUNCE);
    assert_eq!(
        elem.error_handling,
        Some(ErrorHandlingApproach::AttributeDiscard)
    );
    assert!(!elem.atomic, "malformed ATOMIC_AGGREGATE discarded");
    assert_eq!(elem.aggr_asn, None, "malformed AGGREGATOR discarded");
    assert_eq!(
        elem.unknown, None,
        "discarded attribute must not leak as unknown"
    );
    assert_eq!(
        elem.communities,
        Some(vec![MetaCommunity::Plain(Community::Custom(
            Asn::new_32bit(1),
            1
        ))]),
        "the first COMMUNITIES is kept (RFC 7606 §3(g))"
    );
    assert_eq!(elem.next_hop.unwrap().to_string(), "1.2.3.4");
}

#[test]
fn test_local_pref_is_attribute_discard_under_ebgp_assumption() {
    let mut attrs = build_valid_attrs();
    attrs.extend_from_slice(&[0x40, 0x05, 0x02, 0, 100]); // LOCAL_PREF, 2 bytes
    let body = build_update_body(&[], &attrs, &valid_nlri_prefix());

    let elems = elems_of(&body, true);
    assert_eq!(elems.len(), 1);
    assert_eq!(elems[0].elem_type, ElemType::ANNOUNCE);
    assert_eq!(
        elems[0].error_handling,
        Some(ErrorHandlingApproach::AttributeDiscard)
    );
}

#[test]
fn test_malformed_mp_reach_produces_reset_elems() {
    let mut attrs = build_valid_attrs();
    // IPv6 unicast MP_REACH_NLRI whose next-hop length (3) is invalid
    attrs.extend_from_slice(&[
        0x80, 0x0e, 0x08, 0x00, 0x02, 0x01, 0x03, 0xaa, 0xbb, 0xcc, 0x00,
    ]);
    let body = build_update_body(&[], &attrs, &valid_nlri_prefix());

    let elems = elems_of(&body, true);
    assert_eq!(elems.len(), 1);
    assert_eq!(elems[0].prefix.to_string(), "10.0.0.0/24");
    assert_eq!(elems[0].elem_type, ElemType::RESET);
    assert_eq!(
        elems[0].error_handling,
        Some(ErrorHandlingApproach::AfiSafiDisable)
    );
    assert!(elems[0].to_string().starts_with("R|"));
}

#[test]
fn test_repeated_mp_reach_is_session_reset() {
    let mut attrs = vec![0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x00];
    attrs.extend_from_slice(&ipv6_mp_reach());
    attrs.extend_from_slice(&ipv6_mp_reach());
    let body = build_update_body(&[], &attrs, &[]);

    let elems = elems_of(&body, true);
    assert!(!elems.is_empty());
    assert!(elems.iter().all(|e| e.elem_type == ElemType::RESET
        && e.error_handling == Some(ErrorHandlingApproach::SessionReset)));
}

#[test]
fn test_malformed_classic_nlri_is_session_reset() {
    let body = build_update_body(&[], &build_valid_attrs(), &malformed_nlri());
    let update = parse_bgp_update_message(Bytes::from(body), false, &AsnLength::Bits32).unwrap();
    assert_eq!(
        update.error_handling_approach(),
        Some(ErrorHandlingApproach::SessionReset)
    );
}

#[test]
fn test_update_without_nlri_escalates_to_session_reset() {
    // RFC 7606 §5.2: attributes and a withdrawn route, no reachable NLRI, and a
    // treat-as-withdraw error
    let body = build_update_body(&valid_nlri_prefix(), &attrs_with_origin(3), &[]);
    let update =
        parse_bgp_update_message(Bytes::from(body.clone()), false, &AsnLength::Bits32).unwrap();
    assert_eq!(
        update.error_handling_approach(),
        Some(ErrorHandlingApproach::SessionReset)
    );

    let elems = elems_of(&body, true);
    assert_eq!(elems.len(), 1);
    assert_eq!(elems[0].elem_type, ElemType::WITHDRAW);
    assert_eq!(
        elems[0].error_handling,
        Some(ErrorHandlingApproach::SessionReset)
    );
}

#[test]
fn test_clean_update_is_unchanged_by_the_mode() {
    let body = build_update_body(&[], &build_valid_attrs(), &two_prefixes());
    assert_eq!(elems_of(&body, false), elems_of(&body, true));
}

#[test]
fn test_type_filter_sees_synthesized_withdrawals() {
    let body = build_update_body(&[], &attrs_with_origin(3), &two_prefixes());
    let parser = bgpkit_parser::BgpkitParser::from_reader(Cursor::new(bgp4mp_update_record(&body)))
        .enable_rfc7606_error_handling()
        .add_filter("type", "w")
        .unwrap();
    assert_eq!(parser.into_elem_iter().count(), 2);
}

#[test]
fn test_malformed_update_reencodes_byte_identically() {
    let mut attrs = attrs_with_origin(3);
    attrs.extend_from_slice(&[0xc0, 0x08, 0x06, 0, 1, 0, 1, 0, 2]);
    let body = build_update_body(&[], &attrs, &two_prefixes());
    let update =
        parse_bgp_update_message(Bytes::from(body.clone()), false, &AsnLength::Bits32).unwrap();
    assert!(update.is_treat_as_withdraw());
    assert_eq!(update.encode(AsnLength::Bits32).unwrap(), Bytes::from(body));
}

/// The route iterator yields the projection of the element iterator, for
/// UPDATEs without value errors in attributes the route iterator does not parse.
fn assert_routes_match_elems(update_body: &[u8], rfc7606: bool) {
    let record = bgp4mp_update_record(update_body);
    let parser = |bytes: Vec<u8>| {
        let parser = bgpkit_parser::BgpkitParser::from_reader(Cursor::new(bytes));
        if rfc7606 {
            parser.enable_rfc7606_error_handling()
        } else {
            parser
        }
    };
    let routes: Vec<BgpRouteElem> = parser(record.clone()).into_route_iter().collect();
    let projected: Vec<BgpRouteElem> = parser(record)
        .into_elem_iter()
        .map(|elem| BgpRouteElem {
            timestamp: elem.timestamp,
            elem_type: elem.elem_type,
            peer_ip: elem.peer_ip,
            peer_asn: elem.peer_asn,
            prefix: elem.prefix,
            as_path: elem.as_path.map(std::sync::Arc::new),
        })
        .collect();
    assert_eq!(routes, projected);
}

#[test]
fn test_route_iterator_matches_elems_under_rfc7606() {
    let mut discard = build_valid_attrs();
    discard.extend_from_slice(&[0x40, 0x06, 0x01, 0x00]);
    let mut reset = build_valid_attrs();
    reset.extend_from_slice(&[
        0x80, 0x0e, 0x08, 0x00, 0x02, 0x01, 0x03, 0xaa, 0xbb, 0xcc, 0x00,
    ]);
    let mut as4 = vec![0x40, 0x01, 0x01, 0x00];
    as4.extend_from_slice(&[0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0x5b, 0xa0]); // AS_TRANS
    as4.extend_from_slice(&[0x40, 0x03, 0x04, 1, 2, 3, 4]);
    as4.extend_from_slice(&[0xc0, 0x11, 0x06, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00]); // AS4_PATH [0]

    // header-level findings on attributes the route iterator does not parse
    let mut short_communities = build_valid_attrs();
    short_communities.extend_from_slice(&[0xc0, 0x08, 0x06, 0, 1, 0, 1, 0, 2]);
    let mut well_known_communities = build_valid_attrs();
    well_known_communities.extend_from_slice(&[0x40, 0x08, 0x04, 0, 1, 0, 1]);

    let bodies = [
        build_update_body(&[], &build_valid_attrs(), &two_prefixes()),
        build_update_body(&[], &short_communities, &two_prefixes()),
        build_update_body(&[], &well_known_communities, &two_prefixes()),
        build_update_body(&[], &attrs_with_origin(3), &two_prefixes()),
        build_update_body(&[], &discard, &two_prefixes()),
        build_update_body(&[], &reset, &valid_nlri_prefix()),
        build_update_body(&valid_nlri_prefix(), &attrs_with_origin(3), &[]),
        build_update_body(&[], &as4, &valid_nlri_prefix()),
    ];
    for body in &bodies {
        assert_routes_match_elems(body, true);
    }
    // a malformed AS4_PATH is discarded, so the route keeps the AS_PATH alone
    assert_eq!(
        routes_of(&bodies[7])[0]
            .as_path
            .as_deref()
            .map(|p| p.to_string()),
        Some("23456".to_string())
    );
}

fn routes_of(update_body: &[u8]) -> Vec<BgpRouteElem> {
    bgpkit_parser::BgpkitParser::from_reader(Cursor::new(bgp4mp_update_record(update_body)))
        .enable_rfc7606_error_handling()
        .into_route_iter()
        .collect()
}

#[test]
fn test_route_iterator_misses_value_errors_in_attributes_it_does_not_parse() {
    // a D-PATH whose value is too short (RFC 10039 §4): its header is fine, so
    // only the element iterator, which parses the value, withdraws the routes
    let mut attrs = build_valid_attrs();
    attrs.extend_from_slice(&[0xc0, 0x24, 0x02, 0x00, 0x00]);
    let body = build_update_body(&[], &attrs, &two_prefixes());

    assert!(elems_of(&body, true)
        .iter()
        .all(|e| e.elem_type == ElemType::WITHDRAW));
    let routes = routes_of(&body);
    assert_eq!(routes.len(), 2);
    assert!(routes
        .iter()
        .all(|r| r.elem_type == ElemType::ANNOUNCE && r.as_path.is_some()));
}

#[test]
fn test_route_iterator_judges_headers_of_attributes_it_does_not_parse() {
    // COMMUNITIES without the optional bit is a known attribute with wrong
    // flags: treat-as-withdraw in both iterators, not a session reset
    let mut attrs = build_valid_attrs();
    attrs.extend_from_slice(&[0x40, 0x08, 0x04, 0, 1, 0, 1]);
    let body = build_update_body(&[], &attrs, &valid_nlri_prefix());
    let routes = routes_of(&body);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].elem_type, ElemType::WITHDRAW);

    // an unknown code without the optional bit is a session reset in both
    let mut attrs = build_valid_attrs();
    attrs.extend_from_slice(&[0x40, 0xc8, 0x00]);
    let body = build_update_body(&[], &attrs, &valid_nlri_prefix());
    assert_eq!(routes_of(&body)[0].elem_type, ElemType::RESET);
    assert_eq!(elems_of(&body, true)[0].elem_type, ElemType::RESET);
}

#[test]
fn test_route_iterator_malformed_nlri_is_not_fatal_under_rfc7606() {
    // valid withdrawn route, unparseable announced NLRI
    let body = build_update_body(
        &valid_nlri_prefix(),
        &build_valid_attrs(),
        &malformed_nlri(),
    );
    let routes = routes_of(&body);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].elem_type, ElemType::WITHDRAW);
    assert_eq!(routes[0].prefix.to_string(), "10.0.0.0/24");
}
