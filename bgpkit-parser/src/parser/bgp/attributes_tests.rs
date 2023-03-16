//! Attributes parsing tests module

/*
- [ ] parse_origin
- [ ] parse_as_path
- [ ] parse_as_segment
- [ ] parse_next_hop
- [ ] parse_med
- [ ] parse_local_pref
- [ ] parse_aggregator
- [ ] parse_regular_communities
- [ ] parse_originator_id
- [ ] parse_cluster_id
- [ ] parse_clusters
- [ ] parse_nlri
- [ ] parse_mp_next_hop
- [ ] parse_large_communities
- [ ] parse_extended_community
- [ ] parse_ipv6_extended_community
- [ ] parse_only_to_customer_attr
 */

use crate::parser::AttributeParser;
use crate::ParserError;
use bgp_models::prelude::*;
use std::io::Cursor;

/// test parse origin
/// ```text
/// ORIGIN is a well-known mandatory attribute that defines the
///        origin of the path information.  The data octet can assume
///        the following values:
///
///           Value      Meaning
///
///           0         IGP - Network Layer Reachability Information
///                        is interior to the originating AS
///
///           1         EGP - Network Layer Reachability Information
///                        learned via the EGP protocol [RFC904]
///
///           2         INCOMPLETE - Network Layer Reachability
///                        Information learned by some other means
///
/// Usage of this attribute is defined in 5.1.1.
/// ```
#[test]
fn test_parse_origin() {
    let parser = AttributeParser::new(false);
    assert_eq!(
        AttributeValue::Origin(Origin::IGP),
        parser.parse_origin(&mut Cursor::new(&[0u8])).unwrap()
    );
    assert_eq!(
        AttributeValue::Origin(Origin::EGP),
        parser.parse_origin(&mut Cursor::new(&[1u8])).unwrap()
    );
    assert_eq!(
        AttributeValue::Origin(Origin::INCOMPLETE),
        parser.parse_origin(&mut Cursor::new(&[2u8])).unwrap()
    );
    assert!(matches!(
        parser.parse_origin(&mut Cursor::new(&[3u8])).unwrap_err(),
        ParserError::UnknownAttr(_)
    ));
}

///
/// ```text
/// AS_PATH is a well-known mandatory attribute that is composed
/// of a sequence of AS path segments.  Each AS path segment is
/// represented by a triple <path segment type, path segment
/// length, path segment value>.
///
/// The path segment type is a 1-octet length field with the
/// following values defined:
///
/// Value      Segment Type
///
/// 1         AS_SET: unordered set of ASes a route in the
/// UPDATE message has traversed
///
/// 2         AS_SEQUENCE: ordered set of ASes a route in
/// the UPDATE message has traversed
///
/// The path segment length is a 1-octet length field,
/// containing the number of ASes (not the number of octets) in
/// the path segment value field.
///
/// The path segment value field contains one or more AS
/// numbers, each encoded as a 2-octet length field.
///
/// Usage of this attribute is defined in 5.1.2.
/// ```
#[test]
fn test_parse_as_path() {}

#[test]
fn test_parse_as_path_segment() {
    let parser = AttributeParser::new(false);
    //////////////////////
    // 16 bits sequence //
    //////////////////////
    let data: [u8; 8] = [
        2, // sequence
        3, // 3 ASes in path
        0, 1, // AS1
        0, 2, // AS2
        0, 3, // AS3
    ];
    let res = parser
        .parse_as_path_segment(&mut Cursor::new(&data), &AsnLength::Bits16)
        .unwrap();

    assert!(matches!(res, AsPathSegment::AsSequence(_)));
    if let AsPathSegment::AsSequence(p) = res {
        let asns: Vec<u32> = p.into_iter().map(|a| a.asn).collect();
        assert_eq!(asns, vec![1, 2, 3]);
    } else {
        panic!("not a as sequence")
    }

    //////////////////////
    // 16 bits sequence //
    //////////////////////
    let data: [u8; 14] = [
        2, // sequence
        3, // 3 ASes in path
        0, 0, 0, 1, // AS1
        0, 0, 0, 2, // AS2
        0, 0, 0, 3, // AS3
    ];
    let res = parser
        .parse_as_path_segment(&mut Cursor::new(&data), &AsnLength::Bits32)
        .unwrap();
    assert!(matches!(res, AsPathSegment::AsSequence(_)));
    if let AsPathSegment::AsSequence(p) = res {
        let asns: Vec<u32> = p.into_iter().map(|a| a.asn).collect();
        assert_eq!(asns, vec![1, 2, 3]);
    } else {
        panic!("not a as sequence")
    }

    /////////////////
    // other types //
    /////////////////
    let data: [u8; 4] = [
        1, // AS Set
        1, // 1 AS in path
        0, 1,
    ];
    let res = parser
        .parse_as_path_segment(&mut Cursor::new(&data), &AsnLength::Bits16)
        .unwrap();
    assert!(matches!(res, AsPathSegment::AsSet(_)));

    let data: [u8; 4] = [
        3, // Confed Sequence
        1, // 1 AS in path
        0, 1,
    ];
    let res = parser
        .parse_as_path_segment(&mut Cursor::new(&data), &AsnLength::Bits16)
        .unwrap();
    assert!(matches!(res, AsPathSegment::ConfedSequence(_)));

    let data: [u8; 4] = [
        4, // Confed Set
        1, // 1 AS in path
        0, 1,
    ];
    let res = parser
        .parse_as_path_segment(&mut Cursor::new(&data), &AsnLength::Bits16)
        .unwrap();
    assert!(matches!(res, AsPathSegment::ConfedSet(_)));

    let data: [u8; 4] = [
        5, // ERROR
        1, // 1 AS in path
        0, 1,
    ];
    let res = parser
        .parse_as_path_segment(&mut Cursor::new(&data), &AsnLength::Bits16)
        .unwrap_err();
    assert!(matches!(res, ParserError::ParseError(_)));
}
