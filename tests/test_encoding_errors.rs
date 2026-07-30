//! Error-path tests for the fallible encoding API (issue #313).
//!
//! Every wire-format capacity bound must surface as an `EncodingError`
//! instead of silently truncating, wrapping, or dropping data.

use bgpkit_parser::error::EncodingError;
use bgpkit_parser::models::*;
use std::net::Ipv4Addr;
use std::str::FromStr;

fn oversized_attribute() -> Attribute {
    // 30 large communities = 360 bytes, exceeding the 255-byte limit of a
    // non-extended attribute length field
    let communities = vec![LargeCommunity::new(1, [2, 3]); 30];
    Attribute {
        value: AttributeValue::LargeCommunities(communities),
        flag: AttrFlags::OPTIONAL | AttrFlags::TRANSITIVE,
    }
}

#[test]
fn test_oversized_attribute_value_non_extended() {
    let attr = oversized_attribute();
    assert!(!attr.is_extended());
    let err = attr.encode(AsnLength::Bits32).unwrap_err();
    assert_eq!(
        err,
        EncodingError::ValueTooLarge {
            field: "BGP attribute value length",
            actual: 360,
            max: 255
        }
    );
}

#[test]
fn test_oversized_attribute_value_extended() {
    // 6000 large communities = 72000 bytes, exceeding even the extended
    // 2-byte attribute length field
    let communities = vec![LargeCommunity::new(1, [2, 3]); 6000];
    let attr = Attribute {
        value: AttributeValue::LargeCommunities(communities),
        flag: AttrFlags::OPTIONAL | AttrFlags::TRANSITIVE | AttrFlags::EXTENDED,
    };
    let err = attr.encode(AsnLength::Bits32).unwrap_err();
    assert_eq!(
        err,
        EncodingError::ValueTooLarge {
            field: "BGP attribute value length (extended)",
            actual: 72000,
            max: 65535
        }
    );
}

#[test]
fn test_attr_set_is_unencodable() {
    let attr = Attribute::from(AttributeValue::AttrSet(AttrSet {
        origin_as: Asn::from(65000),
        attributes: Attributes::default(),
    }));
    let err = attr.encode(AsnLength::Bits32).unwrap_err();
    assert!(matches!(
        err,
        EncodingError::Unencodable {
            field: "ATTR_SET attribute",
            ..
        }
    ));
}

#[test]
fn test_mp_reach_empty_label_stack_propagates() {
    // Previously this error was swallowed (log + empty attribute value);
    // it must now surface through Attribute::encode.
    let nlri = Nlri {
        afi: Afi::Ipv4,
        safi: Safi::MplsLabel,
        next_hop: Some(NextHopAddress::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
        prefixes: vec![],
        labeled_prefixes: Some(vec![LabeledNetworkPrefix {
            prefix: "203.0.113.0/24".parse().unwrap(),
            labels: Default::default(), // empty label stack cannot be encoded
            path_id: None,
        }]),
        link_state_nlris: None,
        flowspec_nlris: None,
    };
    let attr = Attribute::from(AttributeValue::MpReachNlri(nlri));
    let err = attr.encode(AsnLength::Bits32).unwrap_err();
    assert!(matches!(
        err,
        EncodingError::Unencodable {
            field: "MP NLRI labeled prefix",
            ..
        }
    ));
}

#[test]
fn test_rib_entry_oversized_attributes_propagate() {
    // Regression guard: an entry whose attributes cannot be encoded must fail
    // the whole RibAfiEntries::encode, not be silently dropped from the record.
    let entry = RibEntry {
        peer_index: 0,
        originated_time: 0,
        path_id: None,
        attributes: Attributes::from(vec![oversized_attribute()]),
    };
    let rib = RibAfiEntries {
        rib_type: TableDumpV2Type::RibIpv4Unicast,
        sequence_number: 1,
        prefix: NetworkPrefix::from_str("203.0.113.0/24").unwrap(),
        rib_entries: vec![entry],
    };
    let err = rib.encode().unwrap_err();
    assert_eq!(
        err,
        EncodingError::ValueTooLarge {
            field: "BGP attribute value length",
            actual: 360,
            max: 255
        }
    );
}

#[test]
fn test_rib_entry_count_overflow() {
    let entry = RibEntry {
        peer_index: 0,
        originated_time: 0,
        path_id: None,
        attributes: Attributes::default(),
    };
    let rib = RibAfiEntries {
        rib_type: TableDumpV2Type::RibIpv4Unicast,
        sequence_number: 1,
        prefix: NetworkPrefix::from_str("203.0.113.0/24").unwrap(),
        rib_entries: vec![entry; 65536],
    };
    let err = rib.encode().unwrap_err();
    assert_eq!(
        err,
        EncodingError::ValueTooLarge {
            field: "RIB entry count",
            actual: 65536,
            max: 65535
        }
    );
}

#[test]
fn test_open_message_rejects_reserved_param_type_255() {
    // RFC 9072 reserves parameter type 255 as the extended-length marker;
    // encoding it as a real parameter would be misparsed on round trip.
    let msg = BgpOpenMessage {
        version: 4,
        asn: Asn::new_16bit(64512),
        hold_time: 90,
        bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
        extended_length: false,
        opt_params: vec![OptParam {
            param_type: 255,
            param_value: ParamValue::Raw(vec![0xAA, 0xBB]),
        }],
    };
    let err = msg.encode().unwrap_err();
    assert!(matches!(
        err,
        EncodingError::Unencodable {
            field: "BGP OPEN optional parameter type",
            ..
        }
    ));
}

#[test]
fn test_bgp_message_total_length_overflow() {
    // 17000 distinct /24 prefixes at 4 bytes each push the UPDATE body past
    // the 16-bit BGP message length field.
    let prefixes: Vec<NetworkPrefix> = (0..17000u32)
        .map(|i| {
            NetworkPrefix::from_str(&format!("10.{}.{}.0/24", (i >> 8) & 0xFF, i & 0xFF)).unwrap()
        })
        .collect();
    let update = BgpUpdateMessage {
        withdrawn_prefixes: vec![],
        attributes: Attributes::default(),
        announced_prefixes: prefixes,
    };
    let err = BgpMessage::Update(update)
        .encode(AsnLength::Bits32)
        .unwrap_err();
    assert!(matches!(
        err,
        EncodingError::ValueTooLarge {
            field: "BGP message total length",
            max: 65535,
            ..
        }
    ));
}

#[test]
fn test_tunnel_encap_oversized_sub_tlv() {
    // Sub-TLV types < 128 carry a 1-octet length field
    let mut tlv = TunnelEncapTlv::new(TunnelType::Vxlan);
    tlv.add_sub_tlv(SubTlv::new(SubTlvType::Color, vec![0u8; 300]));
    let mut attr = TunnelEncapAttribute::new();
    attr.add_tunnel_tlv(tlv);
    let attribute = Attribute::from(AttributeValue::TunnelEncapsulation(attr));
    let err = attribute.encode(AsnLength::Bits32).unwrap_err();
    assert_eq!(
        err,
        EncodingError::ValueTooLarge {
            field: "Tunnel Encap sub-TLV value length",
            actual: 300,
            max: 255
        }
    );
}
