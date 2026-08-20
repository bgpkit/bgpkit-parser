//! Golden fixtures for the WASM TypeScript type surface.
//!
//! Serializes representative values of every generated type to
//! `src/wasm/test/fixtures/*.json`. CI regenerates these files and fails on
//! `git diff`, so any change to the Rust models that alters the serde output
//! must be accompanied by regenerated fixtures (and, for generated types,
//! regenerated bindings via `TS_RS_EXPORT_DIR=src/wasm/js/generated cargo
//! test --features ts-rs`). A companion `tsc` check in
//! `src/wasm/test/type-check/` asserts the fixtures type-check against the
//! shipped `.d.ts` files.
//!
//! Run with: `cargo test --features ts-rs,rislive --test test_wasm_type_fixtures`

use bgpkit_parser::error::BgpValidationWarning;
use bgpkit_parser::models::*;
use bgpkit_parser::parse_ris_live_message_raw_full;
use bytes::Bytes;
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

fn write_fixture(name: &str, value: &impl serde::Serialize) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/wasm/test/fixtures");
    std::fs::create_dir_all(&dir).expect("create fixtures dir");
    let json = serde_json::to_string_pretty(value).expect("serialize fixture");
    std::fs::write(dir.join(format!("{name}.json")), format!("{json}\n"))
        .expect("write fixture file");
}

fn sample_attributes() -> Vec<Attribute> {
    let values: Vec<AttributeValue> = vec![
        AttributeValue::Origin(Origin::IGP),
        AttributeValue::AsPath(AsPath::from_segments(vec![
            AsPathSegment::sequence([64512, 174]),
            AsPathSegment::set([65001, 65002]),
        ])),
        AttributeValue::As4Path(AsPath::from_segments(vec![AsPathSegment::sequence([
            4200000000,
        ])])),
        AttributeValue::NextHop("192.0.2.1".parse::<IpAddr>().unwrap()),
        AttributeValue::MultiExitDiscriminator(100),
        AttributeValue::LocalPreference(200),
        AttributeValue::OnlyToCustomer(64512.into()),
        AttributeValue::AtomicAggregate,
        AttributeValue::Aggregator {
            asn: Asn::new_32bit(64512),
            id: Ipv4Addr::new(192, 0, 2, 1),
        },
        AttributeValue::As4Aggregator {
            asn: Asn::new_32bit(4200000000),
            id: Ipv4Addr::new(192, 0, 2, 1),
        },
        AttributeValue::Communities(vec![
            Community::NoExport,
            Community::Custom(Asn::new_32bit(64512), 100),
        ]),
        AttributeValue::ExtendedCommunities(vec![
            ExtendedCommunity::TransitiveTwoOctetAs(TwoOctetAsExtCommunity {
                subtype: 0x02,
                global_admin: Asn::new_32bit(64512),
                local_admin: [0, 0, 0, 1],
            }),
            ExtendedCommunity::NonTransitiveOpaque(OpaqueExtCommunity {
                subtype: 0x04,
                value: [0, 0, 0, 0, 0, 1],
            }),
            ExtendedCommunity::LinkBandwidth(LinkBandwidth {
                global_admin: 64512,
                bandwidth: 12500000.0,
                transitive: true,
            }),
        ]),
        AttributeValue::Ipv6AddressSpecificExtendedCommunities(vec![Ipv6AddrExtCommunity {
            community_type: ExtendedCommunityType::NonTransitiveIpv4Addr,
            subtype: 0x02,
            global_admin: "2001:db8::1".parse().unwrap(),
            local_admin: [0, 1],
        }]),
        AttributeValue::LargeCommunities(vec![LargeCommunity::new(64512, [1, 2])]),
        AttributeValue::OriginatorId(Ipv4Addr::new(10, 0, 0, 1)),
        AttributeValue::Clusters(vec![167772161, 167772162]),
        AttributeValue::MpReachNlri(Nlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: Some(NextHopAddress::Ipv6LinkLocal(
                "2001:db8::1".parse().unwrap(),
                "fe80::1".parse().unwrap(),
            )),
            prefixes: vec![
                NetworkPrefix::new("2001:db8::/32".parse::<IpNet>().unwrap(), None),
                NetworkPrefix::new("198.51.100.0/24".parse::<IpNet>().unwrap(), Some(7)),
            ],
            labeled_prefixes: None,
            link_state_nlris: None,
            flowspec_nlris: None,
        }),
        AttributeValue::MpUnreachNlri(Nlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: None,
            prefixes: vec![NetworkPrefix::new(
                "2001:db8::/32".parse::<IpNet>().unwrap(),
                None,
            )],
            labeled_prefixes: None,
            link_state_nlris: None,
            flowspec_nlris: None,
        }),
        AttributeValue::Development(vec![1, 2, 3]),
        AttributeValue::Raw(AttrRaw {
            code: 22,
            bytes: Bytes::from_static(&[0, 1, 2, 3]),
        }),
        AttributeValue::Deprecated(AttrRaw {
            code: 9,
            bytes: Bytes::from_static(&[10, 0, 0, 1]),
        }),
        AttributeValue::Unknown(AttrRaw {
            code: 99,
            bytes: Bytes::from_static(&[0xff]),
        }),
    ];

    values.into_iter().map(Attribute::from).collect()
}

#[test]
fn write_attribute_value_fixtures() {
    let attributes = sample_attributes();
    let values: Vec<AttributeValue> = attributes.iter().map(|a| a.value.clone()).collect();
    write_fixture(
        "attribute_values",
        &serde_json::json!({ "attributes": attributes, "values": values }),
    );
}

#[test]
fn write_bgp_elem_fixtures() {
    let announce = BgpElem {
        timestamp: 1636245154.8,
        elem_type: ElemType::ANNOUNCE,
        peer_ip: "192.0.2.1".parse().unwrap(),
        peer_asn: Asn::new_32bit(64496),
        peer_bgp_id: Some(Ipv4Addr::new(10, 0, 0, 1)),
        prefix: NetworkPrefix::new("198.51.100.0/24".parse::<IpNet>().unwrap(), None),
        next_hop: Some("192.0.2.1".parse().unwrap()),
        as_path: Some(AsPath::from_segments(vec![
            AsPathSegment::sequence([64496, 174]),
            AsPathSegment::set([65001, 65002]),
        ])),
        origin_asns: Some(vec![65001.into(), 65002.into()]),
        origin: Some(Origin::IGP),
        local_pref: Some(100),
        med: Some(0),
        communities: Some(vec![
            MetaCommunity::Plain(Community::Custom(Asn::new_32bit(64512), 100)),
            MetaCommunity::Large(LargeCommunity::new(64512, [1, 2])),
        ]),
        atomic: false,
        aggr_asn: Some(Asn::new_32bit(64512)),
        aggr_ip: Some(Ipv4Addr::new(192, 0, 2, 1)),
        only_to_customer: Some(Asn::new_32bit(64512)),
        unknown: Some(vec![AttrRaw {
            code: 99,
            bytes: Bytes::from_static(&[0xff]),
        }]),
        deprecated: None,
    };
    write_fixture("bgp_elem_announce", &announce);

    let withdraw = BgpElem {
        timestamp: 1636245154.8,
        elem_type: ElemType::WITHDRAW,
        peer_ip: "192.0.2.1".parse().unwrap(),
        peer_asn: Asn::new_32bit(64496),
        peer_bgp_id: None,
        prefix: NetworkPrefix::new("198.51.100.0/24".parse::<IpNet>().unwrap(), None),
        next_hop: None,
        as_path: None,
        origin_asns: None,
        origin: None,
        local_pref: None,
        med: None,
        communities: None,
        atomic: false,
        aggr_asn: None,
        aggr_ip: None,
        only_to_customer: None,
        unknown: None,
        deprecated: None,
    };
    write_fixture("bgp_elem_withdraw", &withdraw);
}

#[test]
fn write_bgp_validation_warning_fixtures() {
    write_fixture(
        "bgp_validation_warnings",
        &vec![
            BgpValidationWarning::AttributeFlagsError {
                attr_type: AttrType::COMMUNITIES,
                expected_flags: 0xc0,
                actual_flags: 0x40,
            },
            BgpValidationWarning::MissingWellKnownAttribute {
                attr_type: AttrType::ORIGIN,
            },
            BgpValidationWarning::MalformedNlri {
                nlri_type: "announced",
                reason: "invalid prefix length".to_string(),
                raw_bytes: vec![51, 100, 24],
            },
        ],
    );
}

#[cfg(feature = "rislive")]
#[test]
fn write_ris_live_raw_full_fixture() {
    // Real-world RIS Live `ris_message` with `includeRaw` (used by the wasm
    // tests as well). End-to-end fixture: envelope -> hex raw -> full result.
    let message = r#"{
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
    let full = parse_ris_live_message_raw_full(message).unwrap();
    write_fixture("ris_live_raw_full", &full);
}
