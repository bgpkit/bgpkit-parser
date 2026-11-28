//! Parity and scope tests for `BgpkitParser::next_record_elems`.

use bgpkit_parser::models::{
    Afi, AsPath, AsPathSegment, Asn, AttrFlags, AttrType, AttributeValue, Attributes, Bgp4MpEnum,
    Bgp4MpMessage, Bgp4MpType, BgpElem, BgpMessage, BgpUpdateMessage, CommonHeader, Community,
    EntryType, ExtendedCommunity, ExtendedCommunityType, FlowSpecTrafficAction,
    FlowSpecTrafficMarking, FlowSpecTrafficRate, FourOctetAsExtCommunity, GeoPeerTable,
    Ipv4AddrExtCommunity, Ipv6AddrExtCommunity, LargeCommunity, LinkBandwidth, MacMobility,
    MetaCommunity, MrtMessage, MrtRecord, NetworkPrefix, NextHopAddress, Nlri, OpaqueExtCommunity,
    Origin, Peer, PeerIndexTable, RibAfiEntries, RibEntry, RouteDistinguisher, TableDumpMessage,
    TableDumpV2Message, TableDumpV2Type, TwoOctetAsExtCommunity,
};
use bgpkit_parser::{AsPathSegmentType, BgpkitParser, CommunitiesView, ElemRef};
use bytes::{BufMut, BytesMut};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommunityKind {
    Plain,
    Extended,
    Ipv6Extended,
    Large,
}

fn tagged_communities_from_elem(elem: &BgpElem) -> Vec<(CommunityKind, MetaCommunity)> {
    elem.communities
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .copied()
        .map(|mc| {
            let kind = match mc {
                MetaCommunity::Plain(_) => CommunityKind::Plain,
                MetaCommunity::Extended(_) => CommunityKind::Extended,
                MetaCommunity::Ipv6Extended(_) => CommunityKind::Ipv6Extended,
                MetaCommunity::Large(_) => CommunityKind::Large,
            };
            (kind, mc)
        })
        .collect()
}

fn tagged_communities_from_view(view: CommunitiesView<'_>) -> Vec<(CommunityKind, MetaCommunity)> {
    view.iter()
        .map(|mc| {
            let kind = match mc {
                MetaCommunity::Plain(_) => CommunityKind::Plain,
                MetaCommunity::Extended(_) => CommunityKind::Extended,
                MetaCommunity::Ipv6Extended(_) => CommunityKind::Ipv6Extended,
                MetaCommunity::Large(_) => CommunityKind::Large,
            };
            (kind, mc)
        })
        .collect()
}

fn flattened_as_path(elem: &BgpElem) -> Vec<Asn> {
    elem.as_path
        .as_ref()
        .map(|p| p.iter_segments().flatten().copied().collect())
        .unwrap_or_default()
}

fn assert_elem_parity(index: usize, elem: &BgpElem, view: &ElemRef<'_>) {
    assert_eq!(view.prefix(), elem.prefix, "elem #{index}: prefix mismatch");
    assert_eq!(
        view.peer_ip(),
        elem.peer_ip,
        "elem #{index}: peer_ip mismatch"
    );
    assert_eq!(
        view.peer_asn(),
        elem.peer_asn,
        "elem #{index}: peer_asn mismatch"
    );
    assert_eq!(
        view.timestamp(),
        elem.timestamp,
        "elem #{index}: timestamp mismatch"
    );
    assert_eq!(
        view.elem_type(),
        elem.elem_type,
        "elem #{index}: elem_type mismatch"
    );

    // AS_PATH: flat Vec<Asn> (with AS_SET expanded in wire order) + presence + segment structure.
    let path_view = view.as_path();
    assert_eq!(
        path_view.is_present(),
        elem.as_path.is_some(),
        "elem #{index}: as_path presence mismatch"
    );
    assert_eq!(
        path_view.to_vec(),
        flattened_as_path(elem),
        "elem #{index}: as_path Vec<Asn> mismatch"
    );
    assert_eq!(
        path_view.to_as_path(),
        elem.as_path,
        "elem #{index}: as_path segment structure mismatch"
    );

    // Origin ASNs: presence + exact ASN sequence.
    let origins_view = view.origin_asns();
    let origins_opt = origins_view.is_present().then(|| origins_view.to_vec());
    assert_eq!(
        origins_opt, elem.origin_asns,
        "elem #{index}: origin_asns mismatch"
    );
    assert_eq!(
        origins_view.len(),
        origins_opt.as_ref().map_or(0, Vec::len),
        "elem #{index}: origin_asns len mismatch"
    );

    // Communities: (kind, value) pairs in wire order, typed adapters, and raw u32 word count.
    let comm_view = view.communities();
    let expected_pairs = tagged_communities_from_elem(elem);
    let actual_pairs = tagged_communities_from_view(comm_view);
    assert_eq!(
        actual_pairs, expected_pairs,
        "elem #{index}: communities (kind, value) mismatch"
    );

    let expected_plain: Vec<Community> = elem
        .communities
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|c| match c {
            MetaCommunity::Plain(v) => Some(*v),
            _ => None,
        })
        .collect();
    let expected_ext: Vec<ExtendedCommunity> = elem
        .communities
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|c| match c {
            MetaCommunity::Extended(v) => Some(*v),
            _ => None,
        })
        .collect();
    let expected_v6_ext: Vec<Ipv6AddrExtCommunity> = elem
        .communities
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|c| match c {
            MetaCommunity::Ipv6Extended(v) => Some(*v),
            _ => None,
        })
        .collect();
    let expected_large: Vec<LargeCommunity> = elem
        .communities
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|c| match c {
            MetaCommunity::Large(v) => Some(*v),
            _ => None,
        })
        .collect();

    assert_eq!(
        comm_view.as_plain().collect::<Vec<_>>(),
        expected_plain,
        "elem #{index}: as_plain() mismatch"
    );
    assert_eq!(
        comm_view.as_extended().collect::<Vec<_>>(),
        expected_ext,
        "elem #{index}: as_extended() mismatch"
    );
    assert_eq!(
        comm_view.as_ipv6_extended().collect::<Vec<_>>(),
        expected_v6_ext,
        "elem #{index}: as_ipv6_extended() mismatch"
    );
    assert_eq!(
        comm_view.as_large().collect::<Vec<_>>(),
        expected_large,
        "elem #{index}: as_large() mismatch"
    );

    let expected_words = expected_plain.len()
        + expected_ext.len() * 2
        + expected_v6_ext.len() * 5
        + expected_large.len() * 3;
    assert_eq!(
        comm_view.words().count(),
        expected_words,
        "elem #{index}: raw u32 words count mismatch"
    );

    // Scalar attributes.
    assert_eq!(
        view.next_hop(),
        elem.next_hop,
        "elem #{index}: next_hop mismatch"
    );
    assert_eq!(view.med(), elem.med, "elem #{index}: med mismatch");
    assert_eq!(
        view.local_pref(),
        elem.local_pref,
        "elem #{index}: local_pref mismatch"
    );
}

#[test]
fn rib_fixture_field_by_field_parity_with_into_elem_iter() {
    let url = "https://spaces.bgpkit.org/parser/rib-example-small.bz2";

    let mut owned_iter = BgpkitParser::new(url)
        .expect("open RIB fixture for owned iteration")
        .into_elem_iter();
    let mut view_parser =
        BgpkitParser::new(url).expect("open RIB fixture for borrowed element iteration");

    let mut idx = 0usize;
    let mut record_count = 0usize;
    while let Some(mut record) = view_parser.next_record_elems() {
        assert_eq!(record.header().entry_type, EntryType::TABLE_DUMP_V2);
        let declared_len = record.len();
        let mut yielded_in_record = 0usize;
        for elem_ref in record.iter() {
            let owned = owned_iter
                .next()
                .unwrap_or_else(|| panic!("next_record_elems yielded extra elem at #{idx}"));
            assert_elem_parity(idx, &owned, &elem_ref);
            idx += 1;
            yielded_in_record += 1;
        }
        assert_eq!(yielded_in_record, declared_len);
        record_count += 1;
    }

    assert!(
        owned_iter.next().is_none(),
        "into_elem_iter yielded more elems than next_record_elems after {idx} elems"
    );
    assert!(idx > 0 && record_count > 0);
}

/// Build a comprehensive in-memory `TABLE_DUMP_V2` stream exercising all RIB subtypes, segment
/// types (`AS_SET`, `AS_SEQUENCE`, confederation, empty iBGP, missing, and RFC 6793 `AS4_PATH`
/// merging), all community encodings (plain, extended subtypes, IPv6 extended, large), IPv4/IPv6
/// next-hop forms (including RFC 2545 global+link-local pairs in both orders and VPNv6), MED,
/// LOCAL_PREF, mid-file `PeerIndexTable` swaps, and `GeoPeerTable`.
fn build_exhaustive_rib_stream() -> Vec<u8> {
    let mut peer_table = PeerIndexTable::default();
    let p_v4 = peer_table
        .add_peer(Peer::new(
            Ipv4Addr::new(192, 0, 2, 1),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            Asn::new_32bit(64501),
        ))
        .unwrap();
    let p_v6 = peer_table
        .add_peer(Peer::new(
            Ipv4Addr::new(192, 0, 2, 2),
            IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap()),
            Asn::new_16bit(64502),
        ))
        .unwrap();

    let pit_record = MrtRecord {
        common_header: CommonHeader {
            timestamp: 1_700_000_000,
            microsecond_timestamp: None,
            entry_type: EntryType::TABLE_DUMP_V2,
            entry_subtype: TableDumpV2Type::PeerIndexTable as u16,
            length: 0,
        },
        message: MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(peer_table)),
    };

    let geo_record = MrtRecord {
        common_header: CommonHeader {
            timestamp: 1_700_000_000,
            microsecond_timestamp: None,
            entry_type: EntryType::TABLE_DUMP_V2,
            entry_subtype: TableDumpV2Type::GeoPeerTable as u16,
            length: 0,
        },
        message: MrtMessage::TableDumpV2Message(TableDumpV2Message::GeoPeerTable(
            GeoPeerTable::new(Ipv4Addr::new(192, 0, 2, 9), String::new(), 0.0, 0.0),
        )),
    };

    // Entry 1: AS_SEQUENCE + AS_SET + all community families + MED + LOCAL_PREF + NEXT_HOP.
    let mut attrs1 = Attributes::default();
    attrs1.add_attr(AttributeValue::Origin(Origin::IGP).into());
    attrs1.add_attr(
        AttributeValue::AsPath(AsPath::from_segments(vec![
            AsPathSegment::ConfedSequence(vec![Asn::new_32bit(65010)].into()),
            AsPathSegment::sequence([64501, 3356, 174]),
            AsPathSegment::set([13335, 15169, 8075]),
        ]))
        .into(),
    );
    attrs1.add_attr(AttributeValue::NextHop(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 254))).into());
    attrs1.add_attr(AttributeValue::MultiExitDiscriminator(420).into());
    attrs1.add_attr(AttributeValue::LocalPreference(250).into());
    attrs1.add_attr(
        AttributeValue::Communities(vec![
            Community::NoExport,
            Community::NoAdvertise,
            Community::NoExportSubConfed,
            Community::Custom(Asn::new_16bit(3356), 123),
        ])
        .into(),
    );
    attrs1.add_attr(
        AttributeValue::ExtendedCommunities(vec![
            ExtendedCommunity::TransitiveTwoOctetAs(TwoOctetAsExtCommunity {
                subtype: 0x02,
                global_admin: Asn::new_16bit(64501),
                local_admin: [0, 0, 0, 7],
            }),
            ExtendedCommunity::LinkBandwidth(LinkBandwidth {
                global_admin: 64501,
                bandwidth: 1250.5,
                transitive: true,
            }),
            ExtendedCommunity::FlowSpecTrafficRate(FlowSpecTrafficRate::new(64501, 500.0)),
            ExtendedCommunity::FlowSpecTrafficAction(FlowSpecTrafficAction::new(
                64501, true, false,
            )),
            ExtendedCommunity::FlowSpecTrafficMarking(FlowSpecTrafficMarking::new(64501, 46)),
            ExtendedCommunity::TransitiveIpv4Addr(Ipv4AddrExtCommunity {
                subtype: 0x02,
                global_admin: Ipv4Addr::new(203, 0, 113, 5),
                local_admin: [1, 2],
            }),
            ExtendedCommunity::TransitiveFourOctetAs(FourOctetAsExtCommunity {
                subtype: 0x02,
                global_admin: Asn::new_32bit(400_123),
                local_admin: [3, 4],
            }),
            ExtendedCommunity::TransitiveOpaque(OpaqueExtCommunity {
                subtype: 0x03,
                value: [9, 8, 7, 6, 5, 4],
            }),
            ExtendedCommunity::MacMobility(MacMobility {
                sticky: true,
                sequence: 99,
            }),
            ExtendedCommunity::Raw([0x99, 1, 2, 3, 4, 5, 6, 7]),
        ])
        .into(),
    );
    attrs1.add_attr(
        AttributeValue::Ipv6AddressSpecificExtendedCommunities(vec![Ipv6AddrExtCommunity {
            community_type: ExtendedCommunityType::TransitiveTwoOctetAs,
            subtype: 0x02,
            global_admin: Ipv6Addr::from_str("2001:db8::abcd").unwrap(),
            local_admin: [0x12, 0x34],
        }])
        .into(),
    );
    attrs1.add_attr(
        AttributeValue::LargeCommunities(vec![
            LargeCommunity::new(13335, [100, 200]),
            LargeCommunity::new(400_123, [1, 2]),
        ])
        .into(),
    );

    // Entry 2: Empty iBGP AS_PATH (present with 0 segments), missing MED & LOCAL_PREF, AS4_PATH merge.
    let mut attrs2 = Attributes::default();
    attrs2.add_attr(AttributeValue::Origin(Origin::EGP).into());
    attrs2.add_attr(
        AttributeValue::AsPath(AsPath::from_segments(vec![
            AsPathSegment::sequence([64501, 23456]),
            AsPathSegment::sequence([23456, 64499]),
        ]))
        .into(),
    );
    attrs2.add_attr(AttributeValue::As4Path(AsPath::from_sequence([400_001, 400_002])).into());
    attrs2.add_attr(AttributeValue::NextHop(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))).into());

    // Entry 3: Empty 0-segment AS_PATH (iBGP local route) + absent communities.
    let mut attrs3 = Attributes::default();
    attrs3.add_attr(AttributeValue::Origin(Origin::INCOMPLETE).into());
    attrs3.add_attr(AttributeValue::AsPath(AsPath::new()).into());
    attrs3.add_attr(AttributeValue::NextHop(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3))).into());

    let rib_v4 = MrtRecord {
        common_header: CommonHeader {
            timestamp: 1_700_000_001,
            microsecond_timestamp: None,
            entry_type: EntryType::TABLE_DUMP_V2,
            entry_subtype: TableDumpV2Type::RibIpv4Unicast as u16,
            length: 0,
        },
        message: MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(RibAfiEntries {
            rib_type: TableDumpV2Type::RibIpv4Unicast,
            sequence_number: 1,
            prefix: NetworkPrefix::from_str("203.0.113.0/24").unwrap(),
            rib_entries: vec![
                RibEntry {
                    peer_index: p_v4,
                    originated_time: 1_699_999_900,
                    path_id: None,
                    attributes: attrs1,
                },
                RibEntry {
                    peer_index: p_v4,
                    originated_time: 1_699_999_901,
                    path_id: None,
                    attributes: attrs2,
                },
                RibEntry {
                    peer_index: p_v4,
                    originated_time: 1_699_999_902,
                    path_id: None,
                    attributes: attrs3,
                },
            ],
        })),
    };

    // IPv6 ADD-PATH RIB record with RFC 2545 reversed link-local + global pair in MP_REACH_NLRI.
    let mut attrs_v6 = Attributes::default();
    attrs_v6.add_attr(AttributeValue::Origin(Origin::IGP).into());
    attrs_v6.add_attr(AttributeValue::AsPath(AsPath::from_sequence([64502, 15169])).into());
    attrs_v6.add_attr(
        AttributeValue::MpReachNlri(Nlri {
            afi: Afi::Ipv6,
            safi: bgpkit_parser::models::Safi::Unicast,
            next_hop: Some(NextHopAddress::Ipv6LinkLocal(
                Ipv6Addr::from_str("fe80::1").unwrap(),
                Ipv6Addr::from_str("2001:db8::cafe").unwrap(),
            )),
            prefixes: vec![NetworkPrefix::from_str("2001:db8:100::/48").unwrap()],
            labeled_prefixes: None,
            link_state_nlris: None,
            flowspec_nlris: None,
            evpn_nlris: None,
        })
        .into(),
    );

    // Also VPNv6 next-hop in MP_REACH_NLRI and missing AS_PATH.
    let mut attrs_v6_vpn = Attributes::default();
    attrs_v6_vpn.add_attr(AttributeValue::Origin(Origin::IGP).into());
    attrs_v6_vpn.add_attr(
        AttributeValue::MpReachNlri(Nlri {
            afi: Afi::Ipv6,
            safi: bgpkit_parser::models::Safi::Unicast,
            next_hop: Some(NextHopAddress::VpnIpv6(
                RouteDistinguisher([0, 1, 2, 3, 4, 5, 6, 7]),
                Ipv6Addr::from_str("2001:db8::beef").unwrap(),
            )),
            prefixes: vec![NetworkPrefix::from_str("2001:db8:100::/48").unwrap()],
            labeled_prefixes: None,
            link_state_nlris: None,
            flowspec_nlris: None,
            evpn_nlris: None,
        })
        .into(),
    );

    let rib_v6 = MrtRecord {
        common_header: CommonHeader {
            timestamp: 1_700_000_002,
            microsecond_timestamp: None,
            entry_type: EntryType::TABLE_DUMP_V2,
            entry_subtype: TableDumpV2Type::RibIpv6UnicastAddPath as u16,
            length: 0,
        },
        message: MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(RibAfiEntries {
            rib_type: TableDumpV2Type::RibIpv6UnicastAddPath,
            sequence_number: 2,
            prefix: NetworkPrefix::from_str("2001:db8:100::/48").unwrap(),
            rib_entries: vec![
                RibEntry {
                    peer_index: p_v6,
                    originated_time: 1_699_999_950,
                    path_id: Some(7),
                    attributes: attrs_v6,
                },
                RibEntry {
                    peer_index: p_v6,
                    originated_time: 1_699_999_951,
                    path_id: Some(8),
                    attributes: attrs_v6_vpn,
                },
            ],
        })),
    };

    let mut wire = Vec::new();
    for rec in [pit_record, geo_record, rib_v4, rib_v6] {
        wire.extend_from_slice(&rec.encode().unwrap());
    }
    wire
}

#[test]
fn exhaustive_rib_variants_parity_and_segment_views() {
    let wire = build_exhaustive_rib_stream();

    let owned_elems: Vec<BgpElem> = BgpkitParser::from_reader(Cursor::new(wire.clone()))
        .into_elem_iter()
        .collect();
    assert_eq!(owned_elems.len(), 5);

    let mut parser = BgpkitParser::from_reader(Cursor::new(wire));
    let mut idx = 0usize;
    while let Some(mut rec) = parser.next_record_elems() {
        for elem_ref in rec.iter() {
            assert_elem_parity(idx, &owned_elems[idx], &elem_ref);
            if idx == 0 {
                let segs: Vec<(AsPathSegmentType, Vec<Asn>)> = elem_ref
                    .as_path()
                    .segments()
                    .map(|s| (s.segment_type(), s.asns().collect()))
                    .collect();
                assert_eq!(
                    segs,
                    vec![
                        (
                            AsPathSegmentType::ConfedSequence,
                            vec![Asn::new_32bit(65010)]
                        ),
                        (
                            AsPathSegmentType::AsSequence,
                            vec![
                                Asn::new_32bit(64501),
                                Asn::new_32bit(3356),
                                Asn::new_32bit(174),
                            ]
                        ),
                        (
                            AsPathSegmentType::AsSet,
                            vec![
                                Asn::new_32bit(13335),
                                Asn::new_32bit(15169),
                                Asn::new_32bit(8075),
                            ]
                        ),
                    ]
                );
                assert_eq!(elem_ref.communities().plain_words().len(), 4);
                assert_eq!(elem_ref.communities().extended_words().len(), 20);
                assert_eq!(elem_ref.communities().large_words().len(), 6);
            }
            idx += 1;
        }
    }
    assert_eq!(idx, owned_elems.len());
}

#[test]
fn malformed_and_truncated_attributes_match_into_elem_iter() {
    let mut peer_table = PeerIndexTable::default();
    let p0 = peer_table
        .add_peer(Peer::new(
            Ipv4Addr::new(192, 0, 2, 1),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            Asn::new_32bit(64501),
        ))
        .unwrap();
    let pit_record = MrtRecord {
        common_header: CommonHeader {
            timestamp: 1_700_000_000,
            microsecond_timestamp: None,
            entry_type: EntryType::TABLE_DUMP_V2,
            entry_subtype: TableDumpV2Type::PeerIndexTable as u16,
            length: 0,
        },
        message: MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(peer_table)),
    };

    // Hand-craft a RIB entry with:
    // 1. Valid ORIGIN (IGP)
    // 2. Malformed AS_PATH (invalid segment type 9)
    // 3. Malformed COMMUNITIES (length 5, not a multiple of 4)
    // 4. Valid MED (777)
    // 5. Truncated trailing attribute (declares length 50 with 2 bytes left)
    let mut attr_bytes = BytesMut::new();
    attr_bytes.put_slice(&[
        AttrFlags::TRANSITIVE.bits(),
        u8::from(AttrType::ORIGIN),
        1,
        0,
    ]);
    attr_bytes.put_slice(&[
        AttrFlags::TRANSITIVE.bits(),
        u8::from(AttrType::AS_PATH),
        6,
        9, // invalid segment type
        1,
        0,
        0,
        0,
        1,
    ]);
    attr_bytes.put_slice(&[
        (AttrFlags::OPTIONAL | AttrFlags::TRANSITIVE).bits(),
        u8::from(AttrType::COMMUNITIES),
        5,
        1,
        2,
        3,
        4,
        5,
    ]);
    attr_bytes.put_slice(&[
        AttrFlags::OPTIONAL.bits(),
        u8::from(AttrType::MULTI_EXIT_DISCRIMINATOR),
        4,
        0,
        0,
        0x03,
        0x09,
    ]);
    attr_bytes.put_slice(&[
        (AttrFlags::OPTIONAL | AttrFlags::TRANSITIVE).bits(),
        u8::from(AttrType::LARGE_COMMUNITIES),
        50,
        0xAA,
        0xBB,
    ]);

    let mut rib_body = BytesMut::new();
    rib_body.put_u32(1); // seq
    rib_body.put_slice(&[24, 192, 0, 2]); // 192.0.2.0/24
    rib_body.put_u16(1); // 1 entry
    rib_body.put_u16(p0);
    rib_body.put_u32(1_700_000_010);
    rib_body.put_u16(attr_bytes.len() as u16);
    rib_body.put_slice(&attr_bytes);

    let rib_header = CommonHeader {
        timestamp: 1_700_000_010,
        microsecond_timestamp: None,
        entry_type: EntryType::TABLE_DUMP_V2,
        entry_subtype: TableDumpV2Type::RibIpv4Unicast as u16,
        length: rib_body.len() as u32,
    };

    let mut wire = pit_record.encode().unwrap().to_vec();
    wire.extend_from_slice(&rib_header.encode());
    wire.extend_from_slice(&rib_body);

    let owned: Vec<BgpElem> = BgpkitParser::from_reader(Cursor::new(wire.clone()))
        .into_elem_iter()
        .collect();
    assert_eq!(owned.len(), 1);

    let mut view_parser = BgpkitParser::from_reader(Cursor::new(wire));
    let mut rec = view_parser.next_record_elems().expect("one RIB record");
    let elem_ref = rec.iter().next().expect("one RIB entry");
    assert_elem_parity(0, &owned[0], &elem_ref);
    assert!(!elem_ref.as_path().is_present());
    assert!(elem_ref.communities().is_empty());
    assert_eq!(elem_ref.med(), Some(777));
    assert!(view_parser.next_record_elems().is_none());
}

#[test]
fn skips_non_rib_records_and_text_dumps() {
    // Updates file (BGP4MP) yields None.
    let mut updates_parser =
        BgpkitParser::new("tests/fixtures/ripe/rrc00/2000.03/updates.20000325.0345.gz").unwrap();
    assert!(updates_parser.next_record_elems().is_none());

    // Legacy TABLE_DUMP v1 file yields None.
    let mut v1_parser =
        BgpkitParser::new("tests/fixtures/ripe/rrc00/2000.01/bview.20000111.0032.gz").unwrap();
    assert!(v1_parser.next_record_elems().is_none());

    // Text-dump parser yields None.
    let text_dump = "BGP table version is 1, local router ID is 1.2.3.4, vrf id 0\n\
Default local pref 100, local AS 65001\n\n\
   Network          Next Hop            Metric LocPrf Weight Path\n\
*> 1.0.0.0/24       10.0.0.1                 0             0 13335 i\n";
    let mut text_parser = BgpkitParser::from_text_reader(text_dump.as_bytes()).unwrap();
    assert!(text_parser.next_record_elems().is_none());

    // Mixed stream: BGP4MP update before and after TABLE_DUMP_V2 RIB_AFI is skipped cleanly.
    let mut attrs = Attributes::default();
    attrs.add_attr(AttributeValue::Origin(Origin::IGP).into());
    attrs.add_attr(AttributeValue::AsPath(AsPath::from_sequence([65000])).into());
    attrs.add_attr(AttributeValue::NextHop(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).into());
    let bgp4mp = MrtRecord {
        common_header: CommonHeader {
            timestamp: 1_700_000_000,
            microsecond_timestamp: None,
            entry_type: EntryType::BGP4MP,
            entry_subtype: Bgp4MpType::MessageAs4 as u16,
            length: 0,
        },
        message: MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(Bgp4MpMessage {
            msg_type: Bgp4MpType::MessageAs4,
            peer_asn: Asn::new_32bit(65000),
            local_asn: Asn::new_32bit(65001),
            interface_index: 0,
            peer_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            bgp_message: BgpMessage::Update(BgpUpdateMessage {
                withdrawn_prefixes: vec![],
                attributes: attrs.clone(),
                announced_prefixes: vec![NetworkPrefix::from_str("198.51.100.0/24").unwrap()],
            }),
        })),
    };
    let td_v1 = MrtRecord {
        common_header: CommonHeader {
            timestamp: 1_700_000_000,
            microsecond_timestamp: None,
            entry_type: EntryType::TABLE_DUMP,
            entry_subtype: 1,
            length: 0,
        },
        message: MrtMessage::TableDumpMessage(TableDumpMessage {
            view_number: 0,
            sequence_number: 1,
            prefix: NetworkPrefix::from_str("198.51.100.0/24").unwrap(),
            status: 1,
            originated_time: 1_700_000_000,
            peer_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_asn: Asn::new_16bit(65000),
            attributes: attrs,
        }),
    };

    let mut mixed = bgp4mp.encode().unwrap().to_vec();
    mixed.extend_from_slice(&build_exhaustive_rib_stream());
    mixed.extend_from_slice(&td_v1.encode().unwrap());

    // The AS4 update and the RIB slice are both served; the legacy TABLE_DUMP v1 record is the
    // only one this path cannot read, and it is skipped with a warning.
    let mut mixed_parser = BgpkitParser::from_reader(Cursor::new(mixed));
    let mut total_elems = 0usize;
    while let Some(mut rec) = mixed_parser.next_record_elems() {
        total_elems += rec.iter().count();
    }
    assert_eq!(total_elems, 6);
}

/// A parser with filters must not fall through to this path: it would hand back unfiltered
/// elements to a caller that asked for a filter, which is silent divergence from every other
/// iterator in the crate.
#[test]
fn filtered_parser_refuses_the_borrowed_path() {
    // A local fixture: this path returns before reading a byte, so the file only has to exist.
    let fixture = "tests/fixtures/routeviews/bview.slice.gz";
    let mut parser = BgpkitParser::new(fixture)
        .expect("open RIB fixture")
        .add_filter("prefix", "10.0.0.0/8")
        .expect("valid filter");
    assert!(
        parser.next_record_elems().is_none(),
        "a filtered parser must not return unfiltered borrowed elements"
    );
}
