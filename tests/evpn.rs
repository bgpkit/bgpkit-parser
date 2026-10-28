//! EVPN decoding against a capture from a real FRR fabric.
//!
//! `fixtures/evpn/mac-move.bmp` is 19 BMP messages exported by an FRR 10.7.1
//! route reflector in the `evpn-mac-mobility` lab (BGPKIT Labs, `topologies/`):
//! an init message, three peer-up messages and 15 route-monitoring messages,
//! captured with `bmp monitor l2vpn evpn post-policy`.
//!
//! Two FRR leaves advertised a MAC for the same VNI 100. One host then started
//! sending frames with the other host's MAC address, so both leaves kept
//! re-advertising it with an incremented MAC Mobility sequence number: 1, 2, 3
//! and 4, each round preceded by a withdrawal of the previous claim.

use bgpkit_parser::models::*;
use bgpkit_parser::parse_bmp_msg;
use bgpkit_parser::parser::bmp::messages::BmpMessageBody;
use bytes::Bytes;

const CAPTURE: &[u8] = include_bytes!("fixtures/evpn/mac-move.bmp");

/// MAC that moved between the two leaves (the address of the host behind leaf1).
const MOVED_MAC: [u8; 6] = [0xaa, 0xc1, 0xab, 0x73, 0x01, 0x4d];

struct Parsed {
    init: usize,
    peer_up: usize,
    announces: Vec<(BgpUpdateMessage, std::net::IpAddr)>,
    withdrawals: Vec<BgpUpdateMessage>,
}

fn parse_capture() -> Parsed {
    let mut data = Bytes::from_static(CAPTURE);
    let mut parsed = Parsed {
        init: 0,
        peer_up: 0,
        announces: Vec::new(),
        withdrawals: Vec::new(),
    };

    while !data.is_empty() {
        let message = parse_bmp_msg(&mut data).expect("every message in the capture parses");
        match message.message_body {
            BmpMessageBody::InitiationMessage(_) => parsed.init += 1,
            BmpMessageBody::PeerUpNotification(_) => parsed.peer_up += 1,
            BmpMessageBody::RouteMonitoring(monitoring) => {
                let BgpMessage::Update(update) = monitoring.bgp_message else {
                    continue;
                };
                let peer = message
                    .per_peer_header
                    .expect("route monitoring carries a per-peer header")
                    .peer_ip;
                if update
                    .attributes
                    .iter()
                    .any(|attribute| matches!(attribute, AttributeValue::MpReachNlri(_)))
                {
                    parsed.announces.push((update, peer));
                } else {
                    parsed.withdrawals.push(update);
                }
            }
            _ => {}
        }
    }

    parsed
}

fn evpn_nlri(update: &BgpUpdateMessage, reachable: bool) -> &Vec<EvpnNlri> {
    update
        .attributes
        .iter()
        .find_map(|attribute| match (attribute, reachable) {
            (AttributeValue::MpReachNlri(nlri), true) => Some(nlri),
            (AttributeValue::MpUnreachNlri(nlri), false) => Some(nlri),
            _ => None,
        })
        .and_then(|nlri| nlri.evpn_nlris.as_ref())
        .expect("EVPN NLRI")
}

fn mac_ip_route(nlri: &EvpnNlri) -> &MacIpAdvertisement {
    match &nlri.payload {
        EvpnRoutePayload::MacIpAdvertisement(route) => route,
        other => panic!("expected a MAC/IP advertisement, got {other:?}"),
    }
}

fn sequence_numbers(update: &BgpUpdateMessage) -> Vec<u32> {
    update
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AttributeValue::ExtendedCommunities(communities) => Some(
                communities
                    .iter()
                    .filter_map(|community| match community {
                        ExtendedCommunity::MacMobility(mobility) => {
                            assert!(!mobility.sticky, "the capture carries no sticky MAC");
                            Some(mobility.sequence)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

#[test]
fn capture_decodes_into_typed_evpn_records() {
    let parsed = parse_capture();

    assert_eq!(parsed.init, 1, "one BMP init message");
    assert_eq!(parsed.peer_up, 3, "three peer-up messages");
    assert_eq!(parsed.announces.len(), 8, "eight announcements");
    assert_eq!(parsed.withdrawals.len(), 7, "seven withdrawals");
}

#[test]
fn the_fabric_starts_with_one_mac_ip_and_one_implicit_route_per_leaf() {
    let parsed = parse_capture();
    let initial = &parsed.announces[..4];

    let macs: Vec<[u8; 6]> = initial
        .iter()
        .filter_map(|(update, _)| {
            evpn_nlri(update, true)
                .iter()
                .find_map(|route| match &route.payload {
                    EvpnRoutePayload::MacIpAdvertisement(body) => Some(body.mac),
                    _ => None,
                })
        })
        .collect();
    assert_eq!(macs.len(), 2, "each leaf advertises its own host");
    assert!(macs.contains(&MOVED_MAC));
    assert!(
        initial
            .iter()
            .all(|(update, _)| sequence_numbers(update).is_empty()),
        "the first advertisement of a MAC carries no MAC Mobility community"
    );

    let imet: Vec<std::net::IpAddr> = initial
        .iter()
        .filter_map(|(update, _)| {
            evpn_nlri(update, true)
                .iter()
                .find_map(|route| match &route.payload {
                    EvpnRoutePayload::InclusiveMulticast(body) => Some(body.originating_router_ip),
                    _ => None,
                })
        })
        .collect();
    assert_eq!(
        imet,
        vec![
            "10.10.0.11".parse::<std::net::IpAddr>().unwrap(),
            "10.10.0.12".parse().unwrap()
        ],
        "one IMET route each"
    );
}

#[test]
fn the_relearn_war_counts_up_in_the_mac_mobility_community() {
    let parsed = parse_capture();
    let war: Vec<_> = parsed
        .announces
        .iter()
        .filter(|(update, _)| !sequence_numbers(update).is_empty())
        .collect();

    assert_eq!(war.len(), 4, "four rounds of the war");
    let sequences: Vec<u32> = war
        .iter()
        .flat_map(|(update, _)| sequence_numbers(update))
        .collect();
    assert_eq!(sequences, vec![1, 2, 3, 4], "one increment per round");

    // The originator alternates: the challenger claims, the holder re-asserts.
    let peers: Vec<std::net::IpAddr> = war.iter().map(|(_, peer)| *peer).collect();
    assert_eq!(
        peers,
        vec![
            "10.10.0.12".parse::<std::net::IpAddr>().unwrap(),
            "10.10.0.11".parse().unwrap(),
            "10.10.0.12".parse().unwrap(),
            "10.10.0.11".parse().unwrap(),
        ]
    );
}

#[test]
fn every_route_names_its_own_leaf_as_rd_and_next_hop() {
    let parsed = parse_capture();

    for (update, peer) in &parsed.announces {
        for route in evpn_nlri(update, true) {
            let EvpnRoutePayload::MacIpAdvertisement(body) = &route.payload else {
                continue;
            };

            assert_eq!(body.esi, [0u8; 10], "single-homed host, ESI 0");
            assert_eq!(body.label2, None, "MAC-only route, no IP-VRF label");
            assert_eq!(route.path_id, None, "the lab session does not run ADD-PATH");
            assert_eq!(body.ethernet_tag_id, 0);
            assert_eq!(body.ip, None, "MAC-only advertisement, IP length 0");
            assert_eq!(body.label, 100, "VNI 100");

            // The route distinguisher is derived from the advertising VTEP:
            // type 1 (IP-based), the leaf's underlay address, local part 2.
            let rd = route.route_distinguisher.0;
            assert_eq!(rd[0..2], [0x00, 0x01], "RD type 1");
            let rd_ip = std::net::Ipv4Addr::new(rd[2], rd[3], rd[4], rd[5]);
            assert_eq!(std::net::IpAddr::V4(rd_ip), *peer);
            assert_eq!(rd[6..8], [0x00, 0x02]);

            // The next hop is the VTEP of the advertising leaf.
            let next_hop = update
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    AttributeValue::MpReachNlri(nlri) => Some(nlri.next_hop),
                    _ => None,
                })
                .flatten()
                .expect("reachable NLRI has a next hop");
            assert_eq!(next_hop.global_addr(), *peer);
        }
    }
}

#[test]
fn withdrawals_and_end_of_rib_are_typed() {
    let parsed = parse_capture();

    // Two end-of-rib markers arrive right after the peer-up messages: an
    // MP_UNREACH carrying the EVPN family and no NLRI.
    let empty = parsed
        .withdrawals
        .iter()
        .filter(|update| evpn_nlri(update, false).is_empty())
        .count();
    assert_eq!(empty, 2, "one end-of-rib marker per peer");

    // The other five withdraw a MAC/IP route, the moved MAC among them.
    let mut withdrawn_macs = Vec::new();
    for update in &parsed.withdrawals {
        for route in evpn_nlri(update, false) {
            assert_eq!(route.route_type, EvpnRouteType::MacIpAdvertisement);
            withdrawn_macs.push(mac_ip_route(route).mac);
        }
    }
    assert_eq!(withdrawn_macs.len(), 5);
    assert!(
        withdrawn_macs.contains(&MOVED_MAC),
        "the war ends with a withdrawal of the moved MAC"
    );
}
