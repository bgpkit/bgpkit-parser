//! Example: decode EVPN routes from a BMP capture.
//!
//! EVPN (AFI 25 / SAFI 70) carries MAC learning in BGP, so the route
//! reflector's BMP feed is the only place where a MAC move is recorded as a
//! route. This example walks a capture and prints one line per EVPN NLRI:
//! route type, route distinguisher, the MAC or prefix it describes, the VTEP
//! that advertised it, and the MAC Mobility sequence number when one is
//! present.
//!
//! The default input is `tests/fixtures/evpn/mac-move.bmp`, captured from the
//! two-leaf FRR fabric in the BGPKIT Labs `evpn-mac-mobility` topology. One host
//! sent frames with another host's MAC address, so both leaves kept
//! re-advertising that MAC with an incremented MAC Mobility sequence number:
//! the same MAC appears from two VTEPs, sequence 1 then 2 then 3 then 4.
//!
//! ## Usage
//!
//! ```sh
//! cargo run --example evpn_mac_mobility
//! cargo run --example evpn_mac_mobility -- /path/to/capture.bmp
//! ```

use bgpkit_parser::models::*;
use bgpkit_parser::parse_bmp_msg;
use bgpkit_parser::parser::bmp::messages::BmpMessageBody;
use bytes::{Buf, Bytes};
use std::error::Error;

const DEFAULT_CAPTURE: &str = "tests/fixtures/evpn/mac-move.bmp";

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_CAPTURE.to_string());
    let mut data = Bytes::from(std::fs::read(&path)?);
    println!("capture: {path}");

    let mut routes = 0usize;

    while data.remaining() > 0 {
        let message = parse_bmp_msg(&mut data)?;
        let BmpMessageBody::RouteMonitoring(monitoring) = &message.message_body else {
            continue;
        };
        let BgpMessage::Update(update) = &monitoring.bgp_message else {
            continue;
        };
        let peer = message
            .per_peer_header
            .map(|header| header.peer_ip.to_string())
            .unwrap_or_else(|| "-".to_string());

        for attribute in update.attributes.iter() {
            let (nlri, announced) = match attribute {
                AttributeValue::MpReachNlri(nlri) => (nlri, true),
                AttributeValue::MpUnreachNlri(nlri) => (nlri, false),
                _ => continue,
            };
            let Some(evpn_nlris) = &nlri.evpn_nlris else {
                continue;
            };

            let next_hop = nlri
                .next_hop
                .map(|next_hop| next_hop.global_addr().to_string())
                .unwrap_or_else(|| "-".to_string());
            let sequence = mac_mobility_sequence(update);

            for route in evpn_nlris {
                routes += 1;
                println!(
                    "{} vt={:<15} peer={:<15} rd={:<22} {}{}",
                    if announced { "ADD " } else { "DEL " },
                    next_hop,
                    peer,
                    route.route_distinguisher,
                    describe(route),
                    sequence
                        .map(|sequence| format!(" mm-seq={sequence}"))
                        .unwrap_or_default(),
                );
            }
        }
    }

    println!("{routes} EVPN routes");
    Ok(())
}

/// One line per route type: whatever an operator would look at first.
fn describe(route: &EvpnNlri) -> String {
    let route_type = u8::from(route.route_type);
    match &route.payload {
        EvpnRoutePayload::MacIpAdvertisement(body) => format!(
            "[{route_type}] mac={} ip={} eth-tag={} label={}",
            format_mac(&body.mac),
            body.ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "-".to_string()),
            body.ethernet_tag_id,
            body.raw_label,
        ),
        EvpnRoutePayload::InclusiveMulticast(body) => format!(
            "[{route_type}] originator={} eth-tag={}",
            body.originating_router_ip, body.ethernet_tag_id,
        ),
        EvpnRoutePayload::IpPrefix(body) => format!(
            "[{route_type}] prefix={} gateway={} label={}",
            body.ip_prefix, body.gateway_ip, body.raw_label,
        ),
        EvpnRoutePayload::Raw(octets) => {
            format!(
                "[{route_type}] {} raw octets (route type not decoded)",
                octets.len()
            )
        }
    }
}

fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The MAC Mobility sequence number carried by the update, if any - RFC 7432 §7.7.
fn mac_mobility_sequence(update: &BgpUpdateMessage) -> Option<u32> {
    update
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AttributeValue::ExtendedCommunities(communities) => {
                communities.iter().find_map(|community| match community {
                    ExtendedCommunity::MacMobility(mobility) => Some(mobility.sequence),
                    _ => None,
                })
            }
            _ => None,
        })
}
