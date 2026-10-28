use crate::encoder::sink::put_u8_len_slice;
use crate::error::EncodingError;
use crate::models::*;
use crate::parser::bgp::attributes::attr_03_next_hop::{encode_mp_next_hop, parse_mp_next_hop};
use crate::parser::bgp::attributes::attr_29_linkstate::parse_link_state_nlri;
use crate::parser::{parse_nlri_list, ReadUtils};
use crate::ParserError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::IpAddr;

use log::warn;

///
/// <https://datatracker.ietf.org/doc/html/rfc4760#section-3>
/// The attribute is encoded as shown below:
/// +---------------------------------------------------------+
/// | Address Family Identifier (2 octets)                    |
/// +---------------------------------------------------------+
/// | Subsequent Address Family Identifier (1 octet)          |
/// +---------------------------------------------------------+
/// | Length of Next Hop Network Address (1 octet)            |
/// +---------------------------------------------------------+
/// | Network Address of Next Hop (variable)                  |
/// +---------------------------------------------------------+
/// | Reserved (1 octet)                                      |
/// +---------------------------------------------------------+
/// | Network Layer Reachability Information (variable)       |
/// +---------------------------------------------------------+
pub fn parse_nlri(
    mut input: Bytes,
    afi: &Option<Afi>,
    safi: &Option<Safi>,
    prefixes: &Option<&[NetworkPrefix]>,
    reachable: bool,        // whether the NLRI is announcements or withdrawals
    additional_paths: bool, // whether the NLRI is part of an additional paths message
) -> Result<AttributeValue, ParserError> {
    let first_byte_zero = input.first().map(|b| *b == 0).unwrap_or(false);

    // read address family
    let afi = match afi {
        Some(afi) => {
            if first_byte_zero {
                input.read_afi()?
            } else {
                afi.to_owned()
            }
        }
        None => input.read_afi()?,
    };
    let safi = match safi {
        Some(safi) => {
            if first_byte_zero {
                input.read_safi()?
            } else {
                safi.to_owned()
            }
        }
        None => input.read_safi()?,
    };

    let mut next_hop = None;
    if reachable {
        let next_hop_length = input.read_u8()? as usize;
        input.has_n_remaining(next_hop_length)?;
        let next_hop_bytes = input.split_to(next_hop_length);
        next_hop = parse_mp_next_hop(next_hop_bytes)?;
    }

    // Handle different NLRI types based on AFI/SAFI
    let (prefixes, labeled_prefixes, link_state_nlris, evpn_nlris) =
        if afi == Afi::L2vpn && safi == Safi::Evpn {
            // EVPN NLRI - RFC 7432. Reachable NLRI carry the reserved octet
            // after the next hop, exactly like the IP families.
            if reachable && input.read_u8()? != 0 {
                warn!("NLRI reserved byte not 0 (parsing EVPN NLRI)");
            }
            let nlris = parse_evpn_nlri(&mut input, additional_paths)?;
            (Vec::new(), None, None, Some(nlris))
        } else if afi == Afi::L2vpn || safi == Safi::Evpn {
            // L2VPN with another SAFI, or EVPN with another AFI: not a family we
            // can interpret, and not one to hand to the IP-prefix parser either.
            return Err(ParserError::Unsupported(format!(
                "unsupported address family combination {afi:?}/{safi:?}"
            )));
        } else if afi == Afi::LinkState && (safi == Safi::LinkState || safi == Safi::LinkStateVpn) {
            // Parse Link-State NLRI
            if reachable {
                // skip reserved byte for reachable NRLI
                if input.read_u8()? != 0 {
                    warn!("NLRI reserved byte not 0 (parsing NLRI Link-State)");
                }
            }
            let ls_nlri = parse_link_state_nlri(input, afi, safi, next_hop, reachable)?;
            let link_state_list = ls_nlri.link_state_nlris;
            (Vec::new(), None, link_state_list, None)
        } else if safi == Safi::MplsLabel {
            // Parse MPLS-labeled NLRI (RFC 3107/8277)
            // Use MultiLabel mode as default since it handles both single and multiple labels
            // SingleLabel mode would fail on multi-label data due to prefix_bits validation
            let config = LabeledNlriConfig {
                add_path: additional_paths,
                mode: LabeledNlriMode::MultiLabel, // Handles both single and multiple labels
                max_labels: 16,
                peer_max_labels: None,
            };

            if reachable {
                // Parse labeled NLRI (announcements)
                if input.read_u8()? != 0 {
                    warn!("NLRI reserved byte not 0 (parsing MPLS-labeled NLRI)");
                }
                let labeled = parse_labeled_nlri(&mut input, afi, &config)?;
                (Vec::new(), Some(labeled), None, None)
            } else {
                // Parse labeled withdrawal (withdrawals use plain prefixes per RFC 8277 §2.4)
                let prefixes = parse_labeled_withdrawal_nlri(&mut input, afi, &config)?;
                (prefixes, None, None, None)
            }
        } else {
            // Parse traditional IP prefixes
            let prefixes = match prefixes {
                Some(pfxs) => {
                    // skip parsing prefixes: https://datatracker.ietf.org/doc/html/rfc6396#section-4.3.4
                    if first_byte_zero {
                        if reachable {
                            // skip reserved byte for reachable NRLI
                            if input.read_u8()? != 0 {
                                warn!("NLRI reserved byte not 0 (parsing NLRI prefixes)");
                            }
                        }
                        parse_nlri_list(input, additional_paths, &afi)?
                    } else {
                        pfxs.to_vec()
                    }
                }
                None => {
                    if reachable {
                        // skip reserved byte for reachable NRLI
                        if input.read_u8()? != 0 {
                            warn!("NLRI reserved byte not 0 (parsing NLRI prefixes)");
                        }
                    }
                    parse_nlri_list(input, additional_paths, &afi)?
                }
            };
            (prefixes, None, None, None)
        };

    let nlri = Nlri {
        afi,
        safi,
        next_hop,
        prefixes,
        labeled_prefixes,
        link_state_nlris,
        flowspec_nlris: None,
        evpn_nlris,
    };

    match reachable {
        true => Ok(AttributeValue::MpReachNlri(nlri)),
        false => Ok(AttributeValue::MpUnreachNlri(nlri)),
    }
}

/// Parse a sequence of EVPN NLRI entries - RFC 7432 §7.
///
/// Every entry is a route type octet, a length octet, an 8-octet route
/// distinguisher and a route-type-specific body. With ADD-PATH (RFC 7911) a
/// 4-octet path identifier precedes each entry; the length excludes it.
fn parse_evpn_nlri(
    input: &mut Bytes,
    additional_paths: bool,
) -> Result<Vec<EvpnNlri>, ParserError> {
    let mut nlris = Vec::new();

    while input.remaining() > 0 {
        let path_id = if additional_paths {
            Some(input.read_u32()?)
        } else {
            None
        };

        let route_type = EvpnRouteType::from(input.read_u8()?);
        let body_len = input.read_u8()? as usize;
        input.has_n_remaining(body_len)?;
        let mut body = input.split_to(body_len);

        // The route distinguisher is common to every EVPN route type.
        if body.remaining() < 8 {
            return Err(ParserError::ParseError(
                "EVPN NLRI shorter than a route distinguisher".to_string(),
            ));
        }
        let mut rd = [0u8; 8];
        body.copy_to_slice(&mut rd);
        let route_distinguisher = RouteDistinguisher(rd);

        let payload = match route_type {
            EvpnRouteType::MacIpAdvertisement => {
                EvpnRoutePayload::MacIpAdvertisement(parse_mac_ip_advertisement(&mut body)?)
            }
            EvpnRouteType::InclusiveMulticastEthernetTag => {
                EvpnRoutePayload::InclusiveMulticast(parse_inclusive_multicast(&mut body)?)
            }
            EvpnRouteType::IpPrefix => {
                EvpnRoutePayload::IpPrefix(parse_ip_prefix_route(&mut body)?)
            }
            // Route types 1 and 4 are accepted but not decoded yet; keep the
            // octets so nothing is lost and the type stays visible.
            _ => EvpnRoutePayload::Raw(body.to_vec()),
        };

        nlris.push(EvpnNlri {
            path_id,
            route_type,
            route_distinguisher,
            payload,
        });
    }

    Ok(nlris)
}

/// MAC/IP Advertisement route body - RFC 7432 §7.2.
fn parse_mac_ip_advertisement(body: &mut Bytes) -> Result<MacIpAdvertisement, ParserError> {
    // Fixed part, with the route distinguisher already consumed:
    // ESI (10) | Ethernet tag (4) | MAC length (1) | MAC (6) | IP length (1) |
    // Label1 (3).
    if body.remaining() < 10 + 4 + 1 + 6 + 1 + 3 {
        return Err(ParserError::ParseError(
            "EVPN type 2 NLRI too short for the fixed fields".to_string(),
        ));
    }

    let mut esi = [0u8; 10];
    body.copy_to_slice(&mut esi);
    let ethernet_tag_id = body.read_u32()?;

    let mac_len = body.read_u8()?;
    if mac_len != 48 {
        return Err(ParserError::ParseError(format!(
            "EVPN type 2 MAC address length {mac_len} is not 48"
        )));
    }
    let mut mac = [0u8; 6];
    body.copy_to_slice(&mut mac);

    let ip_len = body.read_u8()?;
    let ip = match ip_len {
        0 => None,
        32 => Some(IpAddr::V4(body.read_ipv4_address()?)),
        128 => Some(IpAddr::V6(body.read_ipv6_address()?)),
        other => {
            return Err(ParserError::ParseError(format!(
                "EVPN type 2 IP address length {other} is not 0, 32 or 128"
            )))
        }
    };

    let raw_label = read_three_octet_label(body)?;

    // Label2 is optional: it appears when the route is used for IP-VRF
    // forwarding - RFC 7432 §7.2.
    let raw_label2 = if body.remaining() == 3 {
        Some(read_three_octet_label(body)?)
    } else {
        None
    };

    if body.remaining() != 0 {
        return Err(ParserError::ParseError(format!(
            "EVPN type 2 NLRI has {} trailing octets",
            body.remaining()
        )));
    }

    Ok(MacIpAdvertisement {
        esi,
        ethernet_tag_id,
        mac,
        ip,
        raw_label,
        raw_label2,
    })
}

/// Inclusive Multicast Ethernet Tag route body - RFC 7432 §7.3.
fn parse_inclusive_multicast(body: &mut Bytes) -> Result<InclusiveMulticastRoute, ParserError> {
    if body.remaining() < 4 + 1 {
        return Err(ParserError::ParseError(
            "EVPN type 3 NLRI too short".to_string(),
        ));
    }

    let ethernet_tag_id = body.read_u32()?;
    let ip_len = body.read_u8()?;
    let originating_router_ip = match ip_len {
        32 => IpAddr::V4(body.read_ipv4_address()?),
        128 => IpAddr::V6(body.read_ipv6_address()?),
        other => {
            return Err(ParserError::ParseError(format!(
                "EVPN type 3 originating router IP length {other} is not 32 or 128"
            )))
        }
    };

    if body.remaining() != 0 {
        return Err(ParserError::ParseError(format!(
            "EVPN type 3 NLRI has {} trailing octets",
            body.remaining()
        )));
    }

    Ok(InclusiveMulticastRoute {
        ethernet_tag_id,
        originating_router_ip,
    })
}

/// IP Prefix route body - RFC 9136 §3.1.
///
/// Layout, with the route distinguisher already consumed:
/// `ESI (10) | Ethernet tag (4) | IP prefix length (1) | IP prefix (4 or 16) |
/// GW IP address (4 or 16) | MPLS label (3)`. The NLRI length identifies the
/// address family: 34 octets for IPv4 and 58 for IPv6, which leaves 26 or 50
/// here. The prefix and gateway fields are full width, so a /32 IPv6 prefix is
/// still a 16-octet field.
fn parse_ip_prefix_route(body: &mut Bytes) -> Result<IpPrefixRoute, ParserError> {
    let is_ipv6 = match body.len() {
        26 => false,
        50 => true,
        other => {
            return Err(ParserError::ParseError(format!(
                "EVPN type 5 payload is {other} octets after the route distinguisher, not 26 (IPv4) or 50 (IPv6)"
            )))
        }
    };

    let mut esi = [0u8; 10];
    body.copy_to_slice(&mut esi);
    let ethernet_tag_id = body.read_u32()?;

    let prefix_len = body.read_u8()?;
    let max_len = if is_ipv6 { 128 } else { 32 };
    if prefix_len > max_len {
        return Err(ParserError::ParseError(format!(
            "EVPN type 5 prefix length {prefix_len} is invalid for an {is_ipv6} prefix"
        )));
    }

    let ip_prefix = if is_ipv6 {
        let addr = body.read_ipv6_address()?;
        ipnet::IpNet::new(addr.into(), prefix_len)
    } else {
        let addr = body.read_ipv4_address()?;
        ipnet::IpNet::new(addr.into(), prefix_len)
    }
    .map_err(|e| ParserError::ParseError(format!("EVPN type 5 invalid prefix: {e}")))?;

    let gateway_ip = if is_ipv6 {
        IpAddr::V6(body.read_ipv6_address()?)
    } else {
        IpAddr::V4(body.read_ipv4_address()?)
    };
    let raw_label = read_three_octet_label(body)?;

    if body.remaining() != 0 {
        return Err(ParserError::ParseError(format!(
            "EVPN type 5 NLRI has {} trailing octets",
            body.remaining()
        )));
    }

    Ok(IpPrefixRoute {
        esi,
        ethernet_tag_id,
        ip_prefix,
        gateway_ip,
        raw_label,
    })
}

/// Encode the route-type-specific body of an EVPN NLRI - RFC 7432 §7.
///
/// The payload variant has to agree with the route type: the wire format has one
/// type octet and one body, so a mismatch would be published as a route of the
/// wrong kind.
fn encode_evpn_payload(route: &EvpnNlri) -> Result<Vec<u8>, EncodingError> {
    let payload = &route.payload;
    let expected = match payload {
        EvpnRoutePayload::MacIpAdvertisement(_) => EvpnRouteType::MacIpAdvertisement,
        EvpnRoutePayload::InclusiveMulticast(_) => EvpnRouteType::InclusiveMulticastEthernetTag,
        EvpnRoutePayload::IpPrefix(_) => EvpnRouteType::IpPrefix,
        EvpnRoutePayload::Raw(_) => route.route_type,
    };
    if expected != route.route_type {
        return Err(EncodingError::unencodable(
            "EVPN NLRI route type",
            format!(
                "route type {:?} does not match its {:?} payload",
                route.route_type, expected
            ),
        ));
    }

    let mut out = Vec::new();
    match payload {
        EvpnRoutePayload::MacIpAdvertisement(body) => {
            out.extend_from_slice(&body.esi);
            out.extend_from_slice(&body.ethernet_tag_id.to_be_bytes());
            out.push(48); // MAC address length
            out.extend_from_slice(&body.mac);
            match body.ip {
                None => out.push(0),
                Some(IpAddr::V4(ip)) => {
                    out.push(32);
                    out.extend_from_slice(&ip.octets());
                }
                Some(IpAddr::V6(ip)) => {
                    out.push(128);
                    out.extend_from_slice(&ip.octets());
                }
            }
            push_three_octet(&mut out, body.raw_label, "EVPN Label1")?;
            if let Some(label2) = body.raw_label2 {
                push_three_octet(&mut out, label2, "EVPN Label2")?;
            }
        }
        EvpnRoutePayload::InclusiveMulticast(body) => {
            out.extend_from_slice(&body.ethernet_tag_id.to_be_bytes());
            match body.originating_router_ip {
                IpAddr::V4(ip) => {
                    out.push(32);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(128);
                    out.extend_from_slice(&ip.octets());
                }
            }
        }
        EvpnRoutePayload::IpPrefix(body) => {
            out.extend_from_slice(&body.esi);
            out.extend_from_slice(&body.ethernet_tag_id.to_be_bytes());
            out.push(body.ip_prefix.prefix_len());
            match (&body.ip_prefix, body.gateway_ip) {
                (ipnet::IpNet::V4(net), IpAddr::V4(gateway)) => {
                    out.extend_from_slice(&net.addr().octets());
                    out.extend_from_slice(&gateway.octets());
                }
                (ipnet::IpNet::V6(net), IpAddr::V6(gateway)) => {
                    out.extend_from_slice(&net.addr().octets());
                    out.extend_from_slice(&gateway.octets());
                }
                _ => {
                    return Err(EncodingError::unencodable(
                        "EVPN IP prefix route",
                        "the prefix and the gateway address must be of the same family",
                    ))
                }
            }
            push_three_octet(&mut out, body.raw_label, "EVPN MPLS label")?;
        }
        // Undecoded route types are written back exactly as they were read.
        EvpnRoutePayload::Raw(bytes) => out.extend_from_slice(bytes),
    }
    Ok(out)
}

/// Append a value as the 3-octet label field EVPN uses.
fn push_three_octet(
    out: &mut Vec<u8>,
    value: u32,
    field: &'static str,
) -> Result<(), EncodingError> {
    if value > 0x00FF_FFFF {
        return Err(EncodingError::unencodable(
            field,
            format!("{value} does not fit 3 octets"),
        ));
    }
    out.extend_from_slice(&[(value >> 16) as u8, (value >> 8) as u8, value as u8]);
    Ok(())
}

/// Read the 3-octet label field shared by EVPN route types 2 and 5.
fn read_three_octet_label(body: &mut Bytes) -> Result<u32, ParserError> {
    body.has_n_remaining(3)?;
    let octets = body.split_to(3);
    Ok(u32::from_be_bytes([0, octets[0], octets[1], octets[2]]))
}

/// Encode NLRI attribute to wire format.
///
/// # Arguments
/// * `nlri` - The NLRI to encode
/// * `reachable` - Whether this is MP_REACH_NLRI (true) or MP_UNREACH_NLRI (false)
/// * `add_path` - Whether ADD-PATH capability was negotiated (RFC 7911). If true,
///   path_id will be encoded; if false, prefixes with path_id will cause an error.
pub fn encode_nlri(
    nlri: &Nlri,
    reachable: bool,
    add_path: bool,
    bytes: &mut BytesMut,
) -> Result<(), EncodingError> {
    // An EVPN MP_REACH always carries the VTEP as next hop, and an MP_UNREACH
    // never carries one. Either mismatch would produce a header a receiver
    // decodes into something else, so reject it before writing a byte.
    if nlri.afi == Afi::L2vpn {
        match (reachable, nlri.next_hop) {
            (true, None) => {
                return Err(EncodingError::unencodable(
                    "EVPN NLRI next hop",
                    "an EVPN announcement needs the originating VTEP as next hop",
                ))
            }
            (false, Some(_)) => {
                return Err(EncodingError::unencodable(
                    "EVPN NLRI next hop",
                    "an EVPN withdrawal carries no next hop",
                ))
            }
            _ => {}
        }
    }

    // encode address family
    bytes.put_u16(nlri.afi as u16);
    bytes.put_u8(nlri.safi as u8);

    if let Some(next_hop) = &nlri.next_hop {
        if !reachable {
            warn!("NLRI next hop should not be set for unreachable NLRI (encoding NLRI)");
        }
        // encode next hop (shared with the NEXT_HOP attribute encoder)
        let next_hop_bytes = encode_mp_next_hop(next_hop);
        // all next-hop encodings are fixed-size (4..=48 bytes), so this cannot fail
        put_u8_len_slice(bytes, "MP NLRI next hop length", &next_hop_bytes)?;
    }

    // EVPN NLRI - RFC 7432 §7: a sequence of route type, length, route
    // distinguisher and route-type-specific body.
    if nlri.afi == Afi::L2vpn && nlri.safi == Safi::Evpn {
        // RFC 4760 §3: the reserved octet precedes reachable NLRI.
        if reachable {
            bytes.put_u8(0);
        }
        for route in nlri.evpn_nlris.iter().flatten() {
            match (add_path, route.path_id) {
                (true, Some(path_id)) => bytes.put_u32(path_id),
                (true, None) => {
                    return Err(EncodingError::unencodable(
                        "EVPN NLRI path id",
                        "ADD-PATH is requested but the route carries no path identifier",
                    ))
                }
                (false, Some(_)) => {
                    return Err(EncodingError::unencodable(
                        "EVPN NLRI path id",
                        "the route carries a path identifier but ADD-PATH is not enabled",
                    ))
                }
                (false, None) => {}
            }
            let body = encode_evpn_payload(route)?;
            // The length covers the route distinguisher and the body, and
            // excludes the ADD-PATH identifier.
            let entry_len = 8 + body.len();
            if entry_len > u8::MAX as usize {
                return Err(EncodingError::unencodable(
                    "EVPN NLRI length",
                    format!("{entry_len} octets do not fit the 1-octet length field"),
                ));
            }
            bytes.put_u8(u8::from(route.route_type));
            bytes.put_u8(entry_len as u8);
            bytes.put_slice(&route.route_distinguisher.0);
            bytes.extend_from_slice(&body);
        }
    } else if nlri.afi == Afi::L2vpn {
        // L2VPN is only defined with the EVPN subsequent address family here.
        return Err(EncodingError::unencodable(
            "MP NLRI",
            "L2VPN NLRI require the EVPN subsequent address family",
        ));
    } else if nlri.safi == Safi::MplsLabel {
        // RFC 8277: Write reserved byte for reachable NLRI
        if reachable {
            bytes.put_u8(0);
        }
        if let Some(labeled_prefixes) = &nlri.labeled_prefixes {
            // Choose mode based on label count: SingleLabel for 1 label, MultiLabel for multiple
            for labeled in labeled_prefixes {
                let mode = if labeled.labels.len() <= 1 {
                    crate::models::LabeledNlriMode::SingleLabel
                } else {
                    crate::models::LabeledNlriMode::MultiLabel
                };

                let encoded = crate::models::encode_labeled_prefix(
                    labeled, mode, add_path, None, // peer_max_labels
                )
                .map_err(|e| {
                    EncodingError::unencodable("MP NLRI labeled prefix", format!("{e:?}"))
                })?;
                bytes.extend_from_slice(&encoded);
            }
        }
    } else if nlri.afi == Afi::LinkState {
        // RFC 7752: Write reserved byte for reachable Link-State NLRI
        if reachable {
            bytes.put_u8(0);
        }
        if let Some(link_state_nlris) = &nlri.link_state_nlris {
            // Encode Link-State NLRI entries
            for ls_nlri in link_state_nlris {
                // Encode each Link-State NLRI (this would need a proper implementation)
                // For now, we'll create a placeholder
                bytes.put_u16(ls_nlri.nlri_type as u16);
                bytes.put_u16(0); // Length placeholder - would need actual encoding
            }
        }
    } else {
        // For traditional IP NLRI, write reserved byte for reachable NLRI per RFC 4760
        if reachable {
            bytes.put_u8(0);
        }
        // NLRI for traditional IP prefixes
        for prefix in &nlri.prefixes {
            bytes.extend(prefix.encode());
        }
        // FlowSpec NLRI entries (RFC 8955); previously silently dropped on encode
        if let Some(flowspec_nlris) = &nlri.flowspec_nlris {
            for flowspec in flowspec_nlris {
                bytes.put_slice(&encode_flowspec_nlri(flowspec)?);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_parsing_nlri_simple() {
        let test_bytes = Bytes::from(vec![
            0x00, 0x01, // address family: IPv4
            0x01, // safi: unicast
            0x04, // next hop length: 4
            0xC0, 0x00, 0x02, 0x01, // next hop: 192.0.2.1
            0x00, // reserved
            // NLRI
            0x18, // 24 bits prefix length
            0xC0, 0x00, 0x02, // 192.0.2
        ]);
        let res = parse_nlri(test_bytes, &None, &None, &None, true, false);

        if let Ok(AttributeValue::MpReachNlri(nlri)) = res {
            assert_eq!(nlri.afi, Afi::Ipv4);
            assert_eq!(nlri.safi, Safi::Unicast);
            assert_eq!(
                nlri.next_hop,
                Some(NextHopAddress::Ipv4(
                    Ipv4Addr::from_str("192.0.2.1").unwrap()
                ))
            );
            assert_eq!(
                nlri.prefixes,
                vec![NetworkPrefix::from_str("192.0.2.0/24").unwrap()]
            );
        }
    }

    #[test]
    fn test_parsing_nlri_passed_in_afi() {
        let test_bytes = Bytes::from(vec![
            0x00, 0x01, // address family: IPv4
            0x01, // safi: unicast
            0x04, // next hop length: 4
            0xC0, 0x00, 0x02, 0x01, // next hop: 192.0.2.1
            0x00, // reserved
            // NLRI
            0x18, // 24 bits prefix length
            0xC0, 0x00, 0x02, // 192.0.2
        ]);
        let res = parse_nlri(
            test_bytes,
            &Some(Afi::Ipv4),
            &Some(Safi::Unicast),
            &None,
            true,
            false,
        );

        if let Ok(AttributeValue::MpReachNlri(nlri)) = res {
            assert_eq!(nlri.afi, Afi::Ipv4);
            assert_eq!(nlri.safi, Safi::Unicast);
            assert_eq!(
                nlri.next_hop,
                Some(NextHopAddress::Ipv4(
                    Ipv4Addr::from_str("192.0.2.1").unwrap()
                ))
            );
            assert_eq!(
                nlri.prefixes,
                vec![NetworkPrefix::from_str("192.0.2.0/24").unwrap()]
            );
        }
    }

    #[test]
    fn test_parsing_nlri_errors() {
        // wrong next hop
        let test_bytes = Bytes::from(vec![
            0x00, 0x01, // address family: IPv4
            0x01, // safi: unicast
            0x04, // next hop length: 4
            0xC0, 0x00, 0x02, // next hop: 192.0.2.??
            0x00, // reserved
            // NLRI
            0x18, // 24 bits prefix length
            0xC0, 0x00, 0x02, // 192.0.2
        ]);
        let res = parse_nlri(
            test_bytes,
            &Some(Afi::Ipv4),
            &Some(Safi::Unicast),
            &None,
            true,
            false,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_parsing_nlri_add_path() {
        let test_bytes = Bytes::from(vec![
            0x00, 0x01, // address family: IPv4
            0x01, // safi: unicast
            0x04, // next hop length: 4
            0xC0, 0x00, 0x02, 0x01, // next hop: 192.0.2.1
            0x00, // reserved
            // NLRI
            0x00, 0x00, 0x00, 0x7B, // path_id: 123
            0x18, // 24 bits prefix length
            0xC0, 0x00, 0x02, // 192.0.2
        ]);
        let res = parse_nlri(test_bytes, &None, &None, &None, true, true);

        if let Ok(AttributeValue::MpReachNlri(nlri)) = res {
            assert_eq!(nlri.afi, Afi::Ipv4);
            assert_eq!(nlri.safi, Safi::Unicast);
            assert_eq!(
                nlri.next_hop,
                Some(NextHopAddress::Ipv4(
                    Ipv4Addr::from_str("192.0.2.1").unwrap()
                ))
            );
            let prefix = NetworkPrefix::new(IpNet::from_str("192.0.2.0/24").unwrap(), Some(123));
            assert_eq!(nlri.prefixes[0], prefix);
            assert_eq!(nlri.prefixes[0].path_id, prefix.path_id);
        } else {
            panic!("Unexpected result: {res:?}");
        }
    }

    #[test]
    fn test_encode_nlri() {
        let nlri = Nlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: Some(NextHopAddress::Ipv4(
                Ipv4Addr::from_str("10.0.0.1").unwrap(),
            )),
            prefixes: vec![NetworkPrefix {
                prefix: IpNet::from_str("192.0.1.0/24").unwrap(),
                path_id: None,
            }],
            labeled_prefixes: None,
            link_state_nlris: None,
            flowspec_nlris: None,
            evpn_nlris: None,
        };
        let mut buf = BytesMut::new();
        encode_nlri(&nlri, true, false, &mut buf).unwrap();
        let bytes = buf.freeze();
        assert_eq!(
            bytes,
            Bytes::from(vec![
                0x00, 0x01, // address family: IPv4
                0x01, // safi: unicast
                0x04, // next hop length: 4
                0x0A, 0x00, 0x00, 0x01, // next hop:
                0x00, // reserved
                // NLRI
                0x18, // 24 bits prefix length
                0xC0, 0x00, 0x01, // 192.0.1
            ])
        );
        let parsed_nlri = parse_nlri(bytes, &None, &None, &None, true, false).unwrap();
        assert_eq!(parsed_nlri, AttributeValue::MpReachNlri(nlri));

        let nlri = Nlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: Some(NextHopAddress::Ipv4(
                Ipv4Addr::from_str("10.0.0.1").unwrap(),
            )),
            prefixes: vec![NetworkPrefix {
                prefix: IpNet::from_str("192.0.1.0/24").unwrap(),
                path_id: Some(123),
            }],
            labeled_prefixes: None,
            link_state_nlris: None,
            flowspec_nlris: None,
            evpn_nlris: None,
        };
        let mut buf = BytesMut::new();
        encode_nlri(&nlri, true, true, &mut buf).unwrap();
        let bytes = buf.freeze();
        assert_eq!(
            bytes,
            Bytes::from(vec![
                0x00, 0x01, // address family: IPv4
                0x01, // safi: unicast
                0x04, // next hop length: 4
                0x0A, 0x00, 0x00, 0x01, // next hop:
                0x00, // reserved
                // NLRI
                0x00, 0x00, 0x00, 0x7B, // path_id: 123
                0x18, // 24 bits prefix length
                0xC0, 0x00, 0x01, // 192.0.1
            ])
        );
    }

    #[test]
    fn test_parsing_unreachable_nlri() {
        // Test unreachable NLRI (withdrawals)
        let test_bytes = Bytes::from(vec![
            0x00, 0x01, // address family: IPv4
            0x01, // safi: unicast
            // No next hop for unreachable NLRI
            // No reserved byte for unreachable NLRI
            // NLRI
            0x18, // 24 bits prefix length
            0xC0, 0x00, 0x02, // 192.0.2
        ]);
        let res = parse_nlri(test_bytes, &None, &None, &None, false, false);

        if let Ok(AttributeValue::MpUnreachNlri(nlri)) = res {
            assert_eq!(nlri.afi, Afi::Ipv4);
            assert_eq!(nlri.safi, Safi::Unicast);
            assert_eq!(nlri.next_hop, None);
            assert_eq!(
                nlri.prefixes,
                vec![NetworkPrefix::from_str("192.0.2.0/24").unwrap()]
            );
        } else {
            panic!("Unexpected result: {res:?}");
        }
    }

    #[test]
    fn test_encode_unreachable_nlri() {
        // Test encoding unreachable NLRI (withdrawals)
        let nlri = Nlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: None,
            prefixes: vec![NetworkPrefix {
                prefix: IpNet::from_str("192.0.1.0/24").unwrap(),
                path_id: None,
            }],
            labeled_prefixes: None,
            link_state_nlris: None,
            flowspec_nlris: None,
            evpn_nlris: None,
        };
        let mut buf = BytesMut::new();
        encode_nlri(&nlri, false, false, &mut buf).unwrap();
        let bytes = buf.freeze();
        assert_eq!(
            bytes,
            Bytes::from(vec![
                0x00, 0x01, // address family: IPv4
                0x01, // safi: unicast
                // No next hop for unreachable NLRI
                // No reserved byte for unreachable NLRI
                // NLRI
                0x18, // 24 bits prefix length
                0xC0, 0x00, 0x01, // 192.0.1
            ])
        );

        // Test that the encoded bytes can be parsed back correctly
        let parsed_nlri = parse_nlri(bytes, &None, &None, &None, false, false).unwrap();
        assert_eq!(parsed_nlri, AttributeValue::MpUnreachNlri(nlri));

        // Test with next_hop set (should be encoded for unreachable NLRI)
        let nlri_with_next_hop = Nlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: Some(NextHopAddress::Ipv4(
                Ipv4Addr::from_str("10.0.0.1").unwrap(),
            )),
            prefixes: vec![NetworkPrefix {
                prefix: IpNet::from_str("192.0.1.0/24").unwrap(),
                path_id: None,
            }],
            labeled_prefixes: None,
            link_state_nlris: None,
            flowspec_nlris: None,
            evpn_nlris: None,
        };
        let mut buf = BytesMut::new();
        encode_nlri(&nlri_with_next_hop, false, false, &mut buf).unwrap();
        let bytes = buf.freeze();
        // The encoded bytes should include the next_hop
        assert_eq!(
            bytes,
            Bytes::from(vec![
                0x00, 0x01, // address family: IPv4
                0x01, // safi: unicast
                0x04, // next hop length: 4
                0x0A, 0x00, 0x00, 0x01, // next hop: 10.0.0.1
                // No reserved byte for unreachable NLRI
                // NLRI
                0x18, // 24 bits prefix length
                0xC0, 0x00, 0x01, // 192.0.1
            ])
        );
    }
}

#[cfg(test)]
mod evpn_tests {
    use super::*;
    use std::str::FromStr;

    /// Wrap EVPN NLRI octets in an MP_REACH_NLRI payload with next hop 10.0.0.1.
    fn reach(nlri: Vec<u8>) -> Bytes {
        let mut bytes = vec![
            0x00, 0x19, // AFI 25 (L2VPN)
            0x46, // SAFI 70 (EVPN)
            0x04, 0x0a, 0x00, 0x00, 0x01, // next hop 10.0.0.1
            0x00, // reserved
        ];
        bytes.extend(nlri);
        Bytes::from(bytes)
    }

    /// Wrap EVPN NLRI octets in an MP_UNREACH_NLRI payload.
    fn unreach(nlri: Vec<u8>) -> Bytes {
        let mut bytes = vec![0x00, 0x19, 0x46];
        bytes.extend(nlri);
        Bytes::from(bytes)
    }

    fn mac_ip_nlri(ip_length: u8, ip_bytes: &[u8]) -> Vec<u8> {
        let body_len = 8 + 10 + 4 + 1 + 6 + 1 + ip_bytes.len() + 3;
        let mut nlri = vec![0x02, body_len as u8];
        nlri.extend_from_slice(&[0x00, 0x01, 10, 10, 0, 11, 0, 2]); // RD 10.10.0.11:2
        nlri.extend_from_slice(&[0u8; 10]); // ESI
        nlri.extend_from_slice(&[0, 0, 0, 100]); // ethernet tag
        nlri.extend_from_slice(&[0x30]); // MAC length 48
        nlri.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        nlri.push(ip_length);
        nlri.extend_from_slice(ip_bytes);
        nlri.extend_from_slice(&[0x00, 0x00, 0x64]); // label 100
        nlri
    }

    #[test]
    fn parses_mac_ip_route_with_ipv4() {
        let res = parse_nlri(
            reach(mac_ip_nlri(32, &[192, 0, 2, 10])),
            &None,
            &None,
            &None,
            true,
            false,
        );
        let Ok(AttributeValue::MpReachNlri(nlri)) = res else {
            panic!("expected MP_REACH_NLRI, got {res:?}");
        };
        assert_eq!(nlri.afi, Afi::L2vpn);
        assert_eq!(nlri.safi, Safi::Evpn);
        assert!(nlri.is_evpn());
        assert_eq!(
            nlri.next_hop,
            Some(NextHopAddress::Ipv4("10.0.0.1".parse().unwrap()))
        );

        let routes = nlri.evpn_nlris.expect("EVPN NLRI");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].route_type, EvpnRouteType::MacIpAdvertisement);
        assert_eq!(routes[0].route_distinguisher.0, [0, 1, 10, 10, 0, 11, 0, 2]);
        let EvpnRoutePayload::MacIpAdvertisement(body) = &routes[0].payload else {
            panic!("expected a MAC/IP advertisement");
        };
        assert_eq!(body.esi, [0u8; 10]);
        assert_eq!(body.ethernet_tag_id, 100);
        assert_eq!(body.mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(body.ip, Some("192.0.2.10".parse().unwrap()));
        assert_eq!(body.raw_label, 100);
    }

    #[test]
    fn parses_mac_ip_route_with_ipv6() {
        let ip: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let res = parse_nlri(
            reach(mac_ip_nlri(128, &ip.octets())),
            &None,
            &None,
            &None,
            true,
            false,
        );
        let Ok(AttributeValue::MpReachNlri(nlri)) = res else {
            panic!("expected MP_REACH_NLRI, got {res:?}");
        };
        let routes = nlri.evpn_nlris.expect("EVPN NLRI");
        let EvpnRoutePayload::MacIpAdvertisement(body) = &routes[0].payload else {
            panic!("expected a MAC/IP advertisement");
        };
        assert_eq!(body.ip, Some(std::net::IpAddr::V6(ip)));
    }

    #[test]
    fn parses_implicit_route() {
        let mut nlri = vec![0x03, 0x11];
        nlri.extend_from_slice(&[0x00, 0x01, 10, 10, 0, 11, 0, 2]); // RD
        nlri.extend_from_slice(&[0, 0, 0, 100]); // ethernet tag
        nlri.push(32); // originating router IP length
        nlri.extend_from_slice(&[10, 10, 0, 11]);

        let res = parse_nlri(reach(nlri), &None, &None, &None, true, false);
        let Ok(AttributeValue::MpReachNlri(parsed)) = res else {
            panic!("expected MP_REACH_NLRI, got {res:?}");
        };
        let routes = parsed.evpn_nlris.expect("EVPN NLRI");
        assert_eq!(
            routes[0].route_type,
            EvpnRouteType::InclusiveMulticastEthernetTag
        );
        let EvpnRoutePayload::InclusiveMulticast(body) = &routes[0].payload else {
            panic!("expected an IMET route");
        };
        assert_eq!(body.ethernet_tag_id, 100);
        assert_eq!(
            body.originating_router_ip,
            "10.10.0.11".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn parses_ip_prefix_route() {
        // RFC 9136 §3.1: RD | ESI | Ethernet tag | prefix length | prefix (4) |
        // gateway (4) | label, 34 octets in total for IPv4.
        let mut nlri = vec![0x05, 0x22];
        nlri.extend_from_slice(&[0x00, 0x01, 10, 10, 0, 12, 0, 2]); // RD
        nlri.extend_from_slice(&[0u8; 10]); // ESI
        nlri.extend_from_slice(&[0, 0, 0, 0]); // ethernet tag
        nlri.push(24); // prefix length
        nlri.extend_from_slice(&[198, 51, 100, 0]); // 198.51.100.0/24, full width
        nlri.extend_from_slice(&[0, 0, 0, 0]); // gateway IP
        nlri.extend_from_slice(&[0, 0, 0x64]); // label 100

        let res = parse_nlri(reach(nlri), &None, &None, &None, true, false);
        let Ok(AttributeValue::MpReachNlri(parsed)) = res else {
            panic!("expected MP_REACH_NLRI, got {res:?}");
        };
        let routes = parsed.evpn_nlris.expect("EVPN NLRI");
        assert_eq!(routes[0].route_type, EvpnRouteType::IpPrefix);
        let EvpnRoutePayload::IpPrefix(body) = &routes[0].payload else {
            panic!("expected an IP prefix route");
        };
        assert_eq!(body.esi, [0u8; 10]);
        assert_eq!(
            body.ip_prefix,
            ipnet::IpNet::from_str("198.51.100.0/24").unwrap()
        );
        assert_eq!(body.gateway_ip, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(body.raw_label, 100);
    }

    #[test]
    fn parses_ipv6_ip_prefix_route_shorter_than_slash_32() {
        // A /20 IPv6 prefix still carries 16-octet prefix and gateway fields;
        // the family comes from the NLRI length, not from the prefix length.
        let mut nlri = vec![0x05, 0x3a];
        nlri.extend_from_slice(&[0x00, 0x01, 10, 10, 0, 12, 0, 2]); // RD
        nlri.extend_from_slice(&[0u8; 10]); // ESI
        nlri.extend_from_slice(&[0, 0, 0, 0]); // ethernet tag
        nlri.push(20); // prefix length
        nlri.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        nlri.extend_from_slice(&[0u8; 16]); // gateway IP
        nlri.extend_from_slice(&[0, 0, 0x64]); // label 100

        let res = parse_nlri(reach(nlri), &None, &None, &None, true, false);
        let Ok(AttributeValue::MpReachNlri(parsed)) = res else {
            panic!("expected MP_REACH_NLRI, got {res:?}");
        };
        let routes = parsed.evpn_nlris.expect("EVPN NLRI");
        let EvpnRoutePayload::IpPrefix(body) = &routes[0].payload else {
            panic!("expected an IP prefix route");
        };
        assert_eq!(
            body.ip_prefix,
            ipnet::IpNet::from_str("2001:db8::/20").unwrap()
        );
        assert_eq!(body.gateway_ip, "::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rejects_ip_prefix_route_with_the_wrong_length() {
        // 26 octets after the route distinguisher is neither 34 nor 58 in total.
        let mut nlri = vec![0x05, 0x1a];
        nlri.extend_from_slice(&[0x00, 0x01, 10, 10, 0, 12, 0, 2]); // RD
        nlri.extend_from_slice(&[0u8; 18]);

        let res = parse_nlri(reach(nlri), &None, &None, &None, true, false);
        assert!(
            res.is_err(),
            "a type 5 route of the wrong length must not parse"
        );
    }

    #[test]
    fn parses_optional_second_label() {
        // MAC/IP advertisement used for IP-VRF forwarding carries Label2 too.
        let mut body = mac_ip_nlri(32, &[192, 0, 2, 10]);
        let label2 = [0x00, 0x00, 0x2a];
        body[1] += 3; // body length
        body.extend_from_slice(&label2);

        let res = parse_nlri(reach(body), &None, &None, &None, true, false);
        let Ok(AttributeValue::MpReachNlri(parsed)) = res else {
            panic!("expected MP_REACH_NLRI, got {res:?}");
        };
        let routes = parsed.evpn_nlris.expect("EVPN NLRI");
        let EvpnRoutePayload::MacIpAdvertisement(route) = &routes[0].payload else {
            panic!("expected a MAC/IP advertisement");
        };
        assert_eq!(route.raw_label, 100);
        assert_eq!(route.raw_label2, Some(42));
    }

    #[test]
    fn rejects_a_mac_address_that_does_not_fit() {
        // The fixed-field check passes, but the body ends where the MAC should
        // start: this must be an error, never a panic.
        let mut nlri = vec![0x02, 0x17];
        nlri.extend_from_slice(&[0x00, 0x01, 10, 10, 0, 12, 0, 2]); // RD
        nlri.extend_from_slice(&[0u8; 10]); // ESI
        nlri.extend_from_slice(&[0, 0, 0, 0]); // ethernet tag
        nlri.push(48); // MAC length 48, no MAC bytes follow

        let res = parse_nlri(reach(nlri), &None, &None, &None, true, false);
        assert!(res.is_err(), "a truncated MAC must be a parse error");
    }

    #[test]
    fn keeps_the_add_path_identifier() {
        let mut nlri = vec![0x00, 0x00, 0x00, 0x07]; // path id 7
        nlri.extend_from_slice(&mac_ip_nlri(0, &[]));

        let res = parse_nlri(reach(nlri), &None, &None, &None, true, true);
        let Ok(AttributeValue::MpReachNlri(parsed)) = res else {
            panic!("expected MP_REACH_NLRI, got {res:?}");
        };
        let routes = parsed.evpn_nlris.expect("EVPN NLRI");
        assert_eq!(routes[0].path_id, Some(7));
    }

    #[test]
    fn rejects_families_that_mix_l2vpn_or_evpn_with_something_else() {
        // AFI 1 with SAFI 70 would otherwise be read as IPv4 prefixes.
        let bytes = Bytes::from(vec![0x00, 0x01, 0x46, 0x00]);
        let res = parse_nlri(bytes, &None, &None, &None, false, false);
        assert!(res.is_err(), "ipv4/evpn must not be parsed as prefixes");

        // AFI 25 with SAFI 1 is not a family this parser knows either.
        let bytes = Bytes::from(vec![0x00, 0x19, 0x01, 0x00]);
        let res = parse_nlri(bytes, &None, &None, &None, false, false);
        assert!(res.is_err(), "l2vpn/unicast must not be parsed as prefixes");
    }

    #[test]
    fn keeps_undecoded_route_types_as_raw_bytes() {
        // Route type 6 does not exist today; the bytes after the RD survive.
        let mut nlri = vec![0x06, 0x0a];
        nlri.extend_from_slice(&[0x00, 0x01, 10, 10, 0, 12, 0, 2]);
        nlri.extend_from_slice(&[0xde, 0xad]);

        let res = parse_nlri(reach(nlri), &None, &None, &None, true, false);
        let Ok(AttributeValue::MpReachNlri(parsed)) = res else {
            panic!("expected MP_REACH_NLRI, got {res:?}");
        };
        let routes = parsed.evpn_nlris.expect("EVPN NLRI");
        assert_eq!(routes[0].route_type, EvpnRouteType::Unknown(6));
        assert_eq!(routes[0].payload, EvpnRoutePayload::Raw(vec![0xde, 0xad]));
    }

    #[test]
    fn parses_withdrawals_and_end_of_rib() {
        let res = parse_nlri(
            unreach(mac_ip_nlri(0, &[])),
            &None,
            &None,
            &None,
            false,
            false,
        );
        let Ok(AttributeValue::MpUnreachNlri(parsed)) = res else {
            panic!("expected MP_UNREACH_NLRI, got {res:?}");
        };
        assert_eq!(parsed.next_hop, None);
        let routes = parsed.evpn_nlris.expect("EVPN NLRI");
        assert_eq!(routes.len(), 1);

        // End-of-RIB for EVPN: the address family with no NLRI at all.
        let res = parse_nlri(unreach(vec![]), &None, &None, &None, false, false);
        let Ok(AttributeValue::MpUnreachNlri(parsed)) = res else {
            panic!("expected MP_UNREACH_NLRI, got {res:?}");
        };
        assert_eq!(parsed.evpn_nlris, Some(vec![]));
    }

    #[test]
    fn evpn_nlri_round_trips_through_the_encoder() {
        let wire = reach(mac_ip_nlri(32, &[192, 0, 2, 10]));
        let Ok(AttributeValue::MpReachNlri(parsed)) =
            parse_nlri(wire.clone(), &None, &None, &None, true, false)
        else {
            panic!("expected MP_REACH_NLRI");
        };

        let mut buf = BytesMut::new();
        encode_nlri(&parsed, true, false, &mut buf).expect("EVPN encoding");
        let encoded = buf.freeze();

        assert_eq!(encoded, wire, "encoding reproduces the wire bytes");
        let again = parse_nlri(encoded, &None, &None, &None, true, false).unwrap();
        assert_eq!(again, AttributeValue::MpReachNlri(parsed));
    }

    #[test]
    fn evpn_type_5_round_trips_through_the_encoder() {
        let mut nlri = vec![0x05, 0x22];
        nlri.extend_from_slice(&[0x00, 0x01, 10, 10, 0, 12, 0, 2]); // RD
        nlri.extend_from_slice(&[0u8; 10]); // ESI
        nlri.extend_from_slice(&[0, 0, 0, 0]); // ethernet tag
        nlri.push(24); // prefix length
        nlri.extend_from_slice(&[198, 51, 100, 0]);
        nlri.extend_from_slice(&[0, 0, 0, 0]);
        nlri.extend_from_slice(&[0, 0, 0x64]); // label 100
        let wire = reach(nlri);

        let Ok(AttributeValue::MpReachNlri(parsed)) =
            parse_nlri(wire.clone(), &None, &None, &None, true, false)
        else {
            panic!("expected MP_REACH_NLRI");
        };
        let mut buf = BytesMut::new();
        encode_nlri(&parsed, true, false, &mut buf).unwrap();
        assert_eq!(buf.freeze(), wire);
    }

    #[test]
    fn evpn_add_path_round_trips_preserving_the_path_id() {
        let mut nlri = vec![0x00, 0x00, 0x00, 0x07]; // path id
        nlri.extend_from_slice(&mac_ip_nlri(0, &[]));
        let wire = reach(nlri);

        let Ok(AttributeValue::MpReachNlri(parsed)) =
            parse_nlri(wire.clone(), &None, &None, &None, true, true)
        else {
            panic!("expected MP_REACH_NLRI");
        };
        assert_eq!(
            parsed.evpn_nlris.as_ref().and_then(|r| r[0].path_id),
            Some(7)
        );

        let mut buf = BytesMut::new();
        encode_nlri(&parsed, true, true, &mut buf).unwrap();
        assert_eq!(buf.freeze(), wire);

        // Without ADD-PATH the identifier would be read as a route type.
        let mut buf = BytesMut::new();
        let err = encode_nlri(&parsed, true, false, &mut buf)
            .expect_err("ADD-PATH state and path identifiers must agree");
        assert!(format!("{err:?}").contains("path identifier"));
    }

    #[test]
    fn rejects_trailing_octets_in_an_implicit_route() {
        let mut nlri = vec![0x03, 0x13];
        nlri.extend_from_slice(&[0x00, 0x01, 10, 10, 0, 11, 0, 2]); // RD
        nlri.extend_from_slice(&[0, 0, 0, 100]); // ethernet tag
        nlri.push(32);
        nlri.extend_from_slice(&[10, 10, 0, 11]);
        nlri.extend_from_slice(&[0xde, 0xad]); // trailing junk

        let res = parse_nlri(reach(nlri), &None, &None, &None, true, false);
        assert!(res.is_err(), "trailing octets must not be dropped silently");
    }

    #[test]
    fn refuses_evpn_next_hop_states_that_do_not_exist_on_the_wire() {
        let route = EvpnNlri {
            path_id: None,
            route_type: EvpnRouteType::MacIpAdvertisement,
            route_distinguisher: RouteDistinguisher([0, 1, 10, 10, 0, 11, 0, 2]),
            payload: EvpnRoutePayload::MacIpAdvertisement(MacIpAdvertisement {
                esi: [0; 10],
                ethernet_tag_id: 0,
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                ip: None,
                raw_label: 100,
                raw_label2: None,
            }),
        };

        // An announcement without a VTEP would omit the next-hop length.
        let announcement = Nlri::new_evpn_reachable(None, vec![route.clone()]);
        let mut buf = BytesMut::new();
        let err = encode_nlri(&announcement, true, false, &mut buf)
            .expect_err("a reachable EVPN NLRI needs a next hop");
        assert!(format!("{err:?}").contains("next hop"), "{err:?}");
        assert!(buf.is_empty(), "nothing is written before the refusal");

        // A withdrawal with a next hop would write a field MP_UNREACH lacks.
        let withdrawal = Nlri::new_evpn_reachable(Some("10.10.0.11".parse().unwrap()), vec![route]);
        let mut buf = BytesMut::new();
        let err = encode_nlri(&withdrawal, false, false, &mut buf)
            .expect_err("an EVPN withdrawal carries no next hop");
        assert!(format!("{err:?}").contains("no next hop"), "{err:?}");
    }

    #[test]
    fn refuses_a_route_type_that_disagrees_with_its_payload() {
        let route = EvpnNlri {
            path_id: None,
            // Type 5 with a type 2 body: the header would advertise a family the
            // body does not describe.
            route_type: EvpnRouteType::IpPrefix,
            route_distinguisher: RouteDistinguisher([0, 1, 10, 10, 0, 11, 0, 2]),
            payload: EvpnRoutePayload::MacIpAdvertisement(MacIpAdvertisement {
                esi: [0; 10],
                ethernet_tag_id: 0,
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                ip: None,
                raw_label: 100,
                raw_label2: None,
            }),
        };
        let nlri = Nlri::new_evpn_reachable(Some("10.10.0.11".parse().unwrap()), vec![route]);
        let mut buf = BytesMut::new();
        let err = encode_nlri(&nlri, true, false, &mut buf)
            .expect_err("the route type and payload must agree");
        assert!(format!("{err:?}").contains("route type"), "{err:?}");
    }

    #[test]
    fn the_attribute_encoder_keeps_add_path_state_for_evpn() {
        // The public path infers ADD-PATH from the routes, for announcements
        // and withdrawals alike.
        let route = EvpnNlri {
            path_id: Some(7),
            route_type: EvpnRouteType::MacIpAdvertisement,
            route_distinguisher: RouteDistinguisher([0, 1, 10, 10, 0, 12, 0, 2]),
            payload: EvpnRoutePayload::MacIpAdvertisement(MacIpAdvertisement {
                esi: [0; 10],
                ethernet_tag_id: 0,
                mac: [0xaa, 0xc1, 0xab, 0x73, 0x01, 0x4d],
                ip: None,
                raw_label: 100,
                raw_label2: None,
            }),
        };

        let announced = AttributeValue::MpReachNlri(Nlri::new_evpn_reachable(
            Some("10.10.0.12".parse().unwrap()),
            vec![route.clone()],
        ));
        let mut buf = BytesMut::new();
        Attribute {
            value: announced,
            flag: AttrFlags::OPTIONAL,
        }
        .encode_to(AsnLength::Bits32, &mut buf)
        .expect("an ADD-PATH EVPN announcement encodes");
        // attribute header, then AFI/SAFI, next hop, reserved octet, path id
        assert!(
            buf.windows(4)
                .any(|window| window == [0x00, 0x00, 0x00, 0x07]),
            "the path identifier is on the wire"
        );

        let withdrawn = AttributeValue::MpUnreachNlri(Nlri::new_evpn_unreachable(vec![route]));
        let mut buf = BytesMut::new();
        Attribute {
            value: withdrawn,
            flag: AttrFlags::OPTIONAL,
        }
        .encode_to(AsnLength::Bits32, &mut buf)
        .expect("an ADD-PATH EVPN withdrawal encodes");
        assert!(
            buf.windows(4)
                .any(|window| window == [0x00, 0x00, 0x00, 0x07]),
            "the path identifier survives a withdrawal"
        );
    }

    #[test]
    fn truncated_evpn_nlri_is_an_error() {
        // Type 2 with a body that ends before the MAC address.
        let res = parse_nlri(
            reach(vec![0x02, 0x08, 0, 1, 10, 10, 0, 11, 0, 2]),
            &None,
            &None,
            &None,
            true,
            false,
        );
        assert!(res.is_err(), "a truncated route must not parse");
    }
}
