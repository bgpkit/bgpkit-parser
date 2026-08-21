//! Best-effort, Wireshark-style dissection of BGP messages.
//!
//! This module walks the same wire grammar the parsers consume, but instead of
//! producing model structs it produces a [`DissectionNode`] tree in which every
//! field carries its byte range. It is a separate pass over already-received
//! bytes: nothing here runs on the default parsing hot path, and a dissector
//! never fails — on truncated or malformed input the tree simply stops at the
//! last field that could be walked, which is exactly the "show me where
//! parsing died" experience a byte-level inspector wants.

use crate::models::{AsnLength, DissectionNode};
use std::net::{Ipv4Addr, Ipv6Addr};

/// IANA path attribute names for the type codes this dissector labels.
fn attr_name(code: u8) -> &'static str {
    match code {
        1 => "ORIGIN",
        2 => "AS_PATH",
        3 => "NEXT_HOP",
        4 => "MULTI_EXIT_DISC",
        5 => "LOCAL_PREF",
        6 => "ATOMIC_AGGREGATE",
        7 => "AGGREGATOR",
        8 => "COMMUNITIES",
        9 => "ORIGINATOR_ID",
        10 => "CLUSTER_LIST",
        14 => "MP_REACH_NLRI",
        15 => "MP_UNREACH_NLRI",
        16 => "EXTENDED_COMMUNITIES",
        17 => "AS4_PATH",
        18 => "AS4_AGGREGATOR",
        22 => "PMSI_TUNNEL",
        23 => "TUNNEL_ENCAPSULATION",
        24 => "TRAFFIC_ENGINEERING",
        25 => "IPV6_EXTENDED_COMMUNITIES",
        26 => "AIGP",
        27 => "PE_DISTINGUISHER_LABELS",
        29 => "BGP-LS",
        32 => "LARGE_COMMUNITY",
        33 => "BGPSEC_PATH",
        35 => "ONLY_TO_CUSTOMER",
        37 => "SFP",
        38 => "BFD_DISCRIMINATOR",
        40 => "BGP_PREFIX_SID",
        41 => "BIER",
        _ => "ATTRIBUTE",
    }
}

fn read_u16(data: &[u8], pos: usize) -> Option<u16> {
    let hi = *data.get(pos)?;
    let lo = *data.get(pos + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

fn read_u32(data: &[u8], pos: usize) -> Option<u32> {
    let b: [u8; 4] = data.get(pos..pos + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(b))
}

fn render_prefix(afi_v4: bool, plen: u8, octets: &[u8]) -> String {
    if afi_v4 {
        let mut octets = octets.to_vec();
        octets.resize(4, 0);
        format!(
            "{}.{}.{}.{}/{}",
            octets[0], octets[1], octets[2], octets[3], plen
        )
    } else {
        let mut octets = octets.to_vec();
        octets.resize(16, 0);
        let segs: Vec<u16> = octets
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        let s = &segs;
        format!(
            "{}/{}",
            Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]),
            plen
        )
    }
}

/// Dissect a standalone BGP message (offsets relative to the message start).
///
/// `asn_len` controls how AS numbers inside AS_PATH/AGGREGATOR values are
/// rendered (2- or 4-octet encoding); `add_path` indicates ADD-PATH encoded
/// NLRI (RFC 7911).
pub fn dissect_bgp_message(data: &[u8], asn_len: &AsnLength, add_path: bool) -> DissectionNode {
    dissect_bgp_message_base(data, 0, asn_len, add_path)
}

/// Dissect a BGP message embedded at `base` within a larger buffer (e.g. an
/// MRT BGP4MP record), so that all tree offsets share one coordinate space
/// with the enclosing container.
pub(crate) fn dissect_bgp_message_base(
    data: &[u8],
    base: u32,
    asn_len: &AsnLength,
    add_path: bool,
) -> DissectionNode {
    let mut root = DissectionNode::new(
        "bgp",
        format!("BGP message ({} bytes)", data.len()),
        base,
        data.len() as u32,
    );

    if data.len() < 19 {
        if !data.is_empty() {
            root.children.push(DissectionNode::new(
                "bgp.header",
                format!("Header (truncated, {} of 19 bytes)", data.len()),
                base,
                data.len() as u32,
            ));
        }
        return root;
    }

    let mut header = DissectionNode::new("bgp.header", "Header", base, 19);
    let all_ones = data[..16].iter().all(|b| *b == 0xFF);
    header.children.push(DissectionNode::new(
        "bgp.header.marker",
        if all_ones {
            "Marker (all ones)".to_string()
        } else {
            "Marker (NOT all ones — invalid per RFC 4271)".to_string()
        },
        base,
        16,
    ));
    let length = u16::from_be_bytes([data[16], data[17]]);
    header.children.push(DissectionNode::new(
        "bgp.header.length",
        format!("Length: {length}"),
        base + 16,
        2,
    ));
    let msg_type = data[18];
    let type_name = match msg_type {
        1 => "OPEN",
        2 => "UPDATE",
        3 => "NOTIFICATION",
        4 => "KEEPALIVE",
        5 => "ROUTE-REFRESH",
        _ => "UNKNOWN",
    };
    header.children.push(DissectionNode::new(
        "bgp.header.type",
        format!("Type: {type_name} ({msg_type})"),
        base + 18,
        1,
    ));
    root.children.push(header);

    let body = &data[19..];
    let body_base = base + 19;
    match msg_type {
        1 => root.children.push(dissect_open(body, body_base)),
        2 => root
            .children
            .push(dissect_update(body, body_base, asn_len, add_path)),
        3 => root.children.push(dissect_notification(body, body_base)),
        4 => {}
        5 => root.children.push(dissect_route_refresh(body, body_base)),
        _ => root.children.push(DissectionNode::new(
            "bgp.body",
            format!("Unknown message type ({} bytes)", body.len()),
            body_base,
            body.len() as u32,
        )),
    }
    root
}

fn dissect_update(data: &[u8], base: u32, asn_len: &AsnLength, add_path: bool) -> DissectionNode {
    let mut update = DissectionNode::new("bgp.update", "UPDATE", base, data.len() as u32);

    if data.len() < 2 {
        if !data.is_empty() {
            update.children.push(DissectionNode::new(
                "bgp.update.withdrawn_routes.length",
                "Withdrawn routes length (truncated)",
                base,
                data.len() as u32,
            ));
        }
        return update;
    }

    let withdrawn_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    update.children.push(DissectionNode::new(
        "bgp.update.withdrawn_routes.length",
        format!("Withdrawn routes length: {withdrawn_len}"),
        base,
        2,
    ));

    let mut pos = 2usize;
    if pos + withdrawn_len > data.len() {
        update.children.push(DissectionNode::new(
            "bgp.update.withdrawn_routes",
            format!(
                "Withdrawn routes (truncated: {} of {} bytes)",
                data.len() - pos,
                withdrawn_len
            ),
            base + pos as u32,
            (data.len() - pos) as u32,
        ));
        return update;
    }
    if withdrawn_len > 0 {
        let mut section = DissectionNode::new(
            "bgp.update.withdrawn_routes",
            format!("Withdrawn routes ({withdrawn_len} bytes)"),
            base + 2,
            withdrawn_len as u32,
        );
        section.children = dissect_nlri(&data[2..2 + withdrawn_len], base + 2, true, add_path);
        update.children.push(section);
    }
    pos = 2 + withdrawn_len;

    if pos + 2 > data.len() {
        if pos < data.len() {
            update.children.push(DissectionNode::new(
                "bgp.update.path_attributes.length",
                "Total path attribute length (truncated)",
                base + pos as u32,
                (data.len() - pos) as u32,
            ));
        }
        return update;
    }
    let attr_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    update.children.push(DissectionNode::new(
        "bgp.update.path_attributes.length",
        format!("Total path attribute length: {attr_len}"),
        base + pos as u32,
        2,
    ));
    pos += 2;

    let attr_end = (pos + attr_len).min(data.len());
    if attr_end > pos {
        let mut section = DissectionNode::new(
            "bgp.update.path_attributes",
            format!("Path attributes ({attr_len} bytes)"),
            base + pos as u32,
            (attr_end - pos) as u32,
        );
        section.children =
            dissect_attributes(&data[pos..attr_end], base + pos as u32, asn_len, add_path);
        update.children.push(section);
    } else if attr_len > 0 {
        update.children.push(DissectionNode::new(
            "bgp.update.path_attributes",
            format!("Path attributes (truncated: declared {attr_len} bytes)"),
            base + pos as u32,
            0,
        ));
    }
    pos = attr_end;

    if pos < data.len() {
        let mut section = DissectionNode::new(
            "bgp.update.nlri",
            format!(
                "Network Layer Reachability Information ({} bytes)",
                data.len() - pos
            ),
            base + pos as u32,
            (data.len() - pos) as u32,
        );
        section.children = dissect_nlri(&data[pos..], base + pos as u32, true, add_path);
        update.children.push(section);
    }

    update
}

/// Walk a TLV list of path attributes (RFC 4271 Section 4.3).
fn dissect_attributes(
    data: &[u8],
    base: u32,
    asn_len: &AsnLength,
    add_path: bool,
) -> Vec<DissectionNode> {
    let mut nodes = Vec::new();
    let mut pos = 0usize;
    let asn_size = match asn_len {
        AsnLength::Bits16 => 2,
        AsnLength::Bits32 => 4,
    };

    while pos + 3 <= data.len() {
        let flags = data[pos];
        let code = data[pos + 1];
        let extended = flags & 0x10 != 0;
        let header_len = if extended { 4 } else { 3 };
        if pos + header_len > data.len() {
            break;
        }
        let value_len = if extended {
            match read_u16(data, pos + 2) {
                Some(v) => v as usize,
                None => break,
            }
        } else {
            data[pos + 2] as usize
        };
        let value_start = pos + header_len;
        let value_end = value_start + value_len;
        if value_end > data.len() {
            // Truncated attribute: emit the header plus whatever value bytes
            // are present, then stop — the length field can no longer be
            // trusted to walk past this point.
            let attr_end = data.len();
            let mut node = DissectionNode::new(
                format!("bgp.attr.{code}"),
                format!(
                    "{} (type {code}) — truncated ({} of {} value bytes)",
                    attr_name(code),
                    attr_end - value_start,
                    value_len
                ),
                base + pos as u32,
                (attr_end - pos) as u32,
            );
            node.children.push(DissectionNode::new(
                "bgp.attr.flags",
                format!("Flags: 0x{flags:02X}"),
                base + pos as u32,
                1,
            ));
            nodes.push(node);
            break;
        }

        let total = header_len + value_len;
        let mut node = DissectionNode::new(
            format!("bgp.attr.{code}"),
            format!("{} (type {code}), {value_len} bytes", attr_name(code)),
            base + pos as u32,
            total as u32,
        );
        node.children.push(DissectionNode::new(
            "bgp.attr.flags",
            format!("Flags: 0x{flags:02X}"),
            base + pos as u32,
            1,
        ));
        node.children.push(DissectionNode::new(
            "bgp.attr.type",
            format!("Type: {code} ({})", attr_name(code)),
            base + pos as u32 + 1,
            1,
        ));
        node.children.push(DissectionNode::new(
            "bgp.attr.length",
            format!("Length: {value_len}"),
            base + pos as u32 + 2,
            (header_len - 2) as u32,
        ));
        let value_base = base + value_start as u32;
        let mut value_node = DissectionNode::new(
            "bgp.attr.value",
            format!("Value ({value_len} bytes)"),
            value_base,
            value_len as u32,
        );
        value_node.children = dissect_attr_value(
            code,
            &data[value_start..value_end],
            value_base,
            asn_size,
            add_path,
        );
        node.children.push(value_node);

        nodes.push(node);
        pos = value_end;
    }

    nodes
}

/// Dissect the value body of one path attribute at showcase depth: AS_PATH
/// segments, community entries, MP_REACH/MP_UNREACH structure, and the fixed
/// u32 fields. Other attributes keep a single value node.
fn dissect_attr_value(
    code: u8,
    value: &[u8],
    base: u32,
    asn_size: usize,
    add_path: bool,
) -> Vec<DissectionNode> {
    let mut nodes = Vec::new();
    match code {
        1 => {
            // ORIGIN
            if let Some(v) = value.first() {
                let name = match v {
                    0 => "IGP",
                    1 => "EGP",
                    2 => "INCOMPLETE",
                    _ => "INVALID",
                };
                nodes.push(DissectionNode::new(
                    "bgp.attr.origin",
                    format!("Origin: {name} ({v})"),
                    base,
                    1,
                ));
            }
        }
        2 | 17 => {
            // AS_PATH / AS4_PATH: segments of type(1) + count(1) + count*asn
            let mut pos = 0usize;
            while pos + 2 <= value.len() {
                let seg_type = value[pos];
                let count = value[pos + 1] as usize;
                let seg_len = 2 + count * asn_size;
                if pos + seg_len > value.len() {
                    break;
                }
                let name = match seg_type {
                    1 => "AS_SET",
                    2 => "AS_SEQUENCE",
                    3 => "AS_CONFED_SEQUENCE",
                    4 => "AS_CONFED_SET",
                    _ => "UNKNOWN",
                };
                let mut asns = Vec::with_capacity(count);
                for i in 0..count {
                    let at = pos + 2 + i * asn_size;
                    let asn = if asn_size == 2 {
                        read_u16(value, at).unwrap_or(0) as u32
                    } else {
                        read_u32(value, at).unwrap_or(0)
                    };
                    asns.push(asn.to_string());
                }
                nodes.push(DissectionNode::new(
                    "bgp.attr.as_path.segment",
                    format!("{name}: {}", asns.join(" ")),
                    base + pos as u32,
                    seg_len as u32,
                ));
                pos += seg_len;
            }
        }
        3 => {
            if let Some(ip) = value.get(0..4) {
                let ipv4 = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                nodes.push(DissectionNode::new(
                    "bgp.attr.next_hop",
                    format!("Next hop: {ipv4}"),
                    base,
                    value.len() as u32,
                ));
            }
        }
        4 | 5 | 35 => {
            if let Some(v) = read_u32(value, 0) {
                let name = match code {
                    4 => "Multi-exit discriminator",
                    5 => "Local preference",
                    _ => "Only to customer",
                };
                nodes.push(DissectionNode::new(
                    "bgp.attr.u32",
                    format!("{name}: {v}"),
                    base,
                    value.len() as u32,
                ));
            }
        }
        7 | 18 => {
            // AGGREGATOR: ASN (variable on the wire) + router ID (4)
            if value.len() > 4 {
                let asn_len_field = value.len() - 4;
                let asn = if asn_len_field == 4 {
                    read_u32(value, 0).unwrap_or(0)
                } else {
                    read_u16(value, 0).unwrap_or(0) as u32
                };
                nodes.push(DissectionNode::new(
                    "bgp.attr.aggregator.asn",
                    format!("Aggregator ASN: {asn}"),
                    base,
                    asn_len_field as u32,
                ));
                let id = Ipv4Addr::new(
                    value[asn_len_field],
                    value[asn_len_field + 1],
                    value[asn_len_field + 2],
                    value[asn_len_field + 3],
                );
                nodes.push(DissectionNode::new(
                    "bgp.attr.aggregator.id",
                    format!("Aggregator router ID: {id}"),
                    base + asn_len_field as u32,
                    4,
                ));
            }
        }
        8 => {
            // COMMUNITIES: 4-byte entries
            let mut pos = 0usize;
            let mut idx = 1;
            while pos + 4 <= value.len() {
                let asn = read_u16(value, pos).unwrap_or(0);
                let val = read_u16(value, pos + 2).unwrap_or(0);
                nodes.push(DissectionNode::new(
                    "bgp.attr.communities.entry",
                    format!("Community [{idx}]: {asn}:{val}"),
                    base + pos as u32,
                    4,
                ));
                pos += 4;
                idx += 1;
            }
        }
        9 => {
            if let Some(ip) = value.get(0..4) {
                nodes.push(DissectionNode::new(
                    "bgp.attr.originator_id",
                    format!("Originator ID: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                    base,
                    value.len() as u32,
                ));
            }
        }
        10 => {
            // CLUSTER_LIST: 4-byte entries
            let mut pos = 0usize;
            let mut idx = 1;
            while pos + 4 <= value.len() {
                let id = read_u32(value, pos).unwrap_or(0);
                nodes.push(DissectionNode::new(
                    "bgp.attr.cluster_list.entry",
                    format!("Cluster ID [{idx}]: {id}"),
                    base + pos as u32,
                    4,
                ));
                pos += 4;
                idx += 1;
            }
        }
        14 => {
            // MP_REACH_NLRI: AFI(2) SAFI(1) NH-len(1) NH(var) reserved(1) NLRI
            if value.len() >= 4 {
                let afi = read_u16(value, 0).unwrap_or(0);
                let afi_name = match afi {
                    1 => "IPv4",
                    2 => "IPv6",
                    25 => "L2VPN",
                    _ => "unknown",
                };
                nodes.push(DissectionNode::new(
                    "bgp.attr.mp_reach.afi",
                    format!("AFI: {afi} ({afi_name})"),
                    base,
                    2,
                ));
                nodes.push(DissectionNode::new(
                    "bgp.attr.mp_reach.safi",
                    format!("SAFI: {}", value[2]),
                    base + 2,
                    1,
                ));
                let nh_len = value[3] as usize;
                nodes.push(DissectionNode::new(
                    "bgp.attr.mp_reach.next_hop_length",
                    format!("Next hop length: {nh_len}"),
                    base + 3,
                    1,
                ));
                let mut pos = 4usize;
                if pos + nh_len <= value.len() && nh_len > 0 {
                    nodes.push(DissectionNode::new(
                        "bgp.attr.mp_reach.next_hop",
                        format!("Next hop ({} bytes)", nh_len),
                        base + pos as u32,
                        nh_len as u32,
                    ));
                    pos += nh_len;
                }
                if pos < value.len() {
                    nodes.push(DissectionNode::new(
                        "bgp.attr.mp_reach.reserved",
                        "Reserved",
                        base + pos as u32,
                        1,
                    ));
                    pos += 1;
                }
                if pos < value.len() {
                    nodes.extend(dissect_nlri(
                        &value[pos..],
                        base + pos as u32,
                        afi == 1,
                        add_path,
                    ));
                }
            }
        }
        15 => {
            // MP_UNREACH_NLRI: AFI(2) SAFI(1) withdrawn NLRI
            if value.len() >= 3 {
                let afi = read_u16(value, 0).unwrap_or(0);
                nodes.push(DissectionNode::new(
                    "bgp.attr.mp_unreach.afi",
                    format!("AFI: {afi}"),
                    base,
                    2,
                ));
                nodes.push(DissectionNode::new(
                    "bgp.attr.mp_unreach.safi",
                    format!("SAFI: {}", value[2]),
                    base + 2,
                    1,
                ));
                nodes.extend(dissect_nlri(&value[3..], base + 3, afi == 1, add_path));
            }
        }
        16 => {
            // EXTENDED_COMMUNITIES: 8-byte entries
            let mut pos = 0usize;
            let mut idx = 1;
            while pos + 8 <= value.len() {
                nodes.push(DissectionNode::new(
                    "bgp.attr.ext_communities.entry",
                    format!(
                        "Extended community [{idx}]: {}",
                        render_ext_community(&value[pos..pos + 8])
                    ),
                    base + pos as u32,
                    8,
                ));
                pos += 8;
                idx += 1;
            }
        }
        25 => {
            // IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES: 20-byte entries
            let mut pos = 0usize;
            let mut idx = 1;
            while pos + 20 <= value.len() {
                nodes.push(DissectionNode::new(
                    "bgp.attr.ipv6_ext_communities.entry",
                    format!("IPv6 extended community [{idx}]"),
                    base + pos as u32,
                    20,
                ));
                pos += 20;
                idx += 1;
            }
        }
        26 => {
            // AIGP: TLV of type(1) + length(2, includes header) + value
            let mut pos = 0usize;
            while pos + 3 <= value.len() {
                let tlv_type = value[pos];
                let tlv_len = read_u16(value, pos + 2).unwrap_or(0) as usize;
                if tlv_len < 3 || pos + tlv_len > value.len() {
                    break;
                }
                nodes.push(DissectionNode::new(
                    "bgp.attr.aigp.entry",
                    format!("AIGP TLV: type {tlv_type}, {tlv_len} bytes"),
                    base + pos as u32,
                    tlv_len as u32,
                ));
                pos += tlv_len;
            }
        }
        32 => {
            // LARGE_COMMUNITY: 12-byte entries
            let mut pos = 0usize;
            let mut idx = 1;
            while pos + 12 <= value.len() {
                let ga = read_u32(value, pos).unwrap_or(0);
                let l1 = read_u32(value, pos + 4).unwrap_or(0);
                let l2 = read_u32(value, pos + 8).unwrap_or(0);
                nodes.push(DissectionNode::new(
                    "bgp.attr.large_communities.entry",
                    format!("Large community [{idx}]: {ga}:{l1}:{l2}"),
                    base + pos as u32,
                    12,
                ));
                pos += 12;
                idx += 1;
            }
        }
        _ => {}
    }
    nodes
}

fn render_ext_community(entry: &[u8]) -> String {
    let type_high = entry[0];
    let subtype = entry[1];
    let value = &entry[2..8];
    match type_high & 0x0F {
        0x00 => {
            let asn = u16::from_be_bytes([value[0], value[1]]);
            let val = u32::from_be_bytes([value[2], value[3], value[4], value[5]]);
            format!("type 0x{type_high:02X} subtype 0x{subtype:02X}: {asn}:{val}")
        }
        0x01 => {
            let ip = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
            let val = u16::from_be_bytes([value[4], value[5]]);
            format!("type 0x{type_high:02X} subtype 0x{subtype:02X}: {ip}:{val}")
        }
        0x02 => {
            let asn = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            let val = u16::from_be_bytes([value[4], value[5]]);
            format!("type 0x{type_high:02X} subtype 0x{subtype:02X}: {asn}:{val}")
        }
        _ => {
            let hex: Vec<String> = value.iter().map(|b| format!("{b:02X}")).collect();
            format!(
                "type 0x{type_high:02X} subtype 0x{subtype:02X}: {}",
                hex.join(" ")
            )
        }
    }
}

/// Walk an NLRI section of variable-length prefixes (1 length byte +
/// ceil(len/8) address octets), with optional ADD-PATH path identifiers.
fn dissect_nlri(data: &[u8], base: u32, afi_v4: bool, add_path: bool) -> Vec<DissectionNode> {
    let mut nodes = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let entry_start = pos;
        if add_path {
            if pos + 5 > data.len() {
                break;
            }
            pos += 4; // path identifier
        }
        let plen = match data.get(pos) {
            Some(v) => *v,
            None => break,
        };
        let octets = (plen as usize).div_ceil(8);
        pos += 1;
        if pos + octets > data.len() {
            break;
        }
        let label = render_prefix(afi_v4, plen, &data[pos..pos + octets]);
        nodes.push(DissectionNode::new(
            "bgp.nlri.prefix",
            label,
            base + entry_start as u32,
            (pos + octets - entry_start) as u32,
        ));
        pos += octets;
    }
    nodes
}

fn dissect_open(data: &[u8], base: u32) -> DissectionNode {
    let mut open = DissectionNode::new("bgp.open", "OPEN", base, data.len() as u32);
    if data.len() < 10 {
        if !data.is_empty() {
            open.children.push(DissectionNode::new(
                "bgp.open.truncated",
                format!("Truncated OPEN ({} of 10 fixed bytes)", data.len()),
                base,
                data.len() as u32,
            ));
        }
        return open;
    }

    open.children.push(DissectionNode::new(
        "bgp.open.version",
        format!("Version: {}", data[0]),
        base,
        1,
    ));
    let asn = u16::from_be_bytes([data[1], data[2]]);
    open.children.push(DissectionNode::new(
        "bgp.open.asn",
        format!("My AS: {asn}"),
        base + 1,
        2,
    ));
    let hold = u16::from_be_bytes([data[3], data[4]]);
    open.children.push(DissectionNode::new(
        "bgp.open.hold_time",
        format!("Hold time: {hold}s"),
        base + 3,
        2,
    ));
    open.children.push(DissectionNode::new(
        "bgp.open.bgp_identifier",
        format!(
            "BGP identifier: {}.{}.{}.{}",
            data[5], data[6], data[7], data[8]
        ),
        base + 5,
        4,
    ));
    let opt_len = data[9];
    open.children.push(DissectionNode::new(
        "bgp.open.opt_params_len",
        format!("Optional parameters length: {opt_len}"),
        base + 9,
        1,
    ));

    // Optional parameters; RFC 9072 extended framing starts with type 255
    // followed by a 2-byte aggregate length and 2-byte per-param lengths.
    let mut pos = 10usize;
    let mut extended = false;
    let mut first = true;
    while pos + 2 <= data.len() {
        let param_type = data[pos];
        if first && param_type == 255 && opt_len != 0 {
            extended = true;
            if pos + 3 > data.len() {
                break;
            }
            let ext_len = read_u16(data, pos + 1).unwrap_or(0);
            open.children.push(DissectionNode::new(
                "bgp.open.ext_params_len",
                format!("Extended optional parameters length: {ext_len} (RFC 9072)"),
                base + pos as u32,
                3,
            ));
            pos += 3;
            first = false;
            if ext_len == 0 {
                break;
            }
            continue;
        }
        first = false;

        let len_size = if extended { 2 } else { 1 };
        let value_len = if extended {
            match read_u16(data, pos + 1) {
                Some(v) => v as usize,
                None => break,
            }
        } else {
            *data.get(pos + 1).unwrap_or(&0) as usize
        };
        let header_len = 1 + len_size;
        if pos + header_len + value_len > data.len() {
            break;
        }

        let mut param = DissectionNode::new(
            "bgp.open.param",
            if param_type == 2 {
                "Capabilities (RFC 3392)".to_string()
            } else {
                format!("Optional parameter (type {param_type})")
            },
            base + pos as u32,
            (header_len + value_len) as u32,
        );
        param.children.push(DissectionNode::new(
            "bgp.open.param.type",
            format!("Type: {param_type}"),
            base + pos as u32,
            1,
        ));
        param.children.push(DissectionNode::new(
            "bgp.open.param.length",
            format!("Length: {value_len}"),
            base + pos as u32 + 1,
            len_size as u32,
        ));

        let value = &data[pos + header_len..pos + header_len + value_len];
        let value_base = base + (pos + header_len) as u32;
        if param_type == 2 {
            // Capabilities: code(1) + length(1) + value
            let mut cpos = 0usize;
            while cpos + 2 <= value.len() {
                let cap_code = value[cpos];
                let cap_len = value[cpos + 1] as usize;
                if cpos + 2 + cap_len > value.len() {
                    break;
                }
                let mut cap = DissectionNode::new(
                    "bgp.open.capability",
                    format!("Capability: {} ({cap_code})", capability_name(cap_code)),
                    value_base + cpos as u32,
                    (2 + cap_len) as u32,
                );
                cap.children.push(DissectionNode::new(
                    "bgp.open.capability.code",
                    format!("Code: {cap_code} ({})", capability_name(cap_code)),
                    value_base + cpos as u32,
                    1,
                ));
                cap.children.push(DissectionNode::new(
                    "bgp.open.capability.length",
                    format!("Length: {cap_len}"),
                    value_base + cpos as u32 + 1,
                    1,
                ));
                param.children.push(cap);
                cpos += 2 + cap_len;
            }
        } else {
            param.children.push(DissectionNode::new(
                "bgp.open.param.value",
                format!("Value ({value_len} bytes)"),
                value_base,
                value_len as u32,
            ));
        }

        open.children.push(param);
        pos += header_len + value_len;
    }

    open
}

fn capability_name(code: u8) -> &'static str {
    match code {
        1 => "Multiprotocol Extensions",
        2 => "Route Refresh",
        4 => "Multiple Routes to a Destination",
        5 => "Extended Next Hop Encoding",
        6 => "BGP Extended Message",
        7 => "BGP Role",
        64 => "Graceful Restart",
        65 => "Support for 4-octet AS Number",
        66 => "Support for Add-Path",
        67 => "Enhanced Route Refresh",
        68 => "Long-Lived Graceful Restart",
        _ => "Unknown",
    }
}

fn dissect_notification(data: &[u8], base: u32) -> DissectionNode {
    let mut notification =
        DissectionNode::new("bgp.notification", "NOTIFICATION", base, data.len() as u32);
    if let Some(code) = data.first() {
        notification.children.push(DissectionNode::new(
            "bgp.notification.code",
            format!("Error code: {code}"),
            base,
            1,
        ));
    }
    if data.len() >= 2 {
        notification.children.push(DissectionNode::new(
            "bgp.notification.subcode",
            format!("Error subcode: {}", data[1]),
            base + 1,
            1,
        ));
    }
    if data.len() > 2 {
        notification.children.push(DissectionNode::new(
            "bgp.notification.data",
            format!("Data ({} bytes)", data.len() - 2),
            base + 2,
            (data.len() - 2) as u32,
        ));
    }
    notification
}

fn dissect_route_refresh(data: &[u8], base: u32) -> DissectionNode {
    let mut refresh = DissectionNode::new(
        "bgp.route_refresh",
        "ROUTE-REFRESH",
        base,
        data.len() as u32,
    );
    if data.len() >= 4 {
        let afi = read_u16(data, 0).unwrap_or(0);
        refresh.children.push(DissectionNode::new(
            "bgp.route_refresh.afi",
            format!("AFI: {afi}"),
            base,
            2,
        ));
        refresh.children.push(DissectionNode::new(
            "bgp.route_refresh.subtype",
            format!("Subtype: {}", data[2]),
            base + 2,
            1,
        ));
        refresh.children.push(DissectionNode::new(
            "bgp.route_refresh.safi",
            format!("SAFI: {}", data[3]),
            base + 3,
            1,
        ));
    }
    if data.len() > 4 {
        refresh.children.push(DissectionNode::new(
            "bgp.route_refresh.data",
            format!("ORF data ({} bytes)", data.len() - 4),
            base + 4,
            (data.len() - 4) as u32,
        ));
    }
    refresh
}

#[cfg(test)]
mod tests {
    use super::*;

    /// marker(16) + length(2) + type(1) + body
    fn bgp_wire(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut wire = vec![0xFF; 16];
        let total = (19 + body.len()) as u16;
        wire.extend_from_slice(&total.to_be_bytes());
        wire.push(msg_type);
        wire.extend_from_slice(body);
        wire
    }

    /// ORIGIN + AS_PATH (2 ASNs, 4-octet) + NEXT_HOP + COMMUNITIES (2)
    /// + LARGE_COMMUNITY (1), announced prefix 203.0.113.0/24.
    fn sample_update_body() -> Vec<u8> {
        let mut body = Vec::new();
        // withdrawn routes: one prefix 192.0.2.0/24
        let withdrawn: [u8; 4] = [24, 192, 0, 2];
        body.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
        body.extend_from_slice(&withdrawn);

        let mut attrs = Vec::new();
        attrs.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]); // ORIGIN = IGP
                                                            // AS_PATH: AS_SEQUENCE with 2 4-octet ASNs
        attrs.extend_from_slice(&[0x40, 0x02, 0x0A, 0x02, 0x02]);
        attrs.extend_from_slice(&65001u32.to_be_bytes());
        attrs.extend_from_slice(&65002u32.to_be_bytes());
        // NEXT_HOP
        attrs.extend_from_slice(&[0x40, 0x03, 0x04, 192, 0, 2, 254]);
        // COMMUNITIES: 64512:100, 64512:200
        let mut comms = Vec::new();
        comms.extend_from_slice(&64512u16.to_be_bytes());
        comms.extend_from_slice(&100u16.to_be_bytes());
        comms.extend_from_slice(&64512u16.to_be_bytes());
        comms.extend_from_slice(&200u16.to_be_bytes());
        attrs.push(0xC0);
        attrs.push(0x08);
        attrs.push(comms.len() as u8);
        attrs.extend_from_slice(&comms);
        // LARGE_COMMUNITY: 64496:1:2
        attrs.push(0xC0);
        attrs.push(0x20);
        attrs.push(12);
        attrs.extend_from_slice(&64496u32.to_be_bytes());
        attrs.extend_from_slice(&1u32.to_be_bytes());
        attrs.extend_from_slice(&2u32.to_be_bytes());

        body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        body.extend_from_slice(&attrs);
        // NLRI: 203.0.113.0/24
        body.extend_from_slice(&[24, 203, 0, 113]);
        body
    }

    fn find_node<'a>(node: &'a DissectionNode, field: &str) -> &'a DissectionNode {
        node.find(field)
            .unwrap_or_else(|| panic!("node {field} not found in tree"))
    }

    #[test]
    fn dissect_update_field_offsets() {
        let wire = bgp_wire(2, &sample_update_body());
        let tree = dissect_bgp_message(&wire, &AsnLength::Bits32, false);

        assert_eq!(tree.field, "bgp");
        assert_eq!(tree.offset, 0);
        assert_eq!(tree.length, wire.len() as u32);

        let marker = find_node(&tree, "bgp.header.marker");
        assert_eq!((marker.offset, marker.length), (0, 16));
        let length = find_node(&tree, "bgp.header.length");
        assert_eq!((length.offset, length.length), (16, 2));
        assert_eq!(length.label, format!("Length: {}", wire.len()));
        let msg_type = find_node(&tree, "bgp.header.type");
        assert_eq!((msg_type.offset, msg_type.length), (18, 1));

        // withdrawn length at 19, prefixes at 21
        let wlen = find_node(&tree, "bgp.update.withdrawn_routes.length");
        assert_eq!((wlen.offset, wlen.length), (19, 2));
        assert_eq!(wlen.label, "Withdrawn routes length: 4");
        let wr = find_node(&tree, "bgp.update.withdrawn_routes");
        assert_eq!((wr.offset, wr.length), (21, 4));
        let wprefix = find_node(&tree, "bgp.nlri.prefix");
        assert_eq!((wprefix.offset, wprefix.length), (21, 4));
        assert_eq!(wprefix.label, "192.0.2.0/24");

        // attr section
        let alen = find_node(&tree, "bgp.update.path_attributes.length");
        assert_eq!((alen.offset, alen.length), (25, 2));
        let attrs = find_node(&tree, "bgp.update.path_attributes");
        assert_eq!(attrs.offset, 27);

        // AS_PATH attr: 4 header + 10 value... actually 3 header + 10 value
        let as_path = find_node(&tree, "bgp.attr.2");
        assert_eq!((as_path.offset, as_path.length), (31, 13));
        let segment = find_node(&tree, "bgp.attr.as_path.segment");
        assert_eq!((segment.offset, segment.length), (34, 10));
        assert_eq!(segment.label, "AS_SEQUENCE: 65001 65002");

        // COMMUNITIES attr: header 3 + 8 value
        let comms = find_node(&tree, "bgp.attr.8");
        assert_eq!((comms.offset, comms.length), (51, 11));
        let mut entries = Vec::new();
        tree.find_all("bgp.attr.communities.entry", &mut entries);
        assert_eq!(entries.len(), 2);
        assert_eq!((entries[0].offset, entries[0].length), (54, 4));
        assert_eq!(entries[0].label, "Community [1]: 64512:100");
        assert_eq!(entries[1].label, "Community [2]: 64512:200");

        // LARGE_COMMUNITY attr
        let large = find_node(&tree, "bgp.attr.32");
        assert_eq!((large.offset, large.length), (62, 15));
        let entry = find_node(&tree, "bgp.attr.large_communities.entry");
        assert_eq!(entry.label, "Large community [1]: 64496:1:2");

        // NLRI
        let nlri = find_node(&tree, "bgp.update.nlri");
        assert_eq!(nlri.offset, 77);
        assert_eq!(nlri.length, 4);
    }

    #[test]
    fn dissect_update_mp_reach() {
        // MP_REACH_NLRI for IPv6: afi=2, safi=1, nh_len=16, nh, reserved, prefix
        let mut value = Vec::new();
        value.extend_from_slice(&2u16.to_be_bytes()); // AFI
        value.push(1); // SAFI
        value.push(16); // next hop length
        value.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        value.push(0); // reserved
        value.extend_from_slice(&[32, 0x20, 0x01, 0x0d, 0xb8]); // 2001:db8::/32

        let mut attrs = Vec::new();
        attrs.push(0x80);
        attrs.push(14);
        attrs.push(value.len() as u8);
        attrs.extend_from_slice(&value);

        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // no withdrawn
        body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        body.extend_from_slice(&attrs);

        let wire = bgp_wire(2, &body);
        let tree = dissect_bgp_message(&wire, &AsnLength::Bits32, false);

        let mp_reach = find_node(&tree, "bgp.attr.14");
        let afi = find_node(&tree, "bgp.attr.mp_reach.afi");
        assert_eq!(afi.label, "AFI: 2 (IPv6)");
        let nh = find_node(&tree, "bgp.attr.mp_reach.next_hop");
        assert_eq!(nh.length, 16);
        let prefix = tree.find("bgp.update.nlri");
        assert!(prefix.is_none(), "IPv6 NLRI lives inside MP_REACH");
        let mut prefixes = Vec::new();
        tree.find_all("bgp.nlri.prefix", &mut prefixes);
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].label, "2001:db8::/32");
        assert_eq!(mp_reach.length, 3 + value.len() as u32);
    }

    #[test]
    fn dissect_update_truncated_attribute_is_partial() {
        // AS_PATH attribute declaring more value than present
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes());
        let attrs = [0x40u8, 0x02, 0x0A, 0x02, 0x02, 0x0F, 0x9A]; // declares 10, has 4
        body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        body.extend_from_slice(&attrs);

        let wire = bgp_wire(2, &body);
        let tree = dissect_bgp_message(&wire, &AsnLength::Bits32, false);

        let as_path = find_node(&tree, "bgp.attr.2");
        assert!(as_path.label.contains("truncated"));
        assert_eq!(as_path.length, attrs.len() as u32);
    }

    #[test]
    fn dissect_open_capabilities() {
        // version 4, as 65001, hold 180, id 1.2.3.4, one capability param
        // containing MP Extensions (code 1) + 4-octet AS (code 65)
        let mut caps = Vec::new();
        caps.extend_from_slice(&[1, 4, 0, 1, 0, 1]); // afi 1 safi 1
        caps.extend_from_slice(&[65, 4, 0, 0, 0xFD, 0xE9]); // asn 65001

        let mut body = Vec::new();
        body.push(4);
        body.extend_from_slice(&65001u16.to_be_bytes());
        body.extend_from_slice(&180u16.to_be_bytes());
        body.extend_from_slice(&[1, 2, 3, 4]);
        body.push(2 + caps.len() as u8); // opt params len
        body.push(2); // param type: capabilities
        body.push(caps.len() as u8);
        body.extend_from_slice(&caps);

        let wire = bgp_wire(1, &body);
        let tree = dissect_bgp_message(&wire, &AsnLength::Bits16, false);

        let version = find_node(&tree, "bgp.open.version");
        assert_eq!((version.offset, version.length), (19, 1));
        let asn = find_node(&tree, "bgp.open.asn");
        assert_eq!(asn.label, "My AS: 65001");
        let mut capabilities = Vec::new();
        tree.find_all("bgp.open.capability", &mut capabilities);
        assert_eq!(capabilities.len(), 2);
        assert_eq!(
            capabilities[0].label,
            "Capability: Multiprotocol Extensions (1)"
        );
        assert_eq!(
            capabilities[1].label,
            "Capability: Support for 4-octet AS Number (65)"
        );
        assert_eq!(capabilities[0].offset, 19 + 10 + 2);
    }

    #[test]
    fn dissect_notification_and_route_refresh() {
        let notification = bgp_wire(3, &[6, 5, 0xDE, 0xAD]);
        let tree = dissect_bgp_message(&notification, &AsnLength::Bits16, false);
        let code = find_node(&tree, "bgp.notification.code");
        assert_eq!((code.offset, code.length), (19, 1));
        let data = find_node(&tree, "bgp.notification.data");
        assert_eq!(data.length, 2);

        let refresh = bgp_wire(5, &[0, 1, 0, 1, 0xDE, 0xAD, 0xBE]);
        let tree = dissect_bgp_message(&refresh, &AsnLength::Bits16, false);
        let subtype = find_node(&tree, "bgp.route_refresh.subtype");
        assert_eq!(subtype.label, "Subtype: 0");
        let orf = find_node(&tree, "bgp.route_refresh.data");
        assert_eq!(orf.length, 3);
    }

    #[test]
    fn dissect_keepalive_and_truncated_header() {
        let keepalive = bgp_wire(4, &[]);
        let tree = dissect_bgp_message(&keepalive, &AsnLength::Bits16, false);
        assert_eq!(tree.children.len(), 1, "header only, no body node");
        assert!(tree.find("bgp.header.type").is_some());

        let truncated = dissect_bgp_message(&[0xFF; 7], &AsnLength::Bits16, false);
        let header = find_node(&truncated, "bgp.header");
        assert!(header.label.contains("truncated"));
    }

    #[test]
    fn dissect_addpath_nlri() {
        // ADD-PATH NLRI: path id (4) + prefix length + octets
        let nlri = [0, 0, 0, 7, 24, 203, 0, 113];
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&nlri);

        let wire = bgp_wire(2, &body);
        let tree = dissect_bgp_message(&wire, &AsnLength::Bits32, true);
        let mut prefixes = Vec::new();
        tree.find_all("bgp.nlri.prefix", &mut prefixes);
        assert_eq!(prefixes.len(), 1);
        assert_eq!((prefixes[0].offset, prefixes[0].length), (23, 8));
        assert_eq!(prefixes[0].label, "203.0.113.0/24");
    }
}
