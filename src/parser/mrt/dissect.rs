//! Best-effort dissection of MRT records.
//!
//! Produces a [`DissectionNode`] tree over the whole record — common header
//! fields, the BGP4MP subheader for the message subtypes, and then delegation
//! into the embedded BGP message (see [`crate::parser::bgp::dissect`]) — so
//! every field of every layer shares one byte-offset coordinate space. Like
//! the BGP dissector this is a separate opt-in pass: it never runs on any
//! default iterator path and never fails on malformed input.

use crate::models::{AsnLength, DissectionNode};
use crate::parser::bgp::dissect::dissect_bgp_message_base;
use crate::parser::mrt::RawMrtRecord;

fn read_u16(data: &[u8], pos: usize) -> Option<u16> {
    let hi = *data.get(pos)?;
    let lo = *data.get(pos + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

fn entry_type_name(entry_type: u16) -> &'static str {
    match entry_type {
        12 => "TABLE_DUMP",
        13 => "TABLE_DUMP_V2",
        16 => "BGP4MP",
        17 => "BGP4MP_ET",
        32 => "ISIS",
        33 => "ISIS_ET",
        48 => "OSPFv3",
        49 => "OSPFv3_ET",
        _ => "UNKNOWN",
    }
}

/// Dissect one MRT record from its raw framing.
///
/// Offsets are relative to the start of the record (common header first). For
/// ET records the 4-byte microsecond timestamp is part of the header.
pub fn dissect_mrt_record(raw: &RawMrtRecord) -> DissectionNode {
    let mut buf = Vec::with_capacity(raw.total_bytes_len());
    buf.extend_from_slice(&raw.header_bytes);
    buf.extend_from_slice(&raw.message_bytes);
    dissect_mrt_bytes(&buf)
}

/// Dissect raw MRT record bytes, best-effort.
///
/// Accepts possibly-truncated input (e.g. bytes retained from a failed
/// parse): the tree covers whatever fields could be walked.
pub fn dissect_mrt_bytes(data: &[u8]) -> DissectionNode {
    let mut root = DissectionNode::new(
        "mrt",
        format!("MRT record ({} bytes)", data.len()),
        0,
        data.len() as u32,
    );
    if data.len() < 12 {
        if !data.is_empty() {
            root.children.push(DissectionNode::new(
                "mrt.header",
                format!("Common header (truncated, {} of 12 bytes)", data.len()),
                0,
                data.len() as u32,
            ));
        }
        return root;
    }

    let entry_type = read_u16(data, 4).unwrap_or(0);
    let sub_type = read_u16(data, 6).unwrap_or(0);

    // ET variants (RFC 6396) carry a 4-byte microsecond field after the
    // standard 12-byte header.
    let is_et = matches!(entry_type, 17 | 33 | 49);
    let header_len = if is_et && data.len() >= 16 { 16 } else { 12 };

    let mut header = DissectionNode::new("mrt.header", "Common header", 0, header_len as u32);
    let timestamp = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    header.children.push(DissectionNode::new(
        "mrt.header.timestamp",
        format!("Timestamp: {timestamp}"),
        0,
        4,
    ));
    header.children.push(DissectionNode::new(
        "mrt.header.type",
        format!("Type: {} ({entry_type})", entry_type_name(entry_type)),
        4,
        2,
    ));
    header.children.push(DissectionNode::new(
        "mrt.header.subtype",
        format!("Subtype: {sub_type}"),
        6,
        2,
    ));
    let length = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    header.children.push(DissectionNode::new(
        "mrt.header.length",
        format!("Length: {length}"),
        8,
        4,
    ));
    if header_len == 16 {
        header.children.push(DissectionNode::new(
            "mrt.header.microsecond",
            format!(
                "Microsecond timestamp: {}",
                u32::from_be_bytes([data[12], data[13], data[14], data[15]])
            ),
            12,
            4,
        ));
    }
    root.children.push(header);

    let body = &data[header_len.min(data.len())..];
    let body_base = header_len as u32;
    if body.is_empty() {
        return root;
    }

    let body_node = match entry_type {
        16 | 17 => dissect_bgp4mp(body, body_base, sub_type),
        _ => DissectionNode::new(
            "mrt.body",
            format!("Message body ({} bytes)", body.len()),
            body_base,
            body.len() as u32,
        ),
    };
    root.children.push(body_node);
    root
}

/// Dissect the body of a BGP4MP / BGP4MP_ET record: the peer/local subheader
/// plus the embedded BGP message.
///
/// Message subtypes carry peer AS, local AS, interface index, AFI, peer and
/// local addresses, then the BGP message. State-change subtypes replace the
/// BGP message with old/new session states. Old Zebra records sometimes omit
/// the interface/AFI/address section entirely (see
/// `parse_bgp4mp_message`); that layout is detected and noted.
fn dissect_bgp4mp(data: &[u8], base: u32, sub_type: u16) -> DissectionNode {
    let as4 = matches!(sub_type, 4 | 5 | 7 | 9 | 11);
    let asn_size = if as4 { 4 } else { 2 };
    let add_path = matches!(sub_type, 8..=11);
    let asn_len = if as4 {
        AsnLength::Bits32
    } else {
        AsnLength::Bits16
    };
    let is_message = !matches!(sub_type, 0 | 5);

    let mut node = DissectionNode::new(
        "mrt.bgp4mp",
        format!(
            "BGP4MP {} ({sub_type})",
            if is_message {
                "message"
            } else {
                "state change"
            }
        ),
        base,
        data.len() as u32,
    );

    let mut pos = 0usize;

    if data.len() < 2 * asn_size {
        node.children.push(DissectionNode::new(
            "mrt.bgp4mp.truncated",
            format!(
                "Subheader (truncated: {} of at least {} bytes)",
                data.len(),
                2 * asn_size
            ),
            base,
            data.len() as u32,
        ));
        return node;
    }

    let peer_asn = read_asn(data, 0, asn_size);
    let local_asn = read_asn(data, asn_size, asn_size);
    push_field(
        &mut node,
        "mrt.bgp4mp.peer_asn",
        format!("Peer ASN: {peer_asn}"),
        base,
        asn_size,
    );
    pos += asn_size;
    push_field(
        &mut node,
        "mrt.bgp4mp.local_asn",
        format!("Local ASN: {local_asn}"),
        base + pos as u32,
        asn_size,
    );
    pos += asn_size;

    // Old Zebra compatibility: some records jump straight from the two ASNs
    // to the BGP marker, omitting interface index, AFI, and addresses.
    let rest = &data[pos..];
    if rest.len() >= 16 && rest[..16].iter().all(|b| *b == 0xFF) {
        node.children.push(DissectionNode::new(
            "mrt.bgp4mp.zebra_compat",
            "Missing interface/AFI/address fields (old Zebra record)",
            base + pos as u32,
            0,
        ));
        node.children.push(dissect_bgp_message_base(
            rest,
            base + pos as u32,
            &asn_len,
            add_path,
        ));
        return node;
    }

    if data.len() < pos + 4 {
        node.children.push(DissectionNode::new(
            "mrt.bgp4mp.truncated",
            "Truncated before interface index / AFI",
            base + pos as u32,
            (data.len() - pos) as u32,
        ));
        return node;
    }
    let afi = read_u16(data, pos + 2).unwrap_or(0);
    push_field(
        &mut node,
        "mrt.bgp4mp.interface_index",
        format!("Interface index: {}", read_u16(data, pos).unwrap_or(0)),
        base + pos as u32,
        2,
    );
    pos += 2;
    push_field(
        &mut node,
        "mrt.bgp4mp.afi",
        format!(
            "Address family: {afi} ({})",
            match afi {
                1 => "IPv4",
                2 => "IPv6",
                _ => "unknown",
            }
        ),
        base + pos as u32,
        2,
    );
    pos += 2;
    let addr_len = match afi {
        1 => 4,
        2 => 16,
        _ => {
            node.children.push(DissectionNode::new(
                "mrt.bgp4mp.addresses",
                format!("Unknown AFI {afi}; cannot walk further"),
                base + pos as u32,
                (data.len() - pos) as u32,
            ));
            return node;
        }
    };

    if is_message {
        if data.len() < pos + 2 * addr_len {
            node.children.push(DissectionNode::new(
                "mrt.bgp4mp.truncated",
                "Truncated peer/local addresses",
                base + pos as u32,
                (data.len() - pos) as u32,
            ));
            return node;
        }
        push_field(
            &mut node,
            "mrt.bgp4mp.peer_ip",
            format!("Peer IP: {}", render_ip(&data[pos..pos + addr_len])),
            base + pos as u32,
            addr_len,
        );
        pos += addr_len;
        push_field(
            &mut node,
            "mrt.bgp4mp.local_ip",
            format!("Local IP: {}", render_ip(&data[pos..pos + addr_len])),
            base + pos as u32,
            addr_len,
        );
        pos += addr_len;

        node.children.push(dissect_bgp_message_base(
            &data[pos..],
            base + pos as u32,
            &asn_len,
            add_path,
        ));
    } else {
        // State change: addresses, then old/new session states
        if data.len() < pos + 2 * addr_len + 4 {
            node.children.push(DissectionNode::new(
                "mrt.bgp4mp.truncated",
                "Truncated addresses or states",
                base + pos as u32,
                (data.len() - pos) as u32,
            ));
            return node;
        }
        push_field(
            &mut node,
            "mrt.bgp4mp.peer_ip",
            format!("Peer IP: {}", render_ip(&data[pos..pos + addr_len])),
            base + pos as u32,
            addr_len,
        );
        pos += addr_len;
        push_field(
            &mut node,
            "mrt.bgp4mp.local_ip",
            format!("Local IP: {}", render_ip(&data[pos..pos + addr_len])),
            base + pos as u32,
            addr_len,
        );
        pos += addr_len;
        let old_state = read_u16(data, pos).unwrap_or(0);
        push_field(
            &mut node,
            "mrt.bgp4mp.old_state",
            format!("Old state: {} ({})", old_state, bgp_state_name(old_state)),
            base + pos as u32,
            2,
        );
        pos += 2;
        let new_state = read_u16(data, pos).unwrap_or(0);
        push_field(
            &mut node,
            "mrt.bgp4mp.new_state",
            format!("New state: {} ({})", new_state, bgp_state_name(new_state)),
            base + pos as u32,
            2,
        );
    }

    node
}

fn push_field(node: &mut DissectionNode, field: &str, label: String, offset: u32, len: usize) {
    node.children
        .push(DissectionNode::new(field, label, offset, len as u32));
}

fn read_asn(data: &[u8], pos: usize, asn_size: usize) -> u32 {
    if asn_size == 4 {
        u32::from_be_bytes([
            *data.get(pos).unwrap_or(&0),
            *data.get(pos + 1).unwrap_or(&0),
            *data.get(pos + 2).unwrap_or(&0),
            *data.get(pos + 3).unwrap_or(&0),
        ])
    } else {
        read_u16(data, pos).unwrap_or(0) as u32
    }
}

fn render_ip(octets: &[u8]) -> String {
    if octets.len() == 4 {
        format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
    } else {
        octets
            .chunks(2)
            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
            .collect::<Vec<_>>()
            .join(":")
    }
}

fn bgp_state_name(state: u16) -> &'static str {
    match state {
        1 => "Idle",
        2 => "Connect",
        3 => "Active",
        4 => "OpenSent",
        5 => "OpenConfirm",
        6 => "Established",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one BGP4MP_MESSAGE_AS4 MRT record with a minimal UPDATE inside,
    /// returning the full record wire bytes.
    fn bgp4mp_update_record() -> Vec<u8> {
        // UPDATE body: no withdrawn, ORIGIN+AS_PATH+NEXT_HOP, one prefix
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        attrs.extend_from_slice(&[0x40, 0x02, 0x06, 0x02, 0x01]);
        attrs.extend_from_slice(&65001u32.to_be_bytes());
        attrs.extend_from_slice(&[0x40, 0x03, 0x04, 192, 0, 2, 254]);
        let mut update = Vec::new();
        update.extend_from_slice(&0u16.to_be_bytes());
        update.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        update.extend_from_slice(&attrs);
        update.extend_from_slice(&[24, 203, 0, 113]);

        // BGP message with header
        let mut bgp = vec![0xFF; 16];
        bgp.extend_from_slice(&((19 + update.len()) as u16).to_be_bytes());
        bgp.push(2);
        bgp.extend_from_slice(&update);

        // BGP4MP body
        let mut body = Vec::new();
        body.extend_from_slice(&64496u32.to_be_bytes());
        body.extend_from_slice(&64497u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // interface index
        body.extend_from_slice(&1u16.to_be_bytes()); // AFI IPv4
        body.extend_from_slice(&[192, 0, 2, 1]); // peer IP
        body.extend_from_slice(&[192, 0, 2, 2]); // local IP
        body.extend_from_slice(&bgp);

        // MRT common header: type 16, subtype 4 (BGP4MP_MESSAGE_AS4)
        let mut wire = Vec::new();
        wire.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        wire.extend_from_slice(&16u16.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(&body);
        wire
    }

    #[test]
    fn dissect_mrt_record_layered_offsets() {
        let wire = bgp4mp_update_record();
        let tree = dissect_mrt_bytes(&wire);

        assert_eq!(tree.field, "mrt");
        assert_eq!(tree.length, wire.len() as u32);

        let timestamp = tree.find("mrt.header.timestamp").unwrap();
        assert_eq!((timestamp.offset, timestamp.length), (0, 4));
        let entry_type = tree.find("mrt.header.type").unwrap();
        assert_eq!(entry_type.label, "Type: BGP4MP (16)");
        let subtype = tree.find("mrt.header.subtype").unwrap();
        assert_eq!(subtype.label, "Subtype: 4");

        // BGP4MP subheader at offset 12
        let peer_asn = tree.find("mrt.bgp4mp.peer_asn").unwrap();
        assert_eq!((peer_asn.offset, peer_asn.length), (12, 4));
        assert_eq!(peer_asn.label, "Peer ASN: 64496");
        let afi = tree.find("mrt.bgp4mp.afi").unwrap();
        assert_eq!(afi.offset, 22);
        assert_eq!(afi.label, "Address family: 1 (IPv4)");
        let peer_ip = tree.find("mrt.bgp4mp.peer_ip").unwrap();
        assert_eq!(peer_ip.label, "Peer IP: 192.0.2.1");

        // Embedded BGP message shares the record coordinate space
        let marker = tree.find("bgp.header.marker").unwrap();
        assert_eq!(marker.offset, 12 + 20);
        let segment = tree.find("bgp.attr.as_path.segment").unwrap();
        assert_eq!(segment.label, "AS_SEQUENCE: 65001");
        let prefix = tree.find("bgp.update.nlri").unwrap();
        assert_eq!(prefix.offset + prefix.length, wire.len() as u32);
    }

    #[test]
    fn dissect_mrt_record_from_raw() {
        // chunk one record and dissect via the RawMrtRecord API
        let wire = bgp4mp_update_record();
        let mut cursor = std::io::Cursor::new(wire.clone());
        let raw = crate::parser::mrt::chunk_mrt_record(&mut cursor).unwrap();
        let tree = dissect_mrt_record(&raw);
        assert_eq!(tree.length, wire.len() as u32);
        assert!(tree.find("bgp.header.type").is_some());
    }

    #[test]
    fn dissect_mrt_state_change() {
        let mut body = Vec::new();
        body.extend_from_slice(&64496u16.to_be_bytes());
        body.extend_from_slice(&64497u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[192, 0, 2, 1]);
        body.extend_from_slice(&[192, 0, 2, 2]);
        body.extend_from_slice(&5u16.to_be_bytes()); // OpenConfirm
        body.extend_from_slice(&6u16.to_be_bytes()); // Established

        let mut wire = Vec::new();
        wire.extend_from_slice(&2u32.to_be_bytes());
        wire.extend_from_slice(&16u16.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes()); // STATE_CHANGE
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(&body);

        let tree = dissect_mrt_bytes(&wire);
        let new_state = tree.find("mrt.bgp4mp.new_state").unwrap();
        assert_eq!(new_state.label, "New state: 6 (Established)");
        assert_eq!(new_state.offset, wire.len() as u32 - 2);
    }

    #[test]
    fn dissect_mrt_truncated_header_and_unknown_type() {
        let partial = dissect_mrt_bytes(&[0, 0, 0, 1, 0]);
        let header = partial.find("mrt.header").unwrap();
        assert!(header.label.contains("truncated"));

        // TABLE_DUMP_V2 record body stays opaque
        let mut wire = Vec::new();
        wire.extend_from_slice(&1u32.to_be_bytes());
        wire.extend_from_slice(&13u16.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&4u32.to_be_bytes());
        wire.extend_from_slice(&[0xAA; 4]);
        let tree = dissect_mrt_bytes(&wire);
        let body = tree.find("mrt.body").unwrap();
        assert_eq!(body.label, "Message body (4 bytes)");
    }

    #[test]
    fn dissect_mrt_zebra_compat_detected() {
        // Two 16-bit ASNs followed directly by a BGP marker
        let mut bgp = vec![0xFF; 16];
        bgp.extend_from_slice(&19u16.to_be_bytes());
        bgp.push(4); // KEEPALIVE

        let mut body = Vec::new();
        body.extend_from_slice(&64496u16.to_be_bytes());
        body.extend_from_slice(&64497u16.to_be_bytes());
        body.extend_from_slice(&bgp);

        let mut wire = Vec::new();
        wire.extend_from_slice(&1u32.to_be_bytes());
        wire.extend_from_slice(&16u16.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes()); // BGP4MP_MESSAGE
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(&body);

        let tree = dissect_mrt_bytes(&wire);
        assert!(tree.find("mrt.bgp4mp.zebra_compat").is_some());
        assert!(tree.find("bgp.header.type").is_some());
    }
}
