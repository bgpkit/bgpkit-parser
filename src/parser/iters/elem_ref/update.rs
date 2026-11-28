//! The elements a `BGP4MP` update declares, and the walk that finds them.
//!
//! The NLRI sections and the attribute walk go through the owned parsers, so a family, a next-hop
//! width or an ADD-PATH guess behaves the same here as it does on the owned path.

use super::*;

/// Append the prefixes of one `MP_REACH_NLRI` or `MP_UNREACH_NLRI` body.
///
/// The body goes to the owned NLRI parser, so every family it understands (labelled, VPN, flow-spec,
/// EVPN, link-state), the reserved octet, the next-hop widths it accepts, and the ADD-PATH guess in
/// a block that starts with zero all behave exactly as they do on the owned path.
fn append_mp_nlri(body: &[u8], reachable: bool, add_path: bool, out: &mut Vec<UpdateEntry>) {
    let Ok(value) = crate::parser::bgp::attributes::parse_nlri(
        bytes::Bytes::copy_from_slice(body),
        &None,
        &None,
        &None,
        reachable,
        add_path,
    ) else {
        return;
    };
    let nlri = match value {
        crate::models::AttributeValue::MpReachNlri(nlri)
        | crate::models::AttributeValue::MpUnreachNlri(nlri) => nlri,
        _ => return,
    };
    let elem_type = if reachable {
        ElemType::ANNOUNCE
    } else {
        ElemType::WITHDRAW
    };
    let flags = afi_flags(&nlri.afi, nlri.safi, add_path);
    out.extend(nlri.prefixes.into_iter().map(|prefix| UpdateEntry {
        prefix,
        elem_type,
        flags,
    }));
}

/// The peers of a `PEER_INDEX_TABLE` body, in the order their indices name.
///
/// The owned parser decodes the table; this only turns its map back into a vector, so the hot path
/// keeps an indexed lookup and the wire format has one owner.
pub(super) fn parse_peer_index_vec(data: &[u8]) -> Result<Vec<Peer>, ParserError> {
    let table =
        crate::parser::mrt::messages::table_dump_v2::peer_index_table::parse_peer_index_table(
            &mut bytes::Bytes::copy_from_slice(data),
        )?;
    let mut peers_by_index = table.id_peer_map;
    let count = peers_by_index
        .keys()
        .max()
        .map_or(0, |max| *max as usize + 1);
    let mut peers = Vec::with_capacity(count);
    for index in 0..count {
        match peers_by_index.remove(&(index as u16)) {
            Some(peer) => peers.push(peer),
            // An index the table skips would silently shift every later peer.
            None => {
                return Err(ParserError::ParseError(format!(
                    "peer index table skips index {index}"
                )))
            }
        }
    }
    Ok(peers)
}

/// Whether every attribute header in the block can be read.
///
/// The owned path fails the record when a header itself is unreadable, because it cannot tell where
/// the next attribute begins: three octets left with the extended-length flag set is that case. A
/// body that runs past the end is different — the owned path keeps the attributes it already read
/// and records a finding — so that ends the walk instead of failing it.
pub(super) fn attribute_block_walks(mut attrs: &[u8]) -> bool {
    loop {
        // The owned walker stops when fewer than three octets remain and accepts what it has, so a
        // trailing fragment is not a defect; only an unreadable header is.
        if attrs.len() < 3 {
            return true;
        }
        let (header_len, body_len) = if attrs[0] & 0x10 != 0 {
            if attrs.len() < 4 {
                return false;
            }
            (4usize, u16::from_be_bytes([attrs[2], attrs[3]]) as usize)
        } else {
            (3usize, attrs[2] as usize)
        };
        match attrs.get(header_len + body_len..) {
            Some(rest) => attrs = rest,
            None => return true,
        }
    }
}

/// Append the prefixes of one NLRI section, using the same parser the owned path uses.
///
/// Sharing that parser is the point: it carries the ADD-PATH heuristic for a block that starts with
/// `0x00`, and a section it cannot read contributes no prefixes here exactly as it contributes none
/// there.
fn append_nlri(
    section: &[u8],
    afi: Afi,
    safi: Safi,
    add_path: bool,
    elem_type: ElemType,
    out: &mut Vec<UpdateEntry>,
) {
    if section.is_empty() {
        return;
    }
    let Ok(prefixes) = crate::parser::utils::parse_nlri_list(
        bytes::Bytes::copy_from_slice(section),
        add_path,
        &afi,
    ) else {
        return;
    };
    let flags = afi_flags(&afi, safi, add_path);
    out.extend(prefixes.into_iter().map(|prefix| UpdateEntry {
        prefix,
        elem_type,
        flags,
    }));
}

fn afi_flags(afi: &Afi, safi: Safi, add_path: bool) -> u8 {
    let mut flags = 0u8;
    if add_path {
        flags |= crate::parser::mrt::frame::FLAG_ADD_PATH;
    }
    if *afi == Afi::Ipv6 {
        flags |= FLAG_AFI_IPV6;
    }
    if safi == Safi::Multicast {
        flags |= FLAG_SAFI_MULTICAST;
    }
    flags
}

/// The borrowed elements of the update record currently in the frame buffer.
pub(super) fn update_record_elems<'a>(
    state: &'a mut ElemViewState,
    body_len: usize,
    header: CommonHeader,
    peer_ip: IpAddr,
    peer_asn: Asn,
    timestamp: f64,
) -> Option<RecordElems<'a>> {
    let (attrs, next_hop) = fill_update_entries(
        &state.body_buf[..body_len],
        header.entry_subtype,
        &mut state.update_entries,
    )?;
    Some(RecordElems::update(
        header,
        &state.update_entries,
        attrs,
        peer_ip,
        peer_asn,
        timestamp,
        next_hop,
    ))
}

/// Report a trailing attribute whose length runs past the block, as the owned walker does.
fn warn_on_truncated_attribute(attrs: &[u8]) {
    let mut rest = attrs;
    while let Some((_, value, next)) = next_attr_tlv(rest) {
        let _ = value;
        rest = next;
    }
    if !rest.is_empty() && rest.len() < 3 {
        warn!(
            "attribute block ends with {} octets that cannot hold an attribute header; ignoring them",
            rest.len()
        );
    }
}

/// Fill `out` with the elements of one `BGP4MP` update and return its attribute block.
///
/// Only the AS4 message subtypes are served: the borrowed attribute views read 4-byte AS numbers,
/// which is what those subtypes carry. Anything else returns `None` so the caller can say so and
/// leave the record to the owned path.
///
/// The order matches the owned iterator: announcements (plain NLRI, then `MP_REACH_NLRI`), then
/// withdrawals (plain, then `MP_UNREACH_NLRI`).
/// The next hop every element of one update shares: `NEXT_HOP` when present, else `MP_REACH_NLRI`,
/// which is the order the owned path applies.
fn record_next_hop(attrs: &[u8], add_path: bool) -> Option<IpAddr> {
    let mut plain = None;
    let mut from_mp = None;
    let mut rest = attrs;
    while let Some((code, value, next)) = next_attr_tlv(rest) {
        rest = next;
        match code {
            3 => {
                let mut value = value;
                if let Ok(address) = value.read_address(&Afi::Ipv4) {
                    plain = Some(address);
                }
            }
            14 => from_mp = update_mp_reach_next_hop(value, add_path).or(from_mp),
            _ => {}
        }
    }
    plain.or(from_mp)
}

pub(crate) fn fill_update_entries<'a>(
    body: &'a [u8],
    subtype: u16,
    out: &mut Vec<UpdateEntry>,
) -> Option<(&'a [u8], Option<IpAddr>)> {
    out.clear();
    let add_path = match Bgp4MpType::try_from(subtype).ok()? {
        Bgp4MpType::MessageAs4 | Bgp4MpType::MessageAs4Local => false,
        Bgp4MpType::MessageAs4Addpath | Bgp4MpType::MessageLocalAs4Addpath => true,
        _ => return None,
    };
    let mut rest = body.get(4 * 2..)?;
    if rest.len() < 4 {
        return None;
    }
    let ip_len = match u16::from_be_bytes([rest[2], rest[3]]) {
        1 => 4,
        2 => 16,
        _ => return None,
    };
    rest = rest.get(4 + ip_len * 2..)?;
    // The BGP message: 16-byte marker, a two-byte length counting the whole message, and a one-byte
    // type. Only an UPDATE carries NLRI, and the length bounds what follows: the owned parser
    // rejects a body that runs past it, and octets after it are not NLRI.
    if rest.len() < 19 || rest[18] != 2 {
        return None;
    }
    let message_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
    if message_len < 19 {
        return None;
    }
    // The owned parser clamps a declared length that runs past the body instead of rejecting the
    // record, so the same octets are read here.
    rest = rest.get(19..message_len.min(rest.len()))?;
    if rest.len() < 2 {
        return None;
    }
    let withdrawn_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    rest = rest.get(2..)?;
    if rest.len() < withdrawn_len + 2 {
        return None;
    }
    let withdrawn = &rest[..withdrawn_len];
    rest = &rest[withdrawn_len..];
    let attr_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    rest = rest.get(2..)?;
    if rest.len() < attr_len {
        return None;
    }
    let attrs = &rest[..attr_len];
    let announced = &rest[attr_len..];
    // An attribute block that cannot be walked fails the whole UPDATE on the owned path, including
    // when the walker never reaches an MP attribute.
    if !attribute_block_walks(attrs) {
        return None;
    }
    // One record, one warning: a trailing attribute that runs past the block is reported here
    // instead of once per element the record yields.
    warn_on_truncated_attribute(attrs);

    // MP_REACH and MP_UNREACH sit in the attribute block; find them without decoding anything else.
    // Every occurrence is kept: a malformed duplicate must not hide an earlier valid attribute, so
    // each is tried and the last one that decodes wins, as it does on the owned path.
    let mut mp_reach: Vec<&[u8]> = Vec::new();
    let mut mp_unreach: Vec<&[u8]> = Vec::new();
    let mut pos = 0usize;
    while pos + 3 <= attrs.len() {
        let flags = attrs[pos];
        let code = attrs[pos + 1];
        let (header_len, body_len) = if flags & 0x10 != 0 {
            if pos + 4 > attrs.len() {
                break;
            }
            (
                4usize,
                u16::from_be_bytes([attrs[pos + 2], attrs[pos + 3]]) as usize,
            )
        } else {
            (3usize, attrs[pos + 2] as usize)
        };
        let start = pos + header_len;
        let end = start + body_len;
        if end > attrs.len() {
            break;
        }
        match code {
            14 => mp_reach.push(&attrs[start..end]),
            15 => mp_unreach.push(&attrs[start..end]),
            _ => {}
        }
        pos = end;
    }

    append_nlri(
        announced,
        Afi::Ipv4,
        Safi::Unicast,
        add_path,
        ElemType::ANNOUNCE,
        out,
    );
    for body in &mp_reach {
        append_mp_nlri(body, true, add_path, out);
    }
    // The record's next hop is decoded once here: every element it yields shares it, and decoding
    // it per element would re-parse the NLRI of every prefix for each one.
    let next_hop = record_next_hop(attrs, add_path);
    append_nlri(
        withdrawn,
        Afi::Ipv4,
        Safi::Unicast,
        add_path,
        ElemType::WITHDRAW,
        out,
    );
    for body in &mp_unreach {
        append_mp_nlri(body, false, add_path, out);
    }
    Some((attrs, next_hop))
}
