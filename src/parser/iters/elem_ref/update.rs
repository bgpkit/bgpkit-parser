//! The elements a `BGP4MP` update declares, and the walk that finds them.
//!
//! The NLRI sections and the attribute walk go through the owned parsers, so a family, a next-hop
//! width or an ADD-PATH guess behaves the same here as it does on the owned path.

use super::*;

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
/// Build the element batch for the update whose walk already ran.
pub(super) fn update_record_elems<'a>(
    state: &'a mut ElemViewState,
    body_len: usize,
    header: CommonHeader,
    peer_ip: IpAddr,
    peer_asn: Asn,
    timestamp: f64,
) -> Option<RecordElems<'a>> {
    let (offset, len) = state.update_attrs;
    let (entries, next_hop) = (&state.update_entries, state.update_next_hop);
    let attrs = state.body_buf.get(offset..offset.checked_add(len)?)?;
    // `body_len` bounds the active record; a range outside it means the walk and this read disagree.
    if offset + len > body_len {
        return None;
    }
    Some(RecordElems::update(
        header, entries, attrs, peer_ip, peer_asn, timestamp, next_hop,
    ))
}

/// Report a trailing attribute whose length runs past the block, as the owned walker does.
fn warn_on_truncated_attribute(attrs: &[u8]) {
    let mut rest = attrs;
    while let Some((_, value, next)) = next_attr_tlv(rest) {
        let _ = value;
        rest = next;
    }
    // The owned walker stops at three octets and reports the truncated attribute; a shorter tail is
    // silence there, so it is silence here.
    if rest.len() >= 3 {
        warn!(
            "attribute encodes a length longer than the remaining attribute data; ignoring the rest"
        );
    }
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

    // Each MP attribute is decoded here, once: the last one that decodes wins, as it does on the
    // owned path, and the record's next hop comes out of the same decode.
    let mut next_hop: Option<IpAddr> = None;
    let mut reach: Option<crate::models::Nlri> = None;
    let mut unreach: Option<crate::models::Nlri> = None;
    let mut plain_next_hop: Option<IpAddr> = None;
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
        let value = &attrs[start..end];
        match code {
            3 => {
                let mut value = value;
                if let Ok(address) = value.read_address(&Afi::Ipv4) {
                    plain_next_hop = Some(address);
                }
            }
            14 => {
                if let Ok(crate::models::AttributeValue::MpReachNlri(nlri)) =
                    crate::parser::bgp::attributes::parse_nlri(
                        bytes::Bytes::copy_from_slice(value),
                        &None,
                        &None,
                        &None,
                        true,
                        add_path,
                    )
                {
                    next_hop = nlri.next_hop.map(|next_hop| next_hop.global_addr());
                    reach = Some(nlri);
                }
            }
            15 => {
                if let Ok(crate::models::AttributeValue::MpUnreachNlri(nlri)) =
                    crate::parser::bgp::attributes::parse_nlri(
                        bytes::Bytes::copy_from_slice(value),
                        &None,
                        &None,
                        &None,
                        false,
                        add_path,
                    )
                {
                    unreach = Some(nlri);
                }
            }
            _ => {}
        }
        pos = end;
    }
    let next_hop = plain_next_hop.or(next_hop);

    append_nlri(
        announced,
        Afi::Ipv4,
        Safi::Unicast,
        add_path,
        ElemType::ANNOUNCE,
        out,
    );
    if let Some(nlri) = reach {
        push_nlri_entries(nlri, add_path, ElemType::ANNOUNCE, out);
    }
    append_nlri(
        withdrawn,
        Afi::Ipv4,
        Safi::Unicast,
        add_path,
        ElemType::WITHDRAW,
        out,
    );
    if let Some(nlri) = unreach {
        push_nlri_entries(nlri, add_path, ElemType::WITHDRAW, out);
    }
    Some((attrs, next_hop))
}

/// Append the prefixes one decoded `MP_REACH_NLRI` / `MP_UNREACH_NLRI` carries.
fn push_nlri_entries(
    nlri: crate::models::Nlri,
    _add_path: bool,
    elem_type: ElemType,
    out: &mut Vec<UpdateEntry>,
) {
    let flags = afi_flags(&nlri.afi, nlri.safi, _add_path);
    out.extend(nlri.prefixes.into_iter().map(|prefix| UpdateEntry {
        prefix,
        elem_type,
        flags,
    }));
}
