#![forbid(unsafe_code)]
/*!
Borrowed element views over MRT `TABLE_DUMP_V2` RIB records.

[`BgpkitParser::next_record_elems`](crate::BgpkitParser::next_record_elems) reads one record body
into a reusable buffer owned by the parser and lends a [`RecordElems`] batch over its RIB entries.
Each [`ElemRef`] yielded by [`RecordElems::iter`] borrows directly from the record body and the
active peer index table, decoding BGP attributes on demand without per-element heap allocation.
*/

use crate::error::ParserError;
use crate::models::{
    get_deprecated_attr_type, Afi, AsPath, AsPathSegment, Asn, AsnLength, AttrFlags, AttrRaw,
    AttrType, Bgp4MpType, BgpIdentifier, CommonHeader, Community, ElemType, ExtendedCommunity,
    Ipv6AddrExtCommunity, LargeCommunity, MetaCommunity, NetworkPrefix, Origin, Peer, PeerType,
    Safi,
};
use crate::parser::iters::handle_record_parse_error;
use crate::parser::mrt::frame::{assemble_error_bytes, FrameError, Framer};
use crate::parser::mrt::mrt_header::HeaderBuf;
use crate::parser::{BgpkitParser, ElemError, ReadUtils};
use crate::BgpElem;
use bytes::Bytes;
use ipnet::IpNet;
use log::{error, warn};
use std::cell::Cell;
use std::io::Read;
use std::marker::PhantomData;
use std::net::IpAddr;
use zerocopy::big_endian::U32 as BeU32;
use zerocopy::FromBytes;

const AS_PATH_AS_SET: u8 = 1;
const AS_PATH_AS_SEQUENCE: u8 = 2;
const AS_PATH_CONFED_SEQUENCE: u8 = 3;
const AS_PATH_CONFED_SET: u8 = 4;

const FLAG_AFI_IPV6: u8 = 1 << 0;
const FLAG_SAFI_MULTICAST: u8 = 1 << 1;
const FLAG_ADD_PATH: u8 = 1 << 2;
/// Set for an element of a `BGP4MP` update. A dump's entry decodes `NEXT_HOP` with the record's
/// family; an update's `NEXT_HOP` is always the IPv4 address RFC 4271 defines.
const FLAG_UPDATE: u8 = 1 << 3;

const SLOT_UNSCANNED: u64 = u64::MAX;
const SLOT_ABSENT: u64 = u64::MAX - 1;
const SLOT_MERGED: u64 = u64::MAX - 2;

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
    let flags = afi_flags(&nlri.afi, nlri.safi);
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
fn parse_peer_index_vec(data: &[u8]) -> Result<Vec<Peer>, ParserError> {
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
fn attribute_block_walks(mut attrs: &[u8]) -> bool {
    loop {
        if attrs.is_empty() {
            return true;
        }
        if attrs.len() < 3 {
            return false;
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
    let flags = afi_flags(&afi, safi);
    out.extend(prefixes.into_iter().map(|prefix| UpdateEntry {
        prefix,
        elem_type,
        flags,
    }));
}

fn afi_flags(afi: &Afi, safi: Safi) -> u8 {
    let mut flags = 0u8;
    if *afi == Afi::Ipv6 {
        flags |= FLAG_AFI_IPV6;
    }
    if safi == Safi::Multicast {
        flags |= FLAG_SAFI_MULTICAST;
    }
    flags
}

/// The borrowed elements of the update record currently in the frame buffer.
fn update_record_elems<'a>(
    state: &'a mut ElemViewState,
    body_len: usize,
    header: CommonHeader,
    peer_ip: IpAddr,
    peer_asn: Asn,
    timestamp: f64,
) -> Option<RecordElems<'a>> {
    let attrs = fill_update_entries(
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
    ))
}

/// Fill `out` with the elements of one `BGP4MP` update and return its attribute block.
///
/// Only the AS4 message subtypes are served: the borrowed attribute views read 4-byte AS numbers,
/// which is what those subtypes carry. Anything else returns `None` so the caller can say so and
/// leave the record to the owned path.
///
/// The order matches the owned iterator: announcements (plain NLRI, then `MP_REACH_NLRI`), then
/// withdrawals (plain, then `MP_UNREACH_NLRI`).
pub(crate) fn fill_update_entries<'a>(
    body: &'a [u8],
    subtype: u16,
    out: &mut Vec<UpdateEntry>,
) -> Option<&'a [u8]> {
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
    if message_len < 19 || message_len > rest.len() {
        return None;
    }
    rest = &rest[19..message_len];
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

    // MP_REACH and MP_UNREACH sit in the attribute block; find them without decoding anything else.
    let mut mp_reach: Option<&[u8]> = None;
    let mut mp_unreach: Option<&[u8]> = None;
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
            14 => mp_reach = Some(&attrs[start..end]),
            15 => mp_unreach = Some(&attrs[start..end]),
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
    if let Some(body) = mp_reach {
        append_mp_nlri(body, true, add_path, out);
    }
    append_nlri(
        withdrawn,
        Afi::Ipv4,
        Safi::Unicast,
        add_path,
        ElemType::WITHDRAW,
        out,
    );
    if let Some(body) = mp_unreach {
        append_mp_nlri(body, false, add_path, out);
    }
    Some(attrs)
}
