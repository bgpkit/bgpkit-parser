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
    ExtendedCommunityType, FlowSpecTrafficAction, FlowSpecTrafficMarking, FlowSpecTrafficRate,
    FourOctetAsExtCommunity, Ipv4AddrExtCommunity, Ipv6AddrExtCommunity, LargeCommunity,
    LinkBandwidth, MacMobility, MetaCommunity, NetworkPrefix, OpaqueExtCommunity, Origin, Peer,
    PeerType, Safi, TwoOctetAsExtCommunity,
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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zerocopy::big_endian::U32 as BeU32;
use zerocopy::FromBytes;

const AS_PATH_AS_SET: u8 = 1;
const AS_PATH_AS_SEQUENCE: u8 = 2;
const AS_PATH_CONFED_SEQUENCE: u8 = 3;
const AS_PATH_CONFED_SET: u8 = 4;

const COMMUNITY_NO_EXPORT: u32 = 0xFFFF_FF01;
const COMMUNITY_NO_ADVERTISE: u32 = 0xFFFF_FF02;
const COMMUNITY_NO_EXPORT_SUBCONFED: u32 = 0xFFFF_FF03;

const FLAG_AFI_IPV6: u8 = 1 << 0;
const FLAG_SAFI_MULTICAST: u8 = 1 << 1;
const FLAG_ADD_PATH: u8 = 1 << 2;
/// Set for an element of a `BGP4MP` update. A dump's entry decodes `NEXT_HOP` with the record's
/// family; an update's `NEXT_HOP` is always the IPv4 address RFC 4271 defines.
const FLAG_UPDATE: u8 = 1 << 3;

const SLOT_UNSCANNED: u64 = u64::MAX;
const SLOT_ABSENT: u64 = u64::MAX - 1;
const SLOT_MERGED: u64 = u64::MAX - 2;

/// Reusable parser-owned state backing [`BgpkitParser::next_record_elems`].
///
/// All buffers start empty (`0` heap capacity) so parsers that never call `next_record_elems`
/// pay no allocation overhead.
#[derive(Default)]
pub(crate) struct ElemViewState {
    /// Reusable buffer holding the wire body of the active MRT record.
    ///
    /// The buffer keeps its allocation across records; the active record body is
    /// `&body_buf[..active_len]`.
    pub(crate) body_buf: Vec<u8>,
    /// Shared framing: common header plus the body read into `body_buf`.
    pub(crate) framer: Framer,
    /// Active `TABLE_DUMP_V2` `PeerIndexTable` indexed directly by wire `peer_index`.
    peers: Option<Vec<Peer>>,
    /// NLRI of the `BGP4MP` update the current [`RecordElems`] batch covers.
    pub(crate) update_entries: Vec<UpdateEntry>,
    /// Set once EOF or a non-recoverable framing/core-dump error ends iteration.
    finished: bool,
}

fn parse_peer_index_vec(mut data: &[u8]) -> Result<Vec<Peer>, ParserError> {
    let _collector_bgp_id = data.read_u32()?;
    let view_name_len = data.read_u16()? as usize;
    data.has_n_remaining(view_name_len)?;
    data = &data[view_name_len..];

    let peer_count = data.read_u16()? as usize;
    // Each peer entry is at least 1 (type) + 4 (bgp_id) + 4 (ipv4) + 2 (asn16) = 11 bytes.
    let reserve = peer_count.min(data.len() / 11);
    let mut peers = Vec::with_capacity(reserve);

    for _ in 0..peer_count {
        let peer_type = PeerType::from_bits_retain(data.read_u8()?);
        let afi = if peer_type.contains(PeerType::ADDRESS_FAMILY_IPV6) {
            Afi::Ipv6
        } else {
            Afi::Ipv4
        };
        let asn_len = if peer_type.contains(PeerType::AS_SIZE_32BIT) {
            AsnLength::Bits32
        } else {
            AsnLength::Bits16
        };
        let peer_bgp_id = Ipv4Addr::from(data.read_u32()?);
        let peer_ip = data.read_address(&afi)?;
        let peer_asn = data.read_asn(asn_len)?;
        peers.push(Peer {
            peer_type,
            peer_bgp_id,
            peer_ip,
            peer_asn,
        });
    }

    Ok(peers)
}

fn validate_geo_peer_table(mut data: &[u8]) -> Result<(), ParserError> {
    let _collector_bgp_id = data.read_u32()?;
    let view_name_len = data.read_u16()? as usize;
    data.has_n_remaining(view_name_len)?;
    data = &data[view_name_len..];
    data.has_n_remaining(8)?;
    data = &data[8..];
    let peer_count = data.read_u16()? as usize;
    for _ in 0..peer_count {
        let peer_type = PeerType::from_bits_retain(data.read_u8()?);
        let ip_bytes = if peer_type.contains(PeerType::ADDRESS_FAMILY_IPV6) {
            16
        } else {
            4
        };
        let asn_bytes = if peer_type.contains(PeerType::AS_SIZE_32BIT) {
            4
        } else {
            2
        };
        let skip = 4 + ip_bytes + asn_bytes + 8;
        data.has_n_remaining(skip)?;
        data = &data[skip..];
    }
    Ok(())
}

/// Frame the next record, returning owned framing metadata and leaving the body in
/// `elem_view_state.body_buf`, so no borrow outlives the call.
fn frame_next<R: Read>(
    parser: &mut BgpkitParser<R>,
) -> Result<(CommonHeader, HeaderBuf, usize), FrameError> {
    let state = &mut parser.elem_view_state;
    let frame = state.framer.next(&mut parser.reader, &mut state.body_buf)?;
    Ok((frame.header, frame.raw_header, frame.body.len()))
}

/// What the borrowed element engine produced for the next record.
pub(crate) enum NextBatch<'a> {
    /// A RIB record's elements, borrowed from the parser's record buffer.
    Rib(RecordElems<'a>),
    /// A record this engine does not serve. Its body is still in the parser's buffer, untouched.
    Other {
        header: CommonHeader,
        raw_header: crate::parser::mrt::mrt_header::HeaderBuf,
        body_len: usize,
    },
    /// End of input.
    End,
}

/// Advance to the next record and report whether the borrowed element engine can serve it.
///
/// Unlike [`next_record_elems_impl`], this stops at the first record the engine cannot serve
/// instead of skipping it, so a caller can hand that record to the owned path.
pub(crate) fn next_batch<R: Read>(parser: &mut BgpkitParser<R>) -> NextBatch<'_> {
    use crate::parser::mrt::frame::{classify, RecordKind};

    if parser.text_dump_iter.is_some() || parser.elem_view_state.finished {
        return NextBatch::End;
    }

    loop {
        let (header, raw_header, body_len) = match frame_next(parser) {
            Ok(framed) => framed,
            Err(failure) => {
                if matches!(failure.error, ParserError::EofExpected) {
                    parser.elem_view_state.finished = true;
                    return NextBatch::End;
                }
                if !handle_record_parse_error(parser, failure.error, failure.bytes) {
                    parser.elem_view_state.finished = true;
                    return NextBatch::End;
                }
                continue;
            }
        };

        let body = &parser.elem_view_state.body_buf[..body_len];
        match classify(&header, body) {
            RecordKind::PeerIndex => {
                match parse_peer_index_vec(body) {
                    Ok(peers) => parser.elem_view_state.peers = Some(peers),
                    Err(err) => {
                        let raw = parser
                            .core_dump
                            .then(|| assemble_error_bytes(raw_header.as_slice(), body));
                        if !handle_record_parse_error(parser, err, raw) {
                            parser.elem_view_state.finished = true;
                            return NextBatch::End;
                        }
                    }
                }
                continue;
            }
            RecordKind::GeoPeer => continue,
            RecordKind::Rib {
                prefix,
                entry_count,
                flags,
                entries_offset,
            } => {
                // The same two record-level predicates the owned path applies, so a filtered run
                // keeps the skips it had before it moved onto the framed path.
                if crate::parser::filter::rib_record_excluded(&parser.filters, &prefix)
                    || crate::parser::attr_scan::rib_record_excluded(
                        &parser.filters,
                        body,
                        entries_offset,
                        flags,
                    )
                {
                    continue;
                }
                if parser.elem_view_state.peers.is_none() {
                    error!("{}", ElemError::MissingPeerTable);
                    continue;
                }
                let state = &mut parser.elem_view_state;
                let peers = state.peers.as_deref().expect("checked peers is_some");
                let entries_bytes = &state.body_buf[entries_offset..body_len];
                return NextBatch::Rib(RecordElems::rib(
                    header,
                    entries_bytes,
                    peers,
                    prefix.prefix,
                    entry_count,
                    flags,
                ));
            }
            // Hand the record back untouched: the caller owns the fallback and its error handling.
            RecordKind::Bgp4Mp {
                peer_ip,
                peer_asn,
                timestamp,
            } => {
                // The updates header answers the peer and time predicates, so a record they
                // exclude is dropped without ever being parsed.
                if crate::parser::filter::peer_excludes_record(&parser.filters, &peer_ip, &peer_asn)
                    || crate::parser::filter::timestamp_excludes_record(&parser.filters, timestamp)
                    || crate::parser::attr_scan::bgp4mp_record_excluded(
                        &parser.filters,
                        body,
                        header.entry_subtype,
                    )
                {
                    continue;
                }
                return NextBatch::Other {
                    header,
                    raw_header,
                    body_len,
                };
            }
            RecordKind::Other => {
                return NextBatch::Other {
                    header,
                    raw_header,
                    body_len,
                }
            }
        }
    }
}

pub(crate) fn next_record_elems_impl<R: Read>(
    parser: &mut BgpkitParser<R>,
) -> Option<RecordElems<'_>> {
    use crate::parser::mrt::frame::{bgp4mp_is_update, classify, RecordKind};

    if parser.text_dump_iter.is_some() || parser.elem_view_state.finished {
        return None;
    }
    if !parser.filters.is_empty() {
        parser.options.warn_view_filters_once();
        return None;
    }

    enum Framed {
        Rib {
            header: CommonHeader,
            prefix: IpNet,
            entry_count: u16,
            flags: u8,
            entries_offset: usize,
            body_len: usize,
        },
        Update {
            header: CommonHeader,
            peer_ip: IpAddr,
            peer_asn: Asn,
            timestamp: f64,
            body_len: usize,
        },
    }

    let framed = loop {
        let (common_header, raw_header, body_len) = match frame_next(parser) {
            Ok(framed) => framed,
            Err(failure) => {
                if matches!(failure.error, ParserError::EofExpected) {
                    parser.elem_view_state.finished = true;
                    return None;
                }
                if !handle_record_parse_error(parser, failure.error, failure.bytes) {
                    parser.elem_view_state.finished = true;
                    return None;
                }
                continue;
            }
        };

        let kind = classify(&common_header, &parser.elem_view_state.body_buf[..body_len]);
        match kind {
            RecordKind::PeerIndex => {
                match parse_peer_index_vec(&parser.elem_view_state.body_buf[..body_len]) {
                    Ok(peers) => parser.elem_view_state.peers = Some(peers),
                    Err(err) => {
                        let raw = parser.core_dump.then(|| {
                            assemble_error_bytes(
                                raw_header.as_slice(),
                                &parser.elem_view_state.body_buf[..body_len],
                            )
                        });
                        if !handle_record_parse_error(parser, err, raw) {
                            parser.elem_view_state.finished = true;
                            return None;
                        }
                    }
                }
                continue;
            }
            RecordKind::GeoPeer => {
                if let Err(err) =
                    validate_geo_peer_table(&parser.elem_view_state.body_buf[..body_len])
                {
                    let raw = parser.core_dump.then(|| {
                        assemble_error_bytes(
                            raw_header.as_slice(),
                            &parser.elem_view_state.body_buf[..body_len],
                        )
                    });
                    if !handle_record_parse_error(parser, err, raw) {
                        parser.elem_view_state.finished = true;
                        return None;
                    }
                }
                continue;
            }
            RecordKind::Rib {
                prefix,
                entry_count,
                flags,
                entries_offset,
            } => {
                if parser.elem_view_state.peers.is_none() {
                    error!("{}", ElemError::MissingPeerTable);
                    continue;
                }
                break Framed::Rib {
                    header: common_header,
                    prefix: prefix.prefix,
                    entry_count,
                    flags,
                    entries_offset,
                    body_len,
                };
            }
            RecordKind::Bgp4Mp {
                peer_ip,
                peer_asn,
                timestamp,
            } => {
                // Only the AS4 message subtypes are served; anything else says so once and moves on.
                let (supported, would_yield) = {
                    let state = &mut parser.elem_view_state;
                    let subtype = common_header.entry_subtype;
                    let body = &state.body_buf[..body_len];
                    let supported =
                        fill_update_entries(body, subtype, &mut state.update_entries).is_some();
                    (supported, bgp4mp_is_update(subtype, body))
                };
                if !supported {
                    // A record that carries no prefixes by design is not a gap in the view; only a
                    // record that would have produced elements and did not is worth a warning.
                    if would_yield {
                        parser
                            .options
                            .warn_view_scope_once("BGP4MP record with 2-byte AS numbers");
                    }
                    continue;
                }
                break Framed::Update {
                    header: common_header,
                    peer_ip,
                    peer_asn,
                    timestamp,
                    body_len,
                };
            }
            RecordKind::Other => {
                parser.options.warn_view_scope_once("other");
                continue;
            }
        }
    };

    match framed {
        Framed::Rib {
            header,
            prefix,
            entry_count,
            flags,
            entries_offset,
            body_len,
        } => {
            let state = &mut parser.elem_view_state;
            let peers = state
                .peers
                .as_deref()
                .expect("checked peers is_some before breaking");
            let entries_bytes = &state.body_buf[entries_offset..body_len];
            Some(RecordElems::rib(
                header,
                entries_bytes,
                peers,
                prefix,
                entry_count,
                flags,
            ))
        }
        Framed::Update {
            header,
            peer_ip,
            peer_asn,
            timestamp,
            body_len,
        } => update_record_elems(
            &mut parser.elem_view_state,
            body_len,
            header,
            peer_ip,
            peer_asn,
            timestamp,
        ),
    }
}

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

/// A borrowed batch of elements from one MRT record.
///
/// Holds a mutable borrow of the [`BgpkitParser`] (its reusable record buffer, and the active peer
/// table for a dump); drop it before advancing the parser to the next record.
pub struct RecordElems<'a> {
    header: CommonHeader,
    source: RecordSource<'a>,
}

/// Where a [`RecordElems`] batch takes its elements from.
enum RecordSource<'a> {
    /// `TABLE_DUMP_V2` `RIB_AFI`: one prefix, and entries that name a peer and carry attributes.
    Rib {
        entries_bytes: &'a [u8],
        peers: &'a [Peer],
        prefix: IpNet,
        entry_count: u16,
        flags: u8,
    },
    /// `BGP4MP` update: one attribute block, and the NLRI this record announced or withdrew.
    Update {
        entries: &'a [UpdateEntry],
        attrs: &'a [u8],
        peer_ip: IpAddr,
        peer_asn: Asn,
        timestamp: f64,
    },
}

impl<'a> RecordElems<'a> {
    #[inline]
    pub(crate) fn rib(
        header: CommonHeader,
        entries_bytes: &'a [u8],
        peers: &'a [Peer],
        prefix: IpNet,
        entry_count: u16,
        flags: u8,
    ) -> Self {
        RecordElems {
            header,
            source: RecordSource::Rib {
                entries_bytes,
                peers,
                prefix,
                entry_count,
                flags,
            },
        }
    }

    #[inline]
    pub(crate) fn update(
        header: CommonHeader,
        entries: &'a [UpdateEntry],
        attrs: &'a [u8],
        peer_ip: IpAddr,
        peer_asn: Asn,
        timestamp: f64,
    ) -> Self {
        RecordElems {
            header,
            source: RecordSource::Update {
                entries,
                attrs,
                peer_ip,
                peer_asn,
                timestamp,
            },
        }
    }

    /// Returns the MRT [`CommonHeader`] of this record.
    #[inline]
    pub fn header(&self) -> &CommonHeader {
        &self.header
    }

    /// Returns how many elements the record declares: the RIB entry count, or the number of NLRI
    /// this update announced and withdrew.
    #[inline]
    pub fn len(&self) -> usize {
        match &self.source {
            RecordSource::Rib { entry_count, .. } => *entry_count as usize,
            RecordSource::Update { entries, .. } => entries.len(),
        }
    }

    /// Returns `true` when the record declares no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator yielding borrowed [`ElemRef`] views over the record's elements.
    #[inline]
    pub fn iter(&mut self) -> ElemRefIter<'_> {
        let source = match &self.source {
            RecordSource::Rib {
                entries_bytes,
                peers,
                prefix,
                entry_count,
                flags,
            } => IterSource::Rib {
                data: entries_bytes,
                peers,
                prefix: *prefix,
                remaining: *entry_count,
                flags: *flags,
            },
            RecordSource::Update {
                entries,
                attrs,
                peer_ip,
                peer_asn,
                timestamp,
            } => IterSource::Update {
                entries,
                attrs,
                peer_ip: *peer_ip,
                peer_asn: *peer_asn,
                timestamp: *timestamp,
                next: 0,
            },
        };
        ElemRefIter {
            source,
            _borrow: PhantomData,
        }
    }
}

impl<'a, 'b> IntoIterator for &'b mut RecordElems<'a> {
    type Item = ElemRef<'b>;
    type IntoIter = ElemRefIter<'b>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// One element of a `BGP4MP` update, as the record declared it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct UpdateEntry {
    prefix: NetworkPrefix,
    elem_type: ElemType,
    flags: u8,
}

/// Iterator over borrowed [`ElemRef`]s within a single [`RecordElems`] record.
pub struct ElemRefIter<'a> {
    source: IterSource<'a>,
    _borrow: PhantomData<&'a mut ()>,
}

enum IterSource<'a> {
    Rib {
        data: &'a [u8],
        peers: &'a [Peer],
        prefix: IpNet,
        remaining: u16,
        flags: u8,
    },
    Update {
        entries: &'a [UpdateEntry],
        attrs: &'a [u8],
        peer_ip: IpAddr,
        peer_asn: Asn,
        timestamp: f64,
        next: usize,
    },
}

impl<'a> Iterator for ElemRefIter<'a> {
    type Item = ElemRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.source {
            IterSource::Rib {
                data,
                peers,
                prefix,
                remaining,
                flags,
            } => {
                if *remaining == 0 {
                    return None;
                }
                let with_path_id = (*flags & FLAG_ADD_PATH) != 0;
                let header_len = if with_path_id { 12 } else { 8 };
                if data.len() < header_len {
                    warn!("early break due to error Truncated message: truncated msg while parsing RIB AFI entries");
                    *remaining = 0;
                    return None;
                }
                let peer_index = u16::from_be_bytes([data[0], data[1]]);
                let originated_time = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                // With add-path, bytes 6..10 hold the path id; the element keeps the record's prefix.
                let attr_len =
                    u16::from_be_bytes([data[header_len - 2], data[header_len - 1]]) as usize;
                let end = header_len + attr_len;
                if data.len() < end {
                    warn!(
                        "early break due to error Truncated message: not enough bytes to read. remaining: {}, required: {} while parsing RIB AFI entries",
                        data.len() - header_len,
                        attr_len
                    );
                    *remaining = 0;
                    return None;
                }
                let attrs = &data[header_len..end];
                *data = &data[end..];
                *remaining -= 1;
                let Some(peer) = peers.get(peer_index as usize) else {
                    error!("peer ID {} not found in peer_index table", peer_index);
                    *remaining = 0;
                    return None;
                };
                // One unreadable attribute block fails the whole record on the owned path, so this
                // record yields nothing rather than a subset the other path would not produce.
                if !attribute_block_walks(attrs) {
                    *remaining = 0;
                    return None;
                }
                Some(ElemRef::new(*prefix, peer, originated_time, *flags, attrs))
            }
            IterSource::Update {
                entries,
                attrs,
                peer_ip,
                peer_asn,
                timestamp,
                next,
            } => {
                let entry = entries.get(*next)?;
                *next += 1;
                // A withdrawal carries no attributes, exactly as the owned path leaves them unset.
                let attr_bytes: &[u8] = match entry.elem_type {
                    ElemType::ANNOUNCE => attrs,
                    ElemType::WITHDRAW => &[],
                };
                Some(ElemRef::new_update(
                    entry, *peer_ip, *peer_asn, *timestamp, attr_bytes,
                ))
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = match &self.source {
            IterSource::Rib { remaining, .. } => *remaining as usize,
            IterSource::Update { entries, next, .. } => entries.len().saturating_sub(*next),
        };
        (0, Some(remaining))
    }
}

/// Borrowed view over a single BGP element inside a [`RecordElems`] batch.
///
/// Attributes are decoded lazily from `attr_bytes` when their accessors are called, without heap
/// allocation.
#[derive(Clone, Debug)]
pub struct ElemRef<'a> {
    attr_bytes: &'a [u8],
    peer_ip: IpAddr,
    peer_asn: Asn,
    peer_bgp_id: Option<BgpIdentifier>,
    as_path_slot: Cell<u64>,
    timestamp: f64,
    prefix: IpNet,
    /// The ADD-PATH identifier the announcement carried, if any. A dump's entry has none.
    path_id: Option<u32>,
    flags: u8,
    elem_type: ElemType,
    warned_truncation: Cell<bool>,
}

// Structural invariant: none of the borrowed view types own heap allocations or require Drop.
const _: () = assert!(!std::mem::needs_drop::<ElemRef<'static>>());
const _: () = assert!(!std::mem::needs_drop::<AsPathView<'static>>());
const _: () = assert!(!std::mem::needs_drop::<AsnsView<'static>>());
const _: () = assert!(!std::mem::needs_drop::<CommunitiesView<'static>>());
// A borrowed element carries its peer inline so one type serves both dumps and updates.
const _: () = assert!(std::mem::size_of::<ElemRef<'static>>() <= 104);

impl<'a> ElemRef<'a> {
    #[inline]
    fn new(
        prefix: IpNet,
        peer: &'a Peer,
        originated_time: u32,
        flags: u8,
        attr_bytes: &'a [u8],
    ) -> Self {
        Self {
            attr_bytes,
            peer_ip: peer.peer_ip,
            peer_asn: peer.peer_asn,
            peer_bgp_id: Some(peer.peer_bgp_id),
            as_path_slot: Cell::new(SLOT_UNSCANNED),
            timestamp: originated_time as f64,
            prefix,
            path_id: None,
            flags,
            elem_type: ElemType::ANNOUNCE,
            warned_truncation: Cell::new(false),
        }
    }

    /// An element of a `BGP4MP` update: the peer and the time come from the record header.
    #[inline]
    fn new_update(
        entry: &UpdateEntry,
        peer_ip: IpAddr,
        peer_asn: Asn,
        timestamp: f64,
        attr_bytes: &'a [u8],
    ) -> Self {
        Self {
            attr_bytes,
            peer_ip,
            peer_asn,
            peer_bgp_id: None,
            as_path_slot: Cell::new(SLOT_UNSCANNED),
            timestamp,
            prefix: entry.prefix.prefix,
            path_id: entry.prefix.path_id,
            flags: entry.flags | FLAG_UPDATE,
            elem_type: entry.elem_type,
            warned_truncation: Cell::new(false),
        }
    }

    #[inline]
    fn afi(&self) -> Afi {
        if (self.flags & FLAG_AFI_IPV6) != 0 {
            Afi::Ipv6
        } else {
            Afi::Ipv4
        }
    }

    #[inline]
    fn safi(&self) -> Safi {
        if (self.flags & FLAG_SAFI_MULTICAST) != 0 {
            Safi::Multicast
        } else {
            Safi::Unicast
        }
    }

    /// The family `NEXT_HOP` is encoded with: the record's for a dump, IPv4 for an update.
    #[inline]
    fn next_hop_afi(&self) -> Afi {
        if (self.flags & FLAG_UPDATE) != 0 {
            Afi::Ipv4
        } else {
            self.afi()
        }
    }

    #[inline]
    fn is_add_path(&self) -> bool {
        (self.flags & FLAG_ADD_PATH) != 0
    }

    #[cold]
    #[inline(never)]
    fn warn_truncated_attr_once(&self, raw_code: u8, attr_length: usize, bytes_left: usize) {
        if !self.warned_truncation.replace(true) {
            let attr_type = AttrType::from(raw_code);
            warn!(
                "{:?} attribute encodes a length ({}) that is longer than the remaining attribute data ({}). Skipping remaining attribute data for BGP message",
                attr_type, attr_length, bytes_left
            );
        }
    }

    #[cold]
    #[inline(never)]
    fn scan_merged_as_paths(&self) -> (&'a [u8], &'a [u8]) {
        let bytes = self.attr_bytes;
        let len = bytes.len();
        let mut pos = 0usize;
        let mut p2: &'a [u8] = &[];
        let mut p4: &'a [u8] = &[];

        while pos + 3 <= len {
            let flags = bytes[pos];
            let code = bytes[pos + 1];
            let (hdr_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
                (3usize, bytes[pos + 2] as usize)
            } else {
                if pos + 4 > len {
                    break;
                }
                (
                    4usize,
                    u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize,
                )
            };
            let val_start = pos + hdr_len;
            let val_end = val_start + attr_len;
            if val_end > len {
                self.warn_truncated_attr_once(code, attr_len, len - val_start);
                break;
            }
            if code == u8::from(AttrType::AS_PATH) {
                let slice = &bytes[val_start..val_end];
                if validate_as_path_wire(slice) {
                    p2 = slice;
                }
            } else if code == u8::from(AttrType::AS4_PATH) {
                let slice = &bytes[val_start..val_end];
                if validate_as_path_wire(slice) {
                    p4 = slice;
                }
            }
            pos = val_end;
        }
        (p2, p4)
    }

    #[inline]
    fn resolve_as_path_source(&self) -> AsPathSource<'a> {
        let cached = self.as_path_slot.get();
        if cached != SLOT_UNSCANNED {
            return match cached {
                SLOT_ABSENT => AsPathSource::Absent,
                SLOT_MERGED => {
                    let (as_path, as4_path) = self.scan_merged_as_paths();
                    AsPathSource::Merged { as_path, as4_path }
                }
                packed => {
                    let start = (packed & 0xFFFF) as usize;
                    let len = ((packed >> 16) & 0xFFFF) as usize;
                    AsPathSource::Single(&self.attr_bytes[start..start + len])
                }
            };
        }

        let bytes = self.attr_bytes;
        let len = bytes.len();
        let mut pos = 0usize;
        let mut as_path_span: Option<(u16, u16)> = None;
        let mut as4_path_span: Option<(u16, u16)> = None;

        while pos + 3 <= len {
            let flags = bytes[pos];
            let code = bytes[pos + 1];
            let (hdr_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
                (3usize, bytes[pos + 2] as usize)
            } else {
                if pos + 4 > len {
                    break;
                }
                (
                    4usize,
                    u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize,
                )
            };
            let val_start = pos + hdr_len;
            let val_end = val_start + attr_len;
            if val_end > len {
                self.warn_truncated_attr_once(code, attr_len, len - val_start);
                break;
            }
            if code == u8::from(AttrType::AS_PATH) {
                if validate_as_path_wire(&bytes[val_start..val_end]) {
                    as_path_span = Some((val_start as u16, attr_len as u16));
                }
            } else if code == u8::from(AttrType::AS4_PATH)
                && validate_as_path_wire(&bytes[val_start..val_end])
            {
                as4_path_span = Some((val_start as u16, attr_len as u16));
            }
            pos = val_end;
        }

        match (as_path_span, as4_path_span) {
            (None, None) => {
                self.as_path_slot.set(SLOT_ABSENT);
                AsPathSource::Absent
            }
            (Some((s, l)), None) | (None, Some((s, l))) => {
                let packed = (s as u64) | ((l as u64) << 16);
                self.as_path_slot.set(packed);
                AsPathSource::Single(&bytes[s as usize..s as usize + l as usize])
            }
            (Some((s1, l1)), Some((s2, l2))) => {
                let p1 = &bytes[s1 as usize..s1 as usize + l1 as usize];
                let p2 = &bytes[s2 as usize..s2 as usize + l2 as usize];
                // Per RFC 6793 §4.2.3, when AS_PATH is shorter than AS4_PATH, AS4_PATH is ignored.
                if wire_route_len(p1) < wire_route_len(p2) {
                    let packed = (s1 as u64) | ((l1 as u64) << 16);
                    self.as_path_slot.set(packed);
                    AsPathSource::Single(p1)
                } else {
                    self.as_path_slot.set(SLOT_MERGED);
                    AsPathSource::Merged {
                        as_path: p1,
                        as4_path: p2,
                    }
                }
            }
        }
    }

    /// Returns the prefix this element announces, with the ADD-PATH identifier it carried.
    #[inline]
    pub fn prefix(&self) -> NetworkPrefix {
        NetworkPrefix::new(self.prefix, self.path_id)
    }

    /// Returns the IP address of the peer that exported this RIB entry.
    #[inline]
    pub fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }

    /// Returns the AS number of the peer that exported this RIB entry.
    #[inline]
    pub fn peer_asn(&self) -> Asn {
        self.peer_asn
    }

    /// Returns a zero-allocation borrowed view over the entry's effective `AS_PATH`.
    #[inline]
    pub fn as_path(&self) -> AsPathView<'a> {
        AsPathView {
            source: self.resolve_as_path_source(),
        }
    }

    /// Returns a zero-allocation view over the originating ASNs of the effective `AS_PATH`.
    #[inline]
    pub fn origin_asns(&self) -> AsnsView<'a> {
        match self.resolve_as_path_source() {
            AsPathSource::Absent => AsnsView {
                repr: OriginsRepr::Absent,
            },
            AsPathSource::Single(wire) => single_wire_origins(wire),
            AsPathSource::Merged { as_path, as4_path } => merged_wire_origins(as_path, as4_path),
        }
    }

    /// Returns a zero-allocation view over the entry's standard, extended, and large communities.
    #[inline]
    pub fn communities(&self) -> CommunitiesView<'a> {
        CommunitiesView {
            attr_bytes: self.usable_attr_prefix(),
        }
    }

    /// Returns the effective next-hop address (`NEXT_HOP`, or `MP_REACH_NLRI`'s global next hop).
    pub fn next_hop(&self) -> Option<IpAddr> {
        let bytes = self.attr_bytes;
        let len = bytes.len();
        let afi = self.afi();
        let safi = self.safi();
        let is_add_path = self.is_add_path();
        let mut pos = 0usize;
        let mut next_hop: Option<IpAddr> = None;
        let mut mp_next_hop: Option<IpAddr> = None;

        while pos + 3 <= len {
            let flags = bytes[pos];
            let code = bytes[pos + 1];
            let (hdr_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
                (3usize, bytes[pos + 2] as usize)
            } else {
                if pos + 4 > len {
                    break;
                }
                (
                    4usize,
                    u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize,
                )
            };
            let val_start = pos + hdr_len;
            let val_end = val_start + attr_len;
            if val_end > len {
                self.warn_truncated_attr_once(code, attr_len, len - val_start);
                break;
            }
            if code == u8::from(AttrType::NEXT_HOP) {
                let mut val = &bytes[val_start..val_end];
                if let Ok(addr) = val.read_address(&self.next_hop_afi()) {
                    next_hop = Some(addr);
                }
            } else if code == u8::from(AttrType::MP_REACHABLE_NLRI) {
                if let Ok(addr_opt) =
                    parse_mp_reach_next_hop(&bytes[val_start..val_end], afi, safi, is_add_path)
                {
                    mp_next_hop = addr_opt;
                }
            }
            pos = val_end;
        }

        next_hop.or(mp_next_hop)
    }

    /// Returns the Multi-Exit Discriminator (`MULTI_EXIT_DISCRIMINATOR`), matching
    /// [`BgpElem::med`](crate::BgpElem::med) (`Some(0)` on RIB announcements without MED).
    pub fn med(&self) -> Option<u32> {
        if self.elem_type == ElemType::WITHDRAW {
            return None;
        }
        Some(
            self.scan_u32_attr(u8::from(AttrType::MULTI_EXIT_DISCRIMINATOR))
                .unwrap_or(0),
        )
    }

    /// Returns the Local Preference (`LOCAL_PREFERENCE`), matching
    /// [`BgpElem::local_pref`](crate::BgpElem::local_pref) (`Some(0)` on RIB announcements without
    /// `LOCAL_PREFERENCE`).
    pub fn local_pref(&self) -> Option<u32> {
        if self.elem_type == ElemType::WITHDRAW {
            return None;
        }
        Some(
            self.scan_u32_attr(u8::from(AttrType::LOCAL_PREFERENCE))
                .unwrap_or(0),
        )
    }

    /// Materialise this entry as an owned [`BgpElem`].
    ///
    /// Walks the attribute TLVs once for the scalar attributes, then reuses the borrowed views for
    /// the AS path, the communities, the next hop and the two u32 attributes. Values match an elem
    /// built from a parsed `MrtRecord`, including the `Some(0)` defaults for MED and LOCAL_PREF,
    /// with one documented difference: a known attribute that fails to parse is dropped here,
    /// while the owned path keeps it in `BgpElem::unknown`.
    /// This entry's attribute block, for the predicates that can decide an entry from bytes.
    pub(crate) fn attrs_bytes(&self) -> &'a [u8] {
        self.attr_bytes
    }

    /// Materialise this entry as an owned [`BgpElem`], for the fields the borrowed accessors do
    /// not expose.
    pub fn to_bgp_elem(&self) -> BgpElem {
        let bytes = self.usable_attr_prefix();
        let afi = self.afi();
        let safi = self.safi();
        let is_add_path = self.is_add_path();

        let mut origin: Option<Origin> = None;
        let mut atomic = false;
        let mut aggregator: Option<(Asn, BgpIdentifier)> = None;
        let mut only_to_customer: Option<Asn> = None;
        let mut med: Option<u32> = None;
        let mut local_pref: Option<u32> = None;
        let mut next_hop: Option<IpAddr> = None;
        let mut mp_next_hop: Option<IpAddr> = None;
        let mut as_path_wire: Option<&[u8]> = None;
        let mut as4_path_wire: Option<&[u8]> = None;
        // Community attributes in wire order, decoded after the walk so the order of the produced
        // values matches the attribute order, as the owned path extends them.
        let mut community_attrs: Vec<(u8, &[u8])> = Vec::with_capacity(4);
        let mut unknown: Vec<AttrRaw> = Vec::new();
        let mut deprecated: Vec<AttrRaw> = Vec::new();

        let len = bytes.len();
        let mut pos = 0usize;
        while pos + 3 <= len {
            let flags = bytes[pos];
            let code = bytes[pos + 1];
            let (header_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
                (3usize, bytes[pos + 2] as usize)
            } else {
                if pos + 4 > len {
                    break;
                }
                (
                    4usize,
                    u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize,
                )
            };
            let val_start = pos + header_len;
            let val_end = val_start + attr_len;
            if val_end > len {
                self.warn_truncated_attr_once(code, attr_len, len - val_start);
                break;
            }
            let val = &bytes[val_start..val_end];
            pos = val_end;

            if get_deprecated_attr_type(code).is_some() {
                deprecated.push(AttrRaw {
                    code,
                    bytes: Bytes::copy_from_slice(val),
                });
                continue;
            }

            // A known attribute this cannot decode keeps its bytes in `unknown`, which is what the
            // owned path does with an attribute it falls back to `AttributeValue::Raw`.
            let mut undecoded = false;
            match AttrType::from(code) {
                // A value the owned path cannot parse becomes raw bytes and leaves the earlier
                // attribute of the same type in place, so keep what is already known here too.
                AttrType::ORIGIN => {
                    match val.first().and_then(|value| Origin::try_from(*value).ok()) {
                        Some(decoded) => origin = Some(decoded),
                        None => undecoded = true,
                    }
                }
                AttrType::AS_PATH => {
                    if validate_as_path_wire(val) {
                        as_path_wire = Some(val);
                    } else {
                        undecoded = true;
                    }
                }
                AttrType::AS4_PATH => {
                    if validate_as_path_wire(val) {
                        as4_path_wire = Some(val);
                    } else {
                        undecoded = true;
                    }
                }
                AttrType::NEXT_HOP => {
                    let mut value = val;
                    match value.read_address(&self.next_hop_afi()) {
                        Ok(address) => next_hop = Some(address),
                        Err(_) => undecoded = true,
                    }
                }
                AttrType::MULTI_EXIT_DISCRIMINATOR => {
                    let mut value = val;
                    match value.read_u32() {
                        Ok(number) => med = Some(number),
                        Err(_) => undecoded = true,
                    }
                }
                AttrType::LOCAL_PREFERENCE => {
                    let mut value = val;
                    match value.read_u32() {
                        Ok(number) => local_pref = Some(number),
                        Err(_) => undecoded = true,
                    }
                }
                AttrType::ATOMIC_AGGREGATE => atomic = true,
                AttrType::AGGREGATOR | AttrType::AS4_AGGREGATOR => {
                    match decode_aggregator_slice(val) {
                        Some(decoded) => aggregator = Some(decoded),
                        None => undecoded = true,
                    }
                }
                AttrType::COMMUNITIES
                | AttrType::EXTENDED_COMMUNITIES
                | AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES
                | AttrType::LARGE_COMMUNITIES => community_attrs.push((code, val)),
                AttrType::ONLY_TO_CUSTOMER => {
                    if val.len() >= 4 {
                        only_to_customer = Some(Asn::new_32bit(u32::from_be_bytes([
                            val[0], val[1], val[2], val[3],
                        ])));
                    } else {
                        undecoded = true;
                    }
                }
                AttrType::MP_REACHABLE_NLRI => {
                    if let Ok(address) = parse_mp_reach_next_hop(val, afi, safi, is_add_path) {
                        mp_next_hop = address;
                    }
                }
                // Types the element path keeps as raw bytes, mirroring `get_relevant_attributes`.
                AttrType::Unknown(_)
                | AttrType::TRAFFIC_ENGINEERING
                | AttrType::RESERVED
                | AttrType::PMSI_TUNNEL
                | AttrType::PE_DISTINGUISHER_LABELS
                | AttrType::BGPSEC_PATH
                | AttrType::ATTR_SET => unknown.push(AttrRaw {
                    code,
                    bytes: Bytes::copy_from_slice(val),
                }),
                _ => {}
            }
            if undecoded {
                unknown.push(AttrRaw {
                    code,
                    bytes: Bytes::copy_from_slice(val),
                });
            }
        }

        // RFC 6793 §4.2.3: when AS_PATH is shorter than AS4_PATH, AS4_PATH is ignored.
        let source = match (as_path_wire, as4_path_wire) {
            (None, None) => AsPathSource::Absent,
            (Some(path), None) => AsPathSource::Single(path),
            (None, Some(path)) => AsPathSource::Single(path),
            (Some(path), Some(as4_path)) => {
                if wire_route_len(path) < wire_route_len(as4_path) {
                    AsPathSource::Single(path)
                } else {
                    AsPathSource::Merged {
                        as_path: path,
                        as4_path,
                    }
                }
            }
        };
        let as_path = AsPathView { source }.to_as_path();
        let origin_asns = match source {
            AsPathSource::Absent => None,
            AsPathSource::Single(wire) => Some(single_wire_origins(wire).to_vec()),
            AsPathSource::Merged { as_path, as4_path } => {
                Some(merged_wire_origins(as_path, as4_path).to_vec())
            }
        };

        let mut communities: Vec<MetaCommunity> = Vec::new();
        for (code, val) in community_attrs {
            match AttrType::from(code) {
                AttrType::COMMUNITIES if val.len().is_multiple_of(4) => {
                    for word in bytes_as_be_u32_words(val) {
                        communities.push(MetaCommunity::Plain(decode_plain_community(word.get())));
                    }
                }
                // An attribute whose length is not a whole number of communities fails to parse on
                // the owned path, so nothing from it is rendered and its bytes are kept raw.
                AttrType::EXTENDED_COMMUNITIES if val.len().is_multiple_of(8) => {
                    for chunk in val.as_chunks::<8>().0 {
                        communities
                            .push(MetaCommunity::Extended(decode_extended_community(*chunk)));
                    }
                }
                AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES
                    if val.len().is_multiple_of(20) =>
                {
                    for chunk in val.as_chunks::<20>().0 {
                        communities.push(MetaCommunity::Ipv6Extended(
                            decode_ipv6_extended_community(chunk),
                        ));
                    }
                }
                AttrType::LARGE_COMMUNITIES if val.len().is_multiple_of(12) => {
                    for chunk in val.as_chunks::<12>().0 {
                        let words = bytes_as_be_u32_words(chunk);
                        communities.push(MetaCommunity::Large(LargeCommunity::new(
                            words[0].get(),
                            [words[1].get(), words[2].get()],
                        )));
                    }
                }
                // Anything left is a community attribute the owned path keeps raw.
                _ => unknown.push(AttrRaw {
                    code,
                    bytes: Bytes::copy_from_slice(val),
                }),
            }
        }

        let is_withdrawal = self.elem_type() == ElemType::WITHDRAW;
        BgpElem {
            timestamp: self.timestamp(),
            elem_type: self.elem_type(),
            peer_ip: self.peer_ip,
            peer_asn: self.peer_asn,
            peer_bgp_id: self.peer_bgp_id,
            prefix: NetworkPrefix {
                prefix: self.prefix,
                path_id: self.path_id,
            },
            next_hop: next_hop.or(mp_next_hop),
            as_path,
            origin,
            origin_asns,
            // A withdrawal carries no attributes, so the owned path leaves these unset; every other
            // case keeps the `Some(0)` default the owned path applies too.
            local_pref: (!is_withdrawal).then(|| local_pref.unwrap_or(0)),
            med: (!is_withdrawal).then(|| med.unwrap_or(0)),
            communities: (!communities.is_empty()).then_some(communities),
            atomic,
            aggr_asn: aggregator.map(|value| value.0),
            aggr_ip: aggregator.map(|value| value.1),
            only_to_customer,
            unknown: (!unknown.is_empty()).then_some(unknown),
            deprecated: (!deprecated.is_empty()).then_some(deprecated),
        }
    }

    /// Returns this element's Unix timestamp as seconds (`f64`): the entry's originated time for
    /// a dump, the record's time for an update.
    #[inline]
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }

    /// Returns whether this element is an announcement or a withdrawal.
    #[inline]
    pub fn elem_type(&self) -> ElemType {
        self.elem_type
    }

    fn scan_u32_attr(&self, target_code: u8) -> Option<u32> {
        let bytes = self.attr_bytes;
        let len = bytes.len();
        let mut pos = 0usize;
        let mut found = None;

        while pos + 3 <= len {
            let flags = bytes[pos];
            let code = bytes[pos + 1];
            let (hdr_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
                (3usize, bytes[pos + 2] as usize)
            } else {
                if pos + 4 > len {
                    break;
                }
                (
                    4usize,
                    u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize,
                )
            };
            let val_start = pos + hdr_len;
            let val_end = val_start + attr_len;
            if val_end > len {
                self.warn_truncated_attr_once(code, attr_len, len - val_start);
                break;
            }
            if code == target_code && attr_len >= 4 {
                found = Some(u32::from_be_bytes([
                    bytes[val_start],
                    bytes[val_start + 1],
                    bytes[val_start + 2],
                    bytes[val_start + 3],
                ]));
            }
            pos = val_end;
        }
        found
    }

    #[inline]
    fn usable_attr_prefix(&self) -> &'a [u8] {
        let bytes = self.attr_bytes;
        let len = bytes.len();
        let mut pos = 0usize;
        while pos + 3 <= len {
            let flags = bytes[pos];
            let code = bytes[pos + 1];
            let (hdr_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
                (3usize, bytes[pos + 2] as usize)
            } else {
                if pos + 4 > len {
                    break;
                }
                (
                    4usize,
                    u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize,
                )
            };
            let val_start = pos + hdr_len;
            let val_end = val_start + attr_len;
            if val_end > len {
                self.warn_truncated_attr_once(code, attr_len, len - val_start);
                break;
            }
            pos = val_end;
        }
        &bytes[..pos]
    }
}

/// Validate a 4-byte-ASN `AS_PATH` / `AS4_PATH` attribute payload without allocating.
#[inline]
fn validate_as_path_wire(mut wire: &[u8]) -> bool {
    if wire.len() >= 2 {
        let seg_type = wire[0];
        let count = wire[1] as usize;
        let seg_bytes = 2 + count * 4;
        if seg_bytes == wire.len() {
            return (1..=4).contains(&seg_type);
        }
        if seg_bytes > wire.len() || !(1..=4).contains(&seg_type) {
            return false;
        }
        wire = &wire[seg_bytes..];
    }
    while !wire.is_empty() {
        if wire.len() < 2 {
            return false;
        }
        let seg_type = wire[0];
        let count = wire[1] as usize;
        let seg_bytes = 2 + count * 4;
        if seg_bytes > wire.len() || !(1..=4).contains(&seg_type) {
            return false;
        }
        wire = &wire[seg_bytes..];
    }
    true
}

fn wire_route_len(mut wire: &[u8]) -> usize {
    let mut total = 0usize;
    while wire.len() >= 2 {
        let seg_type = wire[0];
        let count = wire[1] as usize;
        match seg_type {
            AS_PATH_AS_SEQUENCE => total += count,
            AS_PATH_AS_SET => total += 1,
            _ => {}
        }
        wire = &wire[2 + count * 4..];
    }
    total
}

/// Decode `MP_REACH_NLRI` in a `TABLE_DUMP_V2` `RIB_AFI` entry to its resolved global next-hop IP,
/// The global next hop of an `MP_REACH_NLRI` value.
///
/// A `RIB_AFI` entry may omit the attribute's own address family and SAFI (RFC 6396 §4.3.4), which
/// is what a leading zero decides. The next-hop field itself is decoded by the owned parser, so the
/// widths it accepts and rejects are the same on both paths.
fn parse_mp_reach_next_hop(
    mut input: &[u8],
    _rib_afi: Afi,
    _rib_safi: Safi,
    _is_add_path: bool,
) -> Result<Option<IpAddr>, ()> {
    if input.first().copied() == Some(0) {
        input.read_afi().map_err(|_| ())?;
        input.read_safi().map_err(|_| ())?;
    }
    let nh_len = input.read_u8().map_err(|_| ())? as usize;
    let nh_bytes = input.get(..nh_len).ok_or(())?;
    let next_hop = crate::parser::bgp::attributes::attr_03_next_hop::parse_mp_next_hop(
        bytes::Bytes::copy_from_slice(nh_bytes),
    )
    .map_err(|_| ())?;
    Ok(next_hop.map(|next_hop| next_hop.global_addr()))
}

///////////////////////////////////////////////////////////////////////////////
// AS_PATH & Origin ASN Views
///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, Debug)]
enum AsPathSource<'a> {
    Absent,
    Single(&'a [u8]),
    Merged {
        as_path: &'a [u8],
        as4_path: &'a [u8],
    },
}

/// Segment kind in a wire `AS_PATH` attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AsPathSegmentType {
    AsSet,
    AsSequence,
    ConfedSequence,
    ConfedSet,
}

impl AsPathSegmentType {
    #[inline]
    fn from_wire(code: u8) -> Self {
        match code {
            AS_PATH_AS_SET => Self::AsSet,
            AS_PATH_AS_SEQUENCE => Self::AsSequence,
            AS_PATH_CONFED_SEQUENCE => Self::ConfedSequence,
            AS_PATH_CONFED_SET => Self::ConfedSet,
            _ => unreachable!("wire AS_PATH segments are pre-validated to codes 1..=4"),
        }
    }
}

/// Borrowed view over one segment in a wire `AS_PATH`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsPathSegmentRef<'a> {
    seg_type: AsPathSegmentType,
    asn_bytes: &'a [u8],
}

impl<'a> AsPathSegmentRef<'a> {
    /// Returns the segment type (`AS_SEQUENCE`, `AS_SET`, `AS_CONFED_SEQUENCE`, `AS_CONFED_SET`).
    #[inline]
    pub fn segment_type(&self) -> AsPathSegmentType {
        self.seg_type
    }

    /// Returns the number of ASNs in this segment.
    #[inline]
    pub fn len(&self) -> usize {
        self.asn_bytes.len() / 4
    }

    /// Returns `true` if this segment carries zero ASNs.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.asn_bytes.is_empty()
    }

    /// Iterates over the [`Asn`]s in this segment in wire order without allocating.
    #[inline]
    pub fn asns(&self) -> SegmentAsns<'a> {
        SegmentAsns {
            words: bytes_as_be_u32_words(self.asn_bytes),
        }
    }
}

impl<'a> IntoIterator for AsPathSegmentRef<'a> {
    type Item = Asn;
    type IntoIter = SegmentAsns<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.asns()
    }
}

/// Iterator over the 4-octet [`Asn`]s of one borrowed `AS_PATH` segment.
#[derive(Clone, Debug)]
pub struct SegmentAsns<'a> {
    words: &'a [BeU32],
}

impl<'a> Iterator for SegmentAsns<'a> {
    type Item = Asn;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let (first, rest) = self.words.split_first()?;
        self.words = rest;
        Some(Asn::new_32bit(first.get()))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.words.len();
        (n, Some(n))
    }
}

impl ExactSizeIterator for SegmentAsns<'_> {}

/// Zero-allocation borrowed view over an element's effective `AS_PATH`.
///
/// Iterating an `AsPathView` yields every [`Asn`] across its wire segments in order, expanding
/// `AS_SET` (and confederation) segments inline on the fly without allocating. Call
/// [`segments`](Self::segments) to inspect segment boundaries or [`to_vec`](Self::to_vec) to
/// materialise an owned `Vec<Asn>`.
#[derive(Clone, Copy, Debug)]
pub struct AsPathView<'a> {
    source: AsPathSource<'a>,
}

impl<'a> AsPathView<'a> {
    /// Returns `true` if a valid `AS_PATH` (or `AS4_PATH`) attribute is present on the element
    /// (including an empty 0-segment iBGP `AS_PATH`).
    #[inline]
    pub fn is_present(&self) -> bool {
        !matches!(self.source, AsPathSource::Absent)
    }

    /// Returns `true` if the path yields no AS numbers.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    /// Returns an iterator over the wire [`AsPathSegmentRef`]s without allocating.
    #[inline]
    pub fn segments(&self) -> AsPathSegments<'a> {
        match self.source {
            AsPathSource::Absent => AsPathSegments {
                lead: &[],
                lead_remaining: 0,
                tail: &[],
            },
            AsPathSource::Single(wire) => AsPathSegments {
                lead: &[],
                lead_remaining: 0,
                tail: wire,
            },
            AsPathSource::Merged { as_path, as4_path } => {
                let lead_remaining = wire_route_len(as_path) - wire_route_len(as4_path);
                AsPathSegments {
                    lead: if lead_remaining > 0 { as_path } else { &[] },
                    lead_remaining,
                    tail: as4_path,
                }
            }
        }
    }

    /// Returns a zero-allocation iterator over all [`Asn`]s in the path, expanding `AS_SET`
    /// segments inline on the fly.
    #[inline]
    pub fn iter(&self) -> AsPathIter<'a> {
        match self.source {
            AsPathSource::Absent => AsPathIter {
                cur_words: &[],
                segs: AsPathSegments {
                    lead: &[],
                    lead_remaining: 0,
                    tail: &[],
                },
            },
            AsPathSource::Single(wire) => {
                if wire.len() >= 2 {
                    let count = wire[1] as usize;
                    let end = 2 + count * 4;
                    AsPathIter {
                        cur_words: bytes_as_be_u32_words(&wire[2..end]),
                        segs: AsPathSegments {
                            lead: &[],
                            lead_remaining: 0,
                            tail: &wire[end..],
                        },
                    }
                } else {
                    AsPathIter {
                        cur_words: &[],
                        segs: AsPathSegments {
                            lead: &[],
                            lead_remaining: 0,
                            tail: &[],
                        },
                    }
                }
            }
            AsPathSource::Merged { .. } => AsPathIter {
                cur_words: &[],
                segs: self.segments(),
            },
        }
    }

    /// Materialises all [`Asn`]s in this path (with `AS_SET` expanded in wire order) into a `Vec`.
    pub fn to_vec(&self) -> Vec<Asn> {
        self.iter().collect()
    }

    /// Converts this view into an owned `Option<AsPath>` matching [`BgpElem::as_path`](crate::BgpElem::as_path).
    pub fn to_as_path(&self) -> Option<AsPath> {
        match self.source {
            AsPathSource::Absent => None,
            AsPathSource::Single(wire) => Some(wire_to_owned_as_path(wire)),
            AsPathSource::Merged { as_path, as4_path } => {
                let p1 = wire_to_owned_as_path(as_path);
                let p2 = wire_to_owned_as_path(as4_path);
                Some(AsPath::merge_aspath_as4path(&p1, &p2))
            }
        }
    }
}

fn wire_to_owned_as_path(wire: &[u8]) -> AsPath {
    let mut out = AsPath::new();
    let mut rest = wire;
    while rest.len() >= 2 {
        let code = rest[0];
        let count = rest[1] as usize;
        let end = 2 + count * 4;
        let asns = bytes_as_be_u32_words(&rest[2..end])
            .iter()
            .map(|w| Asn::new_32bit(w.get()))
            .collect();
        let seg = match code {
            AS_PATH_AS_SET => AsPathSegment::AsSet(asns),
            AS_PATH_AS_SEQUENCE => AsPathSegment::AsSequence(asns),
            AS_PATH_CONFED_SEQUENCE => AsPathSegment::ConfedSequence(asns),
            AS_PATH_CONFED_SET => AsPathSegment::ConfedSet(asns),
            _ => unreachable!("wire AS_PATH segments are pre-validated"),
        };
        out.append_segment(seg);
        rest = &rest[end..];
    }
    out
}

impl<'a> IntoIterator for AsPathView<'a> {
    type Item = Asn;
    type IntoIter = AsPathIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &AsPathView<'a> {
    type Item = Asn;
    type IntoIter = AsPathIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over borrowed [`AsPathSegmentRef`]s of an [`AsPathView`].
#[derive(Clone, Debug)]
pub struct AsPathSegments<'a> {
    lead: &'a [u8],
    lead_remaining: usize,
    tail: &'a [u8],
}

impl<'a> Iterator for AsPathSegments<'a> {
    type Item = AsPathSegmentRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.lead_remaining > 0 && self.lead.len() >= 2 {
            let code = self.lead[0];
            let count = self.lead[1] as usize;
            let end = 2 + count * 4;
            let full_asn_bytes = &self.lead[2..end];
            self.lead = &self.lead[end..];

            let seg_type = AsPathSegmentType::from_wire(code);
            let route_asns = match seg_type {
                AsPathSegmentType::AsSequence => count,
                AsPathSegmentType::AsSet => 1,
                AsPathSegmentType::ConfedSequence | AsPathSegmentType::ConfedSet => 0,
            };

            if route_asns <= self.lead_remaining {
                self.lead_remaining -= route_asns;
                if self.lead_remaining == 0 {
                    self.lead = &[];
                }
                return Some(AsPathSegmentRef {
                    seg_type,
                    asn_bytes: full_asn_bytes,
                });
            } else {
                // Only AS_SEQUENCE can straddle the leading count boundary (RFC 6793 §4.2.3).
                let take_bytes = self.lead_remaining * 4;
                self.lead_remaining = 0;
                self.lead = &[];
                return Some(AsPathSegmentRef {
                    seg_type,
                    asn_bytes: &full_asn_bytes[..take_bytes],
                });
            }
        }

        if self.tail.len() >= 2 {
            let code = self.tail[0];
            let count = self.tail[1] as usize;
            let end = 2 + count * 4;
            let asn_bytes = &self.tail[2..end];
            self.tail = &self.tail[end..];
            return Some(AsPathSegmentRef {
                seg_type: AsPathSegmentType::from_wire(code),
                asn_bytes,
            });
        }

        None
    }
}

/// Iterator over [`Asn`]s in an [`AsPathView`], expanding `AS_SET` segments on the fly.
#[derive(Clone, Debug)]
pub struct AsPathIter<'a> {
    cur_words: &'a [BeU32],
    segs: AsPathSegments<'a>,
}

impl<'a> Iterator for AsPathIter<'a> {
    type Item = Asn;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((first, rest)) = self.cur_words.split_first() {
                self.cur_words = rest;
                return Some(Asn::new_32bit(first.get()));
            }
            let seg = self.segs.next()?;
            self.cur_words = bytes_as_be_u32_words(seg.asn_bytes);
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum OriginsRepr<'a> {
    Absent,
    Empty,
    One(Asn),
    Set(&'a [BeU32]),
}

#[inline]
fn single_wire_origins(wire: &[u8]) -> AsnsView<'_> {
    // Fast path (99.99% of RIB entries): single non-empty AS_SEQUENCE segment.
    if wire.len() >= 6 && wire[0] == AS_PATH_AS_SEQUENCE && 2 + (wire[1] as usize) * 4 == wire.len()
    {
        let last = wire.len() - 4;
        let asn = Asn::new_32bit(u32::from_be_bytes([
            wire[last],
            wire[last + 1],
            wire[last + 2],
            wire[last + 3],
        ]));
        return AsnsView {
            repr: OriginsRepr::One(asn),
        };
    }

    let mut rest = wire;
    let mut last_seg: Option<(u8, &[u8])> = None;
    while rest.len() >= 2 {
        let code = rest[0];
        let count = rest[1] as usize;
        let end = 2 + count * 4;
        last_seg = Some((code, &rest[2..end]));
        rest = &rest[end..];
    }

    let repr = match last_seg {
        Some((AS_PATH_AS_SEQUENCE, bytes)) if bytes.len() >= 4 => {
            let i = bytes.len() - 4;
            OriginsRepr::One(Asn::new_32bit(u32::from_be_bytes([
                bytes[i],
                bytes[i + 1],
                bytes[i + 2],
                bytes[i + 3],
            ])))
        }
        Some((AS_PATH_AS_SET, bytes)) if !bytes.is_empty() => {
            OriginsRepr::Set(bytes_as_be_u32_words(bytes))
        }
        _ => OriginsRepr::Empty,
    };
    AsnsView { repr }
}

/// Compute exact post-`coalesce()` origin ASNs of RFC 6793 merged `(as_path, as4_path)` without
/// allocating.
#[cold]
fn merged_wire_origins<'a>(as_path: &'a [u8], as4_path: &'a [u8]) -> AsnsView<'a> {
    #[derive(Clone, Copy)]
    enum LastCoalesced<'b> {
        None,
        EmptySeq,
        NonEmptyAsSeq(Asn),
        NonEmptyConfedSeq,
        AsSet(&'b [BeU32]),
        ConfedSet,
    }

    let segs = AsPathSegments {
        lead: if wire_route_len(as_path) > wire_route_len(as4_path) {
            as_path
        } else {
            &[]
        },
        lead_remaining: wire_route_len(as_path) - wire_route_len(as4_path),
        tail: as4_path,
    };

    let mut state = LastCoalesced::None;
    for seg in segs {
        let next_state = match seg.seg_type {
            AsPathSegmentType::AsSequence => {
                if seg.asn_bytes.len() >= 4 {
                    let i = seg.asn_bytes.len() - 4;
                    LastCoalesced::NonEmptyAsSeq(Asn::new_32bit(u32::from_be_bytes([
                        seg.asn_bytes[i],
                        seg.asn_bytes[i + 1],
                        seg.asn_bytes[i + 2],
                        seg.asn_bytes[i + 3],
                    ])))
                } else {
                    LastCoalesced::EmptySeq
                }
            }
            AsPathSegmentType::ConfedSequence => {
                if seg.asn_bytes.is_empty() {
                    LastCoalesced::EmptySeq
                } else {
                    LastCoalesced::NonEmptyConfedSeq
                }
            }
            AsPathSegmentType::AsSet => LastCoalesced::AsSet(bytes_as_be_u32_words(seg.asn_bytes)),
            AsPathSegmentType::ConfedSet => LastCoalesced::ConfedSet,
        };

        // Mirrors `AsPathSegment::merge_in_place` in `AsPath::coalesce`.
        state = match (state, next_state) {
            (LastCoalesced::None, y) | (LastCoalesced::EmptySeq, y) => y,
            (x, LastCoalesced::EmptySeq) => x,
            (_, y) => y,
        };
    }

    let repr = match state {
        LastCoalesced::NonEmptyAsSeq(asn) => OriginsRepr::One(asn),
        LastCoalesced::AsSet(words) if !words.is_empty() => OriginsRepr::Set(words),
        _ => OriginsRepr::Empty,
    };
    AsnsView { repr }
}

/// Zero-allocation view over the originating ASNs of an element's `AS_PATH`.
#[derive(Clone, Copy, Debug)]
pub struct AsnsView<'a> {
    repr: OriginsRepr<'a>,
}

impl<'a> AsnsView<'a> {
    /// Returns `true` when the element carries a valid `AS_PATH` (matching
    /// `elem.origin_asns.is_some()` on [`BgpElem`](crate::BgpElem)).
    #[inline]
    pub fn is_present(&self) -> bool {
        !matches!(self.repr, OriginsRepr::Absent)
    }

    /// Returns the number of originating ASNs (`0`, `1`, or the cardinality of a trailing
    /// `AS_SET`).
    #[inline]
    pub fn len(&self) -> usize {
        match self.repr {
            OriginsRepr::Absent | OriginsRepr::Empty => 0,
            OriginsRepr::One(_) => 1,
            OriginsRepr::Set(words) => words.len(),
        }
    }

    /// Returns `true` if there are zero originating ASNs.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator over the originating [`Asn`]s without allocating.
    #[inline]
    pub fn iter(&self) -> AsnsIter<'a> {
        AsnsIter { repr: self.repr }
    }

    /// Materialises the originating [`Asn`]s into a `Vec<Asn>`.
    pub fn to_vec(&self) -> Vec<Asn> {
        self.iter().collect()
    }
}

impl<'a> IntoIterator for AsnsView<'a> {
    type Item = Asn;
    type IntoIter = AsnsIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &AsnsView<'a> {
    type Item = Asn;
    type IntoIter = AsnsIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over originating [`Asn`]s from [`AsnsView`].
#[derive(Clone, Debug)]
pub struct AsnsIter<'a> {
    repr: OriginsRepr<'a>,
}

impl<'a> Iterator for AsnsIter<'a> {
    type Item = Asn;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.repr {
            OriginsRepr::Absent | OriginsRepr::Empty => None,
            OriginsRepr::One(asn) => {
                let out = *asn;
                self.repr = OriginsRepr::Empty;
                Some(out)
            }
            OriginsRepr::Set(words) => {
                let (first, rest) = words.split_first()?;
                *words = rest;
                Some(Asn::new_32bit(first.get()))
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = match self.repr {
            OriginsRepr::Absent | OriginsRepr::Empty => 0,
            OriginsRepr::One(_) => 1,
            OriginsRepr::Set(words) => words.len(),
        };
        (len, Some(len))
    }
}

impl ExactSizeIterator for AsnsIter<'_> {}

/// AGGREGATOR / AS4_AGGREGATOR: the ASN width follows the attribute length (6 or 8 octets).
#[inline]
fn decode_aggregator_slice(val: &[u8]) -> Option<(Asn, BgpIdentifier)> {
    match val.len() {
        8 => Some((
            Asn::new_32bit(u32::from_be_bytes([val[0], val[1], val[2], val[3]])),
            Ipv4Addr::new(val[4], val[5], val[6], val[7]),
        )),
        6 => Some((
            Asn::new_16bit(u16::from_be_bytes([val[0], val[1]])),
            Ipv4Addr::new(val[2], val[3], val[4], val[5]),
        )),
        _ => None,
    }
}

///////////////////////////////////////////////////////////////////////////////
// Communities View
///////////////////////////////////////////////////////////////////////////////

/// Cast a byte slice whose length is a multiple of 4 into a zero-copy slice of unaligned
/// network-byte-order 32-bit words (`zerocopy::big_endian::U32`) without `unsafe`.
///
/// If `bytes.len()` is not a multiple of 4, returns an empty slice.
#[inline]
fn bytes_as_be_u32_words(bytes: &[u8]) -> &[BeU32] {
    if !bytes.len().is_multiple_of(4) {
        return &[];
    }
    <[BeU32]>::ref_from_bytes(bytes).unwrap_or(&[])
}

/// Zero-copy slice view over unaligned big-endian 32-bit community words in the record body.
#[derive(Clone, Copy, Debug, Default)]
pub struct CommunityWords<'a> {
    words: &'a [BeU32],
}

impl<'a> CommunityWords<'a> {
    /// Number of 32-bit words in this slice.
    #[inline]
    pub fn len(&self) -> usize {
        self.words.len()
    }

    /// Returns `true` if the slice contains no 32-bit words.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// Reads the `index`-th big-endian 32-bit word as a host `u32`.
    #[inline]
    pub fn get(&self, index: usize) -> Option<u32> {
        self.words.get(index).map(|w| w.get())
    }

    /// Iterates over host-endian `u32` words decoded in place.
    #[inline]
    pub fn iter(&self) -> WordSliceIter<'a> {
        WordSliceIter { words: self.words }
    }
}

impl<'a> IntoIterator for CommunityWords<'a> {
    type Item = u32;
    type IntoIter = WordSliceIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over host-endian `u32` words from a [`CommunityWords`] slice.
#[derive(Clone, Debug)]
pub struct WordSliceIter<'a> {
    words: &'a [BeU32],
}

impl Iterator for WordSliceIter<'_> {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<u32> {
        let (first, rest) = self.words.split_first()?;
        self.words = rest;
        Some(first.get())
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.words.len();
        (n, Some(n))
    }
}

impl ExactSizeIterator for WordSliceIter<'_> {}

/// Borrowed view over an element's BGP community attributes (`COMMUNITIES`,
/// `EXTENDED_COMMUNITIES`, `IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES`, and
/// `LARGE_COMMUNITIES`).
///
/// Note on wire layout: BGP attributes in MRT bodies sit at arbitrary 1-byte alignments, store
/// integers in network byte order (big-endian), and split plain, extended, and large communities
/// across distinct TLV attributes. Consequently, a native `&[u32]` slice cannot borrow the wire
/// bytes directly on little-endian hosts without copying. Instead, `CommunitiesView` borrows the
/// attribute bytes directly and exposes zero-allocation 32-bit word accessors ([`words`](Self::words),
/// [`plain_words`](Self::plain_words), [`extended_words`](Self::extended_words),
/// [`large_words`](Self::large_words)) alongside typed in-place adapters
/// ([`as_plain`](Self::as_plain), [`as_extended`](Self::as_extended),
/// [`as_ipv6_extended`](Self::as_ipv6_extended), [`as_large`](Self::as_large), and
/// [`iter`](Self::iter)).
#[derive(Clone, Copy, Debug)]
pub struct CommunitiesView<'a> {
    attr_bytes: &'a [u8],
}

impl<'a> CommunitiesView<'a> {
    /// Returns `true` if the element carries no communities of any kind.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    /// Iterates over all raw 32-bit big-endian words across all valid community attributes in wire
    /// order (`1` word per plain community, `2` per extended, `5` per IPv6 extended, `3` per
    /// large).
    #[inline]
    pub fn words(&self) -> CommunityWordsIter<'a> {
        CommunityWordsIter {
            rest_attrs: self.attr_bytes,
            cur_words: &[],
        }
    }

    /// Zero-copy view over the 32-bit words of the `COMMUNITIES` (type 8) attribute.
    #[inline]
    pub fn plain_words(&self) -> CommunityWords<'a> {
        self.first_valid_words(u8::from(AttrType::COMMUNITIES), 4)
    }

    /// Zero-copy view over the 32-bit words of the `EXTENDED_COMMUNITIES` (type 16) attribute
    /// (two `u32` words per 8-octet extended community).
    #[inline]
    pub fn extended_words(&self) -> CommunityWords<'a> {
        self.first_valid_words(u8::from(AttrType::EXTENDED_COMMUNITIES), 8)
    }

    /// Zero-copy view over the 32-bit words of the `LARGE_COMMUNITIES` (type 32) attribute
    /// (three `u32` words per 12-octet large community).
    #[inline]
    pub fn large_words(&self) -> CommunityWords<'a> {
        self.first_valid_words(u8::from(AttrType::LARGE_COMMUNITIES), 12)
    }

    /// Iterates over standard RFC 1997 [`Community`] values (`COMMUNITIES`, type 8).
    #[inline]
    pub fn as_plain(&self) -> PlainCommunitiesIter<'a> {
        PlainCommunitiesIter {
            rest_attrs: self.attr_bytes,
            cur_words: &[],
        }
    }

    /// Iterates over RFC 4360 [`ExtendedCommunity`] values (`EXTENDED_COMMUNITIES`, type 16).
    #[inline]
    pub fn as_extended(&self) -> ExtendedCommunitiesIter<'a> {
        ExtendedCommunitiesIter {
            rest_attrs: self.attr_bytes,
            cur_bytes: &[],
        }
    }

    /// Iterates over RFC 5701 [`Ipv6AddrExtCommunity`] values
    /// (`IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES`, type 25).
    #[inline]
    pub fn as_ipv6_extended(&self) -> Ipv6ExtendedCommunitiesIter<'a> {
        Ipv6ExtendedCommunitiesIter {
            rest_attrs: self.attr_bytes,
            cur_bytes: &[],
        }
    }

    /// Iterates over RFC 8092 [`LargeCommunity`] values (`LARGE_COMMUNITIES`, type 32).
    #[inline]
    pub fn as_large(&self) -> LargeCommunitiesIter<'a> {
        LargeCommunitiesIter {
            rest_attrs: self.attr_bytes,
            cur_words: &[],
        }
    }

    /// Iterates over all [`MetaCommunity`] values in wire attribute order, matching
    /// [`BgpElem::communities`](crate::BgpElem::communities).
    #[inline]
    pub fn iter(&self) -> MetaCommunitiesIter<'a> {
        MetaCommunitiesIter {
            rest_attrs: self.attr_bytes,
            cur_kind: ActiveCommunityAttr::None,
        }
    }

    fn first_valid_words(&self, target_code: u8, unit_bytes: usize) -> CommunityWords<'a> {
        let mut rest = self.attr_bytes;
        while let Some((code, val, next_rest)) = next_attr_tlv(rest) {
            rest = next_rest;
            if code == target_code && val.len().is_multiple_of(unit_bytes) {
                return CommunityWords {
                    words: bytes_as_be_u32_words(val),
                };
            }
        }
        CommunityWords { words: &[] }
    }
}

impl<'a> IntoIterator for CommunitiesView<'a> {
    type Item = MetaCommunity;
    type IntoIter = MetaCommunitiesIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &CommunitiesView<'a> {
    type Item = MetaCommunity;
    type IntoIter = MetaCommunitiesIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[inline]
fn next_attr_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if bytes.len() < 3 {
        return None;
    }
    let flags = bytes[0];
    let code = bytes[1];
    let (hdr_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
        (3usize, bytes[2] as usize)
    } else {
        if bytes.len() < 4 {
            return None;
        }
        (4usize, u16::from_be_bytes([bytes[2], bytes[3]]) as usize)
    };
    let end = hdr_len + attr_len;
    if end > bytes.len() {
        return None;
    }
    Some((code, &bytes[hdr_len..end], &bytes[end..]))
}

#[inline]
fn decode_plain_community(word: u32) -> Community {
    match word {
        COMMUNITY_NO_EXPORT => Community::NoExport,
        COMMUNITY_NO_ADVERTISE => Community::NoAdvertise,
        COMMUNITY_NO_EXPORT_SUBCONFED => Community::NoExportSubConfed,
        value => {
            let asn = ((value >> 16) & 0xFFFF) as u16;
            let data = (value & 0xFFFF) as u16;
            Community::Custom(Asn::new_16bit(asn), data)
        }
    }
}

fn decode_extended_community(b: [u8; 8]) -> ExtendedCommunity {
    let ec_type_u8 = b[0];
    let sub_type = b[1];
    match ExtendedCommunityType::from(ec_type_u8) {
        ExtendedCommunityType::TransitiveTwoOctetAs => match sub_type {
            0x04 => ExtendedCommunity::LinkBandwidth(LinkBandwidth {
                global_admin: u16::from_be_bytes([b[2], b[3]]),
                bandwidth: f32::from_bits(u32::from_be_bytes([b[4], b[5], b[6], b[7]])),
                transitive: true,
            }),
            _ => ExtendedCommunity::TransitiveTwoOctetAs(TwoOctetAsExtCommunity {
                subtype: sub_type,
                global_admin: Asn::new_16bit(u16::from_be_bytes([b[2], b[3]])),
                local_admin: [b[4], b[5], b[6], b[7]],
            }),
        },
        ExtendedCommunityType::NonTransitiveTwoOctetAs => match sub_type {
            0x04 => ExtendedCommunity::LinkBandwidth(LinkBandwidth {
                global_admin: u16::from_be_bytes([b[2], b[3]]),
                bandwidth: f32::from_bits(u32::from_be_bytes([b[4], b[5], b[6], b[7]])),
                transitive: false,
            }),
            0x06 => ExtendedCommunity::FlowSpecTrafficRate(FlowSpecTrafficRate::new(
                u16::from_be_bytes([b[2], b[3]]),
                f32::from_bits(u32::from_be_bytes([b[4], b[5], b[6], b[7]])),
            )),
            0x07 => {
                let as_number = u16::from_be_bytes([b[2], b[3]]);
                let flags = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                ExtendedCommunity::FlowSpecTrafficAction(FlowSpecTrafficAction::new(
                    as_number,
                    (flags & 0x01) != 0,
                    (flags & 0x02) != 0,
                ))
            }
            0x08 => ExtendedCommunity::FlowSpecRedirect(TwoOctetAsExtCommunity {
                subtype: sub_type,
                global_admin: Asn::new_16bit(u16::from_be_bytes([b[2], b[3]])),
                local_admin: [b[4], b[5], b[6], b[7]],
            }),
            0x09 => ExtendedCommunity::FlowSpecTrafficMarking(FlowSpecTrafficMarking::new(
                u16::from_be_bytes([b[2], b[3]]),
                b[4],
            )),
            _ => ExtendedCommunity::NonTransitiveTwoOctetAs(TwoOctetAsExtCommunity {
                subtype: sub_type,
                global_admin: Asn::new_16bit(u16::from_be_bytes([b[2], b[3]])),
                local_admin: [b[4], b[5], b[6], b[7]],
            }),
        },
        ExtendedCommunityType::TransitiveIpv4Addr => {
            ExtendedCommunity::TransitiveIpv4Addr(Ipv4AddrExtCommunity {
                subtype: sub_type,
                global_admin: Ipv4Addr::new(b[2], b[3], b[4], b[5]),
                local_admin: [b[6], b[7]],
            })
        }
        ExtendedCommunityType::NonTransitiveIpv4Addr => {
            ExtendedCommunity::NonTransitiveIpv4Addr(Ipv4AddrExtCommunity {
                subtype: sub_type,
                global_admin: Ipv4Addr::new(b[2], b[3], b[4], b[5]),
                local_admin: [b[6], b[7]],
            })
        }
        ExtendedCommunityType::TransitiveFourOctetAs => {
            ExtendedCommunity::TransitiveFourOctetAs(FourOctetAsExtCommunity {
                subtype: sub_type,
                global_admin: Asn::new_32bit(u32::from_be_bytes([b[2], b[3], b[4], b[5]])),
                local_admin: [b[6], b[7]],
            })
        }
        ExtendedCommunityType::NonTransitiveFourOctetAs => {
            ExtendedCommunity::NonTransitiveFourOctetAs(FourOctetAsExtCommunity {
                subtype: sub_type,
                global_admin: Asn::new_32bit(u32::from_be_bytes([b[2], b[3], b[4], b[5]])),
                local_admin: [b[6], b[7]],
            })
        }
        ExtendedCommunityType::TransitiveOpaque => {
            ExtendedCommunity::TransitiveOpaque(OpaqueExtCommunity {
                subtype: sub_type,
                value: [b[2], b[3], b[4], b[5], b[6], b[7]],
            })
        }
        ExtendedCommunityType::NonTransitiveOpaque => {
            ExtendedCommunity::NonTransitiveOpaque(OpaqueExtCommunity {
                subtype: sub_type,
                value: [b[2], b[3], b[4], b[5], b[6], b[7]],
            })
        }
        ExtendedCommunityType::Evpn => match sub_type {
            0x00 => ExtendedCommunity::MacMobility(MacMobility {
                sticky: (b[2] & 0x01) != 0,
                sequence: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            }),
            _ => ExtendedCommunity::Raw(b),
        },
        ExtendedCommunityType::Unknown(_) => ExtendedCommunity::Raw(b),
    }
}

fn decode_ipv6_extended_community(b: &[u8]) -> Ipv6AddrExtCommunity {
    let addr_octets: [u8; 16] = b[2..18].try_into().expect("16-octet IPv6 address");
    Ipv6AddrExtCommunity {
        community_type: ExtendedCommunityType::from(b[0]),
        subtype: b[1],
        global_admin: Ipv6Addr::from(addr_octets),
        local_admin: [b[18], b[19]],
    }
}

/// Iterator over all raw 32-bit community words across an element's community attributes.
#[derive(Clone, Debug)]
pub struct CommunityWordsIter<'a> {
    rest_attrs: &'a [u8],
    cur_words: &'a [BeU32],
}

impl Iterator for CommunityWordsIter<'_> {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<u32> {
        loop {
            if let Some((first, rest)) = self.cur_words.split_first() {
                self.cur_words = rest;
                return Some(first.get());
            }
            let (code, val, next_rest) = next_attr_tlv(self.rest_attrs)?;
            self.rest_attrs = next_rest;
            let valid = match AttrType::from(code) {
                AttrType::COMMUNITIES => val.len().is_multiple_of(4),
                AttrType::EXTENDED_COMMUNITIES => val.len().is_multiple_of(8),
                AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES => {
                    val.len().is_multiple_of(20)
                }
                AttrType::LARGE_COMMUNITIES => val.len().is_multiple_of(12),
                _ => false,
            };
            if valid {
                self.cur_words = bytes_as_be_u32_words(val);
            }
        }
    }
}

/// Iterator over standard [`Community`] values from [`CommunitiesView::as_plain`].
#[derive(Clone, Debug)]
pub struct PlainCommunitiesIter<'a> {
    rest_attrs: &'a [u8],
    cur_words: &'a [BeU32],
}

impl Iterator for PlainCommunitiesIter<'_> {
    type Item = Community;

    #[inline]
    fn next(&mut self) -> Option<Community> {
        loop {
            if let Some((first, rest)) = self.cur_words.split_first() {
                self.cur_words = rest;
                return Some(decode_plain_community(first.get()));
            }
            let (code, val, next_rest) = next_attr_tlv(self.rest_attrs)?;
            self.rest_attrs = next_rest;
            if code == u8::from(AttrType::COMMUNITIES) && val.len().is_multiple_of(4) {
                self.cur_words = bytes_as_be_u32_words(val);
            }
        }
    }
}

/// Iterator over [`ExtendedCommunity`] values from [`CommunitiesView::as_extended`].
#[derive(Clone, Debug)]
pub struct ExtendedCommunitiesIter<'a> {
    rest_attrs: &'a [u8],
    cur_bytes: &'a [u8],
}

impl Iterator for ExtendedCommunitiesIter<'_> {
    type Item = ExtendedCommunity;

    #[inline]
    fn next(&mut self) -> Option<ExtendedCommunity> {
        loop {
            if self.cur_bytes.len() >= 8 {
                let raw: [u8; 8] = self.cur_bytes[..8].try_into().expect("8 bytes");
                self.cur_bytes = &self.cur_bytes[8..];
                return Some(decode_extended_community(raw));
            }
            let (code, val, next_rest) = next_attr_tlv(self.rest_attrs)?;
            self.rest_attrs = next_rest;
            if code == u8::from(AttrType::EXTENDED_COMMUNITIES) && val.len().is_multiple_of(8) {
                self.cur_bytes = val;
            }
        }
    }
}

/// Iterator over [`Ipv6AddrExtCommunity`] values from [`CommunitiesView::as_ipv6_extended`].
#[derive(Clone, Debug)]
pub struct Ipv6ExtendedCommunitiesIter<'a> {
    rest_attrs: &'a [u8],
    cur_bytes: &'a [u8],
}

impl Iterator for Ipv6ExtendedCommunitiesIter<'_> {
    type Item = Ipv6AddrExtCommunity;

    #[inline]
    fn next(&mut self) -> Option<Ipv6AddrExtCommunity> {
        loop {
            if self.cur_bytes.len() >= 20 {
                let item = decode_ipv6_extended_community(&self.cur_bytes[..20]);
                self.cur_bytes = &self.cur_bytes[20..];
                return Some(item);
            }
            let (code, val, next_rest) = next_attr_tlv(self.rest_attrs)?;
            self.rest_attrs = next_rest;
            if code == u8::from(AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES)
                && val.len().is_multiple_of(20)
            {
                self.cur_bytes = val;
            }
        }
    }
}

/// Iterator over [`LargeCommunity`] values from [`CommunitiesView::as_large`].
#[derive(Clone, Debug)]
pub struct LargeCommunitiesIter<'a> {
    rest_attrs: &'a [u8],
    cur_words: &'a [BeU32],
}

impl Iterator for LargeCommunitiesIter<'_> {
    type Item = LargeCommunity;

    #[inline]
    fn next(&mut self) -> Option<LargeCommunity> {
        loop {
            if self.cur_words.len() >= 3 {
                let ga = self.cur_words[0].get();
                let d0 = self.cur_words[1].get();
                let d1 = self.cur_words[2].get();
                self.cur_words = &self.cur_words[3..];
                return Some(LargeCommunity::new(ga, [d0, d1]));
            }
            let (code, val, next_rest) = next_attr_tlv(self.rest_attrs)?;
            self.rest_attrs = next_rest;
            if code == u8::from(AttrType::LARGE_COMMUNITIES) && val.len().is_multiple_of(12) {
                self.cur_words = bytes_as_be_u32_words(val);
            }
        }
    }
}

#[derive(Clone, Debug)]
enum ActiveCommunityAttr<'a> {
    None,
    Plain(&'a [BeU32]),
    Extended(&'a [u8]),
    Ipv6Extended(&'a [u8]),
    Large(&'a [BeU32]),
}

/// Iterator over all [`MetaCommunity`] items in wire attribute order.
#[derive(Clone, Debug)]
pub struct MetaCommunitiesIter<'a> {
    rest_attrs: &'a [u8],
    cur_kind: ActiveCommunityAttr<'a>,
}

impl Iterator for MetaCommunitiesIter<'_> {
    type Item = MetaCommunity;

    #[inline]
    fn next(&mut self) -> Option<MetaCommunity> {
        loop {
            match &mut self.cur_kind {
                ActiveCommunityAttr::Plain(words) => {
                    if let Some((first, rest)) = words.split_first() {
                        *words = rest;
                        return Some(MetaCommunity::Plain(decode_plain_community(first.get())));
                    }
                }
                ActiveCommunityAttr::Extended(bytes) => {
                    if bytes.len() >= 8 {
                        let raw: [u8; 8] = bytes[..8].try_into().expect("8 bytes");
                        *bytes = &bytes[8..];
                        return Some(MetaCommunity::Extended(decode_extended_community(raw)));
                    }
                }
                ActiveCommunityAttr::Ipv6Extended(bytes) => {
                    if bytes.len() >= 20 {
                        let item = decode_ipv6_extended_community(&bytes[..20]);
                        *bytes = &bytes[20..];
                        return Some(MetaCommunity::Ipv6Extended(item));
                    }
                }
                ActiveCommunityAttr::Large(words) => {
                    if words.len() >= 3 {
                        let ga = words[0].get();
                        let d0 = words[1].get();
                        let d1 = words[2].get();
                        *words = &words[3..];
                        return Some(MetaCommunity::Large(LargeCommunity::new(ga, [d0, d1])));
                    }
                }
                ActiveCommunityAttr::None => {}
            }

            self.cur_kind = ActiveCommunityAttr::None;
            let (code, val, next_rest) = next_attr_tlv(self.rest_attrs)?;
            self.rest_attrs = next_rest;
            match AttrType::from(code) {
                AttrType::COMMUNITIES if val.len().is_multiple_of(4) => {
                    self.cur_kind = ActiveCommunityAttr::Plain(bytes_as_be_u32_words(val));
                }
                AttrType::EXTENDED_COMMUNITIES if val.len().is_multiple_of(8) => {
                    self.cur_kind = ActiveCommunityAttr::Extended(val);
                }
                AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES
                    if val.len().is_multiple_of(20) =>
                {
                    self.cur_kind = ActiveCommunityAttr::Ipv6Extended(val);
                }
                AttrType::LARGE_COMMUNITIES if val.len().is_multiple_of(12) => {
                    self.cur_kind = ActiveCommunityAttr::Large(bytes_as_be_u32_words(val));
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_as_be_u32_words_alignment_and_length_check() {
        // Unaligned subslice (offset 1) with valid multiple-of-4 length decodes big-endian u32s.
        let backing = [0xAA, 0x00, 0x00, 0xFD, 0xE8, 0xFF, 0xFF, 0xFF, 0x01];
        let unaligned = &backing[1..9];
        let words = bytes_as_be_u32_words(unaligned);
        assert_eq!(words.len(), 2);
        assert_eq!(words[0].get(), 65_000);
        assert_eq!(words[1].get(), COMMUNITY_NO_EXPORT);

        // Non-multiple-of-4 length is rejected cleanly as empty rather than panicking.
        assert!(bytes_as_be_u32_words(&backing[1..8]).is_empty());
        assert!(bytes_as_be_u32_words(&[]).is_empty());
    }
}

#[cfg(test)]
mod materialise_tests {
    use super::*;

    /// A real TABLE_DUMP_V2 slice: one PEER_INDEX_TABLE followed by 399 RIB records.
    const RIB_FIXTURE: &str = "tests/fixtures/routeviews/bview.slice.gz";

    /// The borrowed view serves updates as well as dumps, and must produce the same elements the
    /// owned record path produces for the same file.
    #[test]
    fn borrowed_update_elems_match_owned_elems() {
        // A 15-minute RIPE update file: BGP4MP messages with 4-byte AS numbers.
        let fixture = "tests/fixtures/ripe/rrc15/2010.02/updates.20100227.1600.gz";
        // The borrowed view serves the AS4 message subtypes; the fixture also carries 2-byte ASN
        // records from 2010, which stay on the owned path and are excluded from the comparison.
        let (owned, legacy_records): (Vec<_>, usize) = {
            let mut elementor = crate::parser::mrt::mrt_elem::Elementor::new();
            let mut owned = Vec::new();
            let mut legacy = 0;
            for record in BgpkitParser::new(fixture)
                .expect("open fixture")
                .into_record_iter()
            {
                if !matches!(record.common_header.entry_subtype, 4 | 5 | 9 | 10) {
                    legacy += 1;
                    continue;
                }
                owned.extend(elementor.record_to_elems(record));
            }
            (owned, legacy)
        };
        assert!(!owned.is_empty(), "fixture produced no elems");
        assert!(
            legacy_records > 0,
            "fixture should exercise the 2-byte skip"
        );

        let mut parser = BgpkitParser::new(fixture).expect("open fixture");
        let mut borrowed = Vec::new();
        while let Some(mut record) = parser.next_record_elems() {
            assert!(!record.is_empty(), "an update record declared no elements");
            for elem in record.iter() {
                borrowed.push(elem.to_bgp_elem());
            }
        }
        assert_eq!(owned.len(), borrowed.len(), "element count differs");
        for (index, (owned_elem, borrowed_elem)) in owned.iter().zip(&borrowed).enumerate() {
            assert_eq!(owned_elem, borrowed_elem, "element {index} differs");
        }
    }

    /// Every field of a materialised element must equal what the owned record path produces for
    /// the same entry. The reference is the record iterator plus `Elementor`, not `into_elem_iter`,
    /// which now goes through this same borrowed engine.
    #[test]
    fn borrowed_elems_match_owned_elems() {
        let owned: Vec<_> = {
            let mut elementor = crate::parser::mrt::mrt_elem::Elementor::new();
            BgpkitParser::new(RIB_FIXTURE)
                .expect("open fixture")
                .into_record_iter()
                .flat_map(|record| elementor.record_to_elems(record))
                .collect()
        };
        assert!(!owned.is_empty(), "fixture produced no elems");

        let mut parser = BgpkitParser::new(RIB_FIXTURE).expect("open fixture");
        let mut borrowed = Vec::new();
        while let Some(mut record) = parser.next_record_elems() {
            for elem in record.iter() {
                borrowed.push(elem.to_bgp_elem());
            }
        }

        assert_eq!(owned.len(), borrowed.len(), "element count differs");
        for (index, (owned_elem, borrowed_elem)) in owned.iter().zip(borrowed.iter()).enumerate() {
            assert_eq!(owned_elem, borrowed_elem, "elem {index} differs");
        }
    }
}

#[cfg(test)]
mod wire_parity_tests {
    use crate::models::*;
    use std::io::Cursor;
    use std::str::FromStr;

    /// Wrap a BGP4MP body in an MRT common header.
    fn mrt(subtype: Bgp4MpType, body: Vec<u8>) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(&1_600_000_000u32.to_be_bytes());
        wire.extend_from_slice(&(EntryType::BGP4MP as u16).to_be_bytes());
        wire.extend_from_slice(&(subtype as u16).to_be_bytes());
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(&body);
        wire
    }

    /// A BGP4MP message body: envelope, then a BGP message of the given type.
    fn bgp4mp_body(asn_len: AsnLength, afi: Afi, msg_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        match asn_len {
            AsnLength::Bits16 => {
                body.extend_from_slice(&64496u16.to_be_bytes());
                body.extend_from_slice(&64497u16.to_be_bytes());
            }
            AsnLength::Bits32 => {
                body.extend_from_slice(&64496u32.to_be_bytes());
                body.extend_from_slice(&64497u32.to_be_bytes());
            }
        }
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&u16::from(afi).to_be_bytes());
        match afi {
            Afi::Ipv4 => {
                body.extend_from_slice(&[192, 0, 2, 1]);
                body.extend_from_slice(&[192, 0, 2, 2]);
            }
            Afi::Ipv6 => {
                body.extend_from_slice(&[
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]);
                body.extend_from_slice(&[
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                ]);
            }
            other => panic!("test does not build BGP4MP records for {other:?}"),
        }
        let mut message = vec![0xFF; 16];
        message.extend_from_slice(&((19 + payload.len()) as u16).to_be_bytes());
        message.push(msg_type);
        message.extend_from_slice(payload);
        body.extend_from_slice(&message);
        body
    }

    /// An UPDATE payload: withdrawn NLRI, attribute block, announced NLRI.
    fn update_payload(withdrawn: &[u8], attributes: &[u8], announced: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
        payload.extend_from_slice(withdrawn);
        payload.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        payload.extend_from_slice(attributes);
        payload.extend_from_slice(announced);
        payload
    }

    /// One path attribute with a one-octet length. Optional attributes need the optional bit, or
    /// the parser treats the flag byte as a validation finding and drops the attribute.
    fn attr(code: u8, body: &[u8]) -> Vec<u8> {
        let optional = matches!(code, 14 | 15);
        let flags = if optional { 0x80 } else { 0x40 };
        let mut out = vec![flags, code, body.len() as u8];
        out.extend_from_slice(body);
        out
    }

    fn origin_igp() -> Vec<u8> {
        attr(1, &[0])
    }

    fn next_hop() -> Vec<u8> {
        attr(3, &[192, 0, 2, 254])
    }

    /// AS_SEQUENCE of length zero followed by a real one: the owned renderer writes a separator for
    /// the empty segment, so a view that skipped it would compare positions differently.
    fn as_path_with_empty_segment() -> Vec<u8> {
        let mut body = vec![2u8, 0];
        body.extend_from_slice(&[2u8, 2]);
        body.extend_from_slice(&3356u32.to_be_bytes());
        body.extend_from_slice(&174u32.to_be_bytes());
        attr(2, &body)
    }

    fn as_path(asns: &[u32], width: AsnLength) -> Vec<u8> {
        let mut body = vec![2u8, asns.len() as u8];
        for asn in asns {
            match width {
                AsnLength::Bits16 => body.extend_from_slice(&(*asn as u16).to_be_bytes()),
                AsnLength::Bits32 => body.extend_from_slice(&asn.to_be_bytes()),
            }
        }
        attr(2, &body)
    }

    /// MP_UNREACH_NLRI for AFI 1, SAFI 4 (labelled unicast): one NLRI whose first 24 of 48 bits are
    /// the compatibility field, leaving 203.0.113.0/24.
    fn labelled_withdrawal_attr() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_be_bytes());
        body.push(4);
        body.push(48);
        body.extend_from_slice(&[0x00, 0x01, 0x02]);
        body.extend_from_slice(&[203, 0, 113]);
        attr(15, &body)
    }

    /// A one-octet NLRI encoding of an IPv4 prefix.
    fn nlri(prefix: &str) -> Vec<u8> {
        let network = NetworkPrefix::from_str(prefix).expect("parse prefix");
        let bits = network.prefix.prefix_len();
        let mut out = vec![bits];
        match network.prefix {
            ipnet::IpNet::V4(v4) => {
                let octets = v4.addr().octets();
                out.extend_from_slice(&octets[..usize::from(bits).div_ceil(8)]);
            }
            ipnet::IpNet::V6(_) => panic!("test builds IPv4 NLRI here"),
        }
        out
    }

    fn owned_elems(wire: &[u8]) -> Vec<BgpElem> {
        crate::BgpkitParser::from_reader(Cursor::new(wire.to_vec()))
            .into_elem_iter()
            .collect()
    }

    fn borrowed_elems(wire: &[u8]) -> Vec<BgpElem> {
        let mut parser = crate::BgpkitParser::from_reader(Cursor::new(wire.to_vec()));
        let mut elems = Vec::new();
        while let Some(mut record) = parser.next_record_elems() {
            for elem in &mut record {
                elems.push(elem.to_bgp_elem());
            }
        }
        elems
    }

    /// Wrap a body in an MRT header of an explicit entry type and subtype.
    fn mrt_typed(entry: EntryType, subtype: u16, body: Vec<u8>) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(&1_600_000_000u32.to_be_bytes());
        wire.extend_from_slice(&(entry as u16).to_be_bytes());
        wire.extend_from_slice(&subtype.to_be_bytes());
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(&body);
        wire
    }

    /// A `PEER_INDEX_TABLE` record with one peer, then one `RIB_AFI` record for the prefix, mirroring
    /// what a dump carries.
    fn rib_record(
        rib_subtype: u16,
        prefix_len: u8,
        prefix_bytes: &[u8],
        attributes: &[u8],
    ) -> Vec<u8> {
        let mut peer_table = Vec::new();
        peer_table.extend_from_slice(&[192, 0, 2, 10]); // collector BGP id
        peer_table.extend_from_slice(&0u16.to_be_bytes()); // empty view name
        peer_table.extend_from_slice(&1u16.to_be_bytes()); // one peer
        peer_table.push(0); // peer type
        peer_table.extend_from_slice(&[192, 0, 2, 20]); // peer BGP id
        peer_table.extend_from_slice(&[192, 0, 2, 30]); // peer address
        peer_table.extend_from_slice(&64496u32.to_be_bytes()); // peer ASN
        let mut wire = mrt_typed(
            EntryType::TABLE_DUMP_V2,
            TableDumpV2Type::PeerIndexTable as u16,
            peer_table,
        );

        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes()); // sequence number
        body.push(prefix_len);
        body.extend_from_slice(prefix_bytes);
        body.extend_from_slice(&1u16.to_be_bytes()); // one entry
        body.extend_from_slice(&0u16.to_be_bytes()); // peer index
        body.extend_from_slice(&1_600_000_000u32.to_be_bytes()); // originated time
        body.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        body.extend_from_slice(attributes);
        wire.extend_from_slice(&mrt_typed(EntryType::TABLE_DUMP_V2, rib_subtype, body));
        wire
    }

    /// Both paths must produce the same elements for a shape that is legal but rare in real traffic.
    fn assert_same(wire: &[u8]) -> Vec<BgpElem> {
        let owned = owned_elems(wire);
        let borrowed = borrowed_elems(wire);
        assert_eq!(owned, borrowed, "owned and borrowed elements differ");
        owned
    }

    #[test]
    fn empty_as_path_segment() {
        let attributes: Vec<u8> = [origin_igp(), as_path_with_empty_segment(), next_hop()].concat();
        let wire = mrt(
            Bgp4MpType::MessageAs4,
            bgp4mp_body(
                AsnLength::Bits32,
                Afi::Ipv4,
                2,
                &update_payload(&[], &attributes, &nlri("198.51.100.0/24")),
            ),
        );
        let elems = assert_same(&wire);
        assert_eq!(elems.len(), 1);
        let rendered = elems[0].as_path.as_ref().map(|path| path.to_string());
        assert!(
            rendered
                .as_deref()
                .is_some_and(|path| path.contains(" 3356 174")),
            "as_path was {rendered:?}"
        );
    }

    #[test]
    fn labelled_withdrawal() {
        let attributes: Vec<u8> = [
            origin_igp(),
            as_path(&[3356, 174], AsnLength::Bits32),
            labelled_withdrawal_attr(),
        ]
        .concat();
        let wire = mrt(
            Bgp4MpType::MessageAs4,
            bgp4mp_body(
                AsnLength::Bits32,
                Afi::Ipv4,
                2,
                &update_payload(&[], &attributes, &[]),
            ),
        );
        let elems = assert_same(&wire);
        assert_eq!(elems.len(), 1);
        assert_eq!(elems[0].prefix.prefix.to_string(), "203.0.113.0/24");
        assert_eq!(elems[0].elem_type, ElemType::WITHDRAW);
    }

    /// A dump's `NEXT_HOP` is encoded with the record's family, so an IPv6 entry carries sixteen
    /// bytes. Reading it as IPv4 would report the first four octets as the next hop.
    #[test]
    fn ipv6_dump_entry_reads_a_sixteen_byte_next_hop() {
        let next_hop = [0x20u8, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let attributes: Vec<u8> = [
            origin_igp(),
            as_path(&[3356, 174], AsnLength::Bits32),
            attr(3, &next_hop),
        ]
        .concat();
        // RIB_IPV6_UNICAST, 2001:db8::/32
        let wire = rib_record(4, 32, &[0x20, 0x01, 0x0d, 0xb8], &attributes);
        let elems = assert_same(&wire);
        assert_eq!(elems.len(), 1);
        assert_eq!(elems[0].next_hop, Some("2001:db8::1".parse().unwrap()));
    }

    /// The prefix accessor must carry the ADD-PATH identifier the record declared.
    #[test]
    fn add_path_identifier_survives_the_prefix_accessor() {
        let attributes: Vec<u8> = [
            origin_igp(),
            as_path(&[3356, 174], AsnLength::Bits32),
            next_hop(),
        ]
        .concat();
        let mut announced = 7u32.to_be_bytes().to_vec();
        announced.extend_from_slice(&nlri("203.0.113.0/24"));
        let wire = mrt(
            Bgp4MpType::MessageAs4Addpath,
            bgp4mp_body(
                AsnLength::Bits32,
                Afi::Ipv4,
                2,
                &update_payload(&[], &attributes, &announced),
            ),
        );
        let elems = assert_same(&wire);
        assert_eq!(elems.len(), 1);
        assert_eq!(elems[0].prefix.path_id, Some(7));

        let mut parser = crate::BgpkitParser::from_reader(Cursor::new(wire));
        let mut seen = 0;
        while let Some(mut record) = parser.next_record_elems() {
            for elem in &mut record {
                assert_eq!(elem.prefix().path_id, Some(7));
                seen += 1;
            }
        }
        assert_eq!(seen, 1);
    }

    /// A 2-byte-ASN BGP4MP record is outside the borrowed view's scope: it produces no elements
    /// there while the owned path parses it. This pins the documented boundary.
    #[test]
    fn two_byte_asn_record_is_not_served_by_the_view() {
        let attributes: Vec<u8> = [
            origin_igp(),
            as_path(&[3356, 174], AsnLength::Bits16),
            next_hop(),
        ]
        .concat();
        let wire = mrt(
            Bgp4MpType::Message,
            bgp4mp_body(
                AsnLength::Bits16,
                Afi::Ipv4,
                2,
                &update_payload(&[], &attributes, &nlri("198.51.100.0/24")),
            ),
        );
        assert_eq!(owned_elems(&wire).len(), 1);
        assert!(borrowed_elems(&wire).is_empty());
    }

    /// An IPv6 announcement in a record that also carries an IPv4 NEXT_HOP: the owned path prefers
    /// the attribute, so the view must read it as IPv4 rather than with the entry's family.
    #[test]
    fn ipv6_announcement_with_ipv4_next_hop_attribute() {
        let mut mp_reach = Vec::new();
        mp_reach.extend_from_slice(&2u16.to_be_bytes());
        mp_reach.push(1);
        mp_reach.push(16);
        mp_reach.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe,
        ]);
        mp_reach.push(0);
        mp_reach.push(32);
        mp_reach.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        let attributes: Vec<u8> = [
            origin_igp(),
            as_path(&[3356, 174], AsnLength::Bits32),
            next_hop(),
            attr(14, &mp_reach),
        ]
        .concat();
        let wire = mrt(
            Bgp4MpType::MessageAs4,
            bgp4mp_body(
                AsnLength::Bits32,
                Afi::Ipv4,
                2,
                &update_payload(&[], &attributes, &[]),
            ),
        );
        let elems = assert_same(&wire);
        assert_eq!(elems.len(), 1);
        assert_eq!(elems[0].next_hop, Some("192.0.2.254".parse().unwrap()));
    }
}
