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
    AttrType, BgpIdentifier, CommonHeader, Community, ElemType, ExtendedCommunity,
    ExtendedCommunityType, FlowSpecTrafficAction, FlowSpecTrafficMarking, FlowSpecTrafficRate,
    FourOctetAsExtCommunity, Ipv4AddrExtCommunity, Ipv6AddrExtCommunity, LargeCommunity,
    LinkBandwidth, MacMobility, MetaCommunity, NetworkPrefix, NextHopAddress, OpaqueExtCommunity,
    Origin, Peer, PeerType, Safi, TwoOctetAsExtCommunity,
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
                return NextBatch::Rib(RecordElems {
                    header,
                    entries_bytes,
                    peers,
                    prefix: prefix.prefix,
                    entry_count,
                    flags,
                });
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
    use crate::parser::mrt::frame::{classify, RecordKind};

    if parser.text_dump_iter.is_some()
        || !parser.filters.is_empty()
        || parser.elem_view_state.finished
    {
        return None;
    }

    let (common_header, prefix, entry_count, flags, entries_offset, body_len) = loop {
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
                break (
                    common_header,
                    prefix,
                    entry_count,
                    flags,
                    entries_offset,
                    body_len,
                );
            }
            // This entry point serves RIB dumps only; other records are skipped, as documented.
            RecordKind::Bgp4Mp { .. } | RecordKind::Other => continue,
        }
    };

    let state = &mut parser.elem_view_state;
    let peers = state
        .peers
        .as_deref()
        .expect("checked peers is_some before breaking");
    let entries_bytes = &state.body_buf[entries_offset..body_len];
    Some(RecordElems {
        header: common_header,
        entries_bytes,
        peers,
        prefix: prefix.prefix,
        entry_count,
        flags,
    })
}

/// A borrowed batch of elements from one `TABLE_DUMP_V2` `RIB_AFI` MRT record.
///
/// Holds a mutable borrow of the [`BgpkitParser`] (and its active peer table and record buffer);
/// drop `RecordElems` before advancing the parser to the next record.
pub struct RecordElems<'a> {
    header: CommonHeader,
    entries_bytes: &'a [u8],
    peers: &'a [Peer],
    prefix: IpNet,
    entry_count: u16,
    flags: u8,
}

impl<'a> RecordElems<'a> {
    /// Returns the MRT [`CommonHeader`] of this record.
    #[inline]
    pub fn header(&self) -> &CommonHeader {
        &self.header
    }

    /// Returns the exact RIB entry count declared in the `RIB_AFI` header.
    #[inline]
    pub fn len(&self) -> usize {
        self.entry_count as usize
    }

    /// Returns `true` if the `RIB_AFI` header declares zero entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Returns an iterator yielding borrowed [`ElemRef`] views over the record's RIB entries.
    #[inline]
    pub fn iter(&mut self) -> ElemRefIter<'_> {
        ElemRefIter {
            data: self.entries_bytes,
            peers: self.peers,
            prefix: self.prefix,
            remaining: self.entry_count,
            flags: self.flags,
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

/// Iterator over borrowed [`ElemRef`]s within a single [`RecordElems`] record.
pub struct ElemRefIter<'a> {
    data: &'a [u8],
    peers: &'a [Peer],
    prefix: IpNet,
    remaining: u16,
    flags: u8,
    _borrow: PhantomData<&'a mut ()>,
}

impl<'a> ElemRefIter<'a> {
    #[cold]
    #[inline(never)]
    fn finish_truncated_header(&mut self) {
        warn!("early break due to error Truncated message: truncated msg while parsing RIB AFI entries");
        self.remaining = 0;
    }

    #[cold]
    #[inline(never)]
    fn finish_truncated_attrs(&mut self, required: usize, remaining: usize) {
        warn!(
            "early break due to error Truncated message: not enough bytes to read. remaining: {}, required: {} while parsing RIB AFI entries",
            remaining, required
        );
        self.remaining = 0;
    }

    #[cold]
    #[inline(never)]
    fn finish_missing_peer(&mut self, peer_index: u16) {
        error!("peer ID {} not found in peer_index table", peer_index);
        self.remaining = 0;
    }
}

impl<'a> Iterator for ElemRefIter<'a> {
    type Item = ElemRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let data = self.data;
        if (self.flags & FLAG_ADD_PATH) == 0 {
            if data.len() < 8 {
                self.finish_truncated_header();
                return None;
            }
            let peer_index = u16::from_be_bytes([data[0], data[1]]);
            let originated_time = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
            let attr_len = u16::from_be_bytes([data[6], data[7]]) as usize;
            let end = 8 + attr_len;
            if data.len() < end {
                self.finish_truncated_attrs(attr_len, data.len() - 8);
                return None;
            }
            self.data = &data[end..];
            self.remaining -= 1;
            let Some(peer) = self.peers.get(peer_index as usize) else {
                self.finish_missing_peer(peer_index);
                return None;
            };
            Some(ElemRef::new(
                self.prefix,
                peer,
                originated_time,
                self.flags,
                &data[8..end],
            ))
        } else {
            if data.len() < 12 {
                self.finish_truncated_header();
                return None;
            }
            let peer_index = u16::from_be_bytes([data[0], data[1]]);
            let originated_time = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
            // Bytes 6..10 hold the optional ADD-PATH path_id; BgpElem retains the RIB_AFI prefix.
            let attr_len = u16::from_be_bytes([data[10], data[11]]) as usize;
            let end = 12 + attr_len;
            if data.len() < end {
                self.finish_truncated_attrs(attr_len, data.len() - 12);
                return None;
            }
            self.data = &data[end..];
            self.remaining -= 1;
            let Some(peer) = self.peers.get(peer_index as usize) else {
                self.finish_missing_peer(peer_index);
                return None;
            };
            Some(ElemRef::new(
                self.prefix,
                peer,
                originated_time,
                self.flags,
                &data[12..end],
            ))
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining as usize))
    }
}

/// Borrowed view over a single BGP element inside a [`RecordElems`] batch.
///
/// Attributes are decoded lazily from `attr_bytes` when their accessors are called, without heap
/// allocation.
#[derive(Clone, Debug)]
pub struct ElemRef<'a> {
    attr_bytes: &'a [u8],
    peer: &'a Peer,
    as_path_slot: Cell<u64>,
    originated_time: u32,
    prefix: IpNet,
    flags: u8,
    warned_truncation: Cell<bool>,
}

// Structural invariant: none of the borrowed view types own heap allocations or require Drop.
const _: () = assert!(!std::mem::needs_drop::<ElemRef<'static>>());
const _: () = assert!(!std::mem::needs_drop::<AsPathView<'static>>());
const _: () = assert!(!std::mem::needs_drop::<AsnsView<'static>>());
const _: () = assert!(!std::mem::needs_drop::<CommunitiesView<'static>>());
const _: () = assert!(std::mem::size_of::<ElemRef<'static>>() <= 64);

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
            peer,
            as_path_slot: Cell::new(SLOT_UNSCANNED),
            originated_time,
            prefix,
            flags,
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

    /// Returns the prefix announced by this RIB entry.
    #[inline]
    pub fn prefix(&self) -> NetworkPrefix {
        NetworkPrefix::new(self.prefix, None)
    }

    /// Returns the IP address of the peer that exported this RIB entry.
    #[inline]
    pub fn peer_ip(&self) -> IpAddr {
        self.peer.peer_ip
    }

    /// Returns the AS number of the peer that exported this RIB entry.
    #[inline]
    pub fn peer_asn(&self) -> Asn {
        self.peer.peer_asn
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
                if let Ok(addr) = val.read_address(&afi) {
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
        Some(
            self.scan_u32_attr(u8::from(AttrType::MULTI_EXIT_DISCRIMINATOR))
                .unwrap_or(0),
        )
    }

    /// Returns the Local Preference (`LOCAL_PREFERENCE`), matching
    /// [`BgpElem::local_pref`](crate::BgpElem::local_pref) (`Some(0)` on RIB announcements without
    /// `LOCAL_PREFERENCE`).
    pub fn local_pref(&self) -> Option<u32> {
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

    #[doc = ""]
    #[doc = "Materialise this entry as an owned [`BgpElem`]."]
    pub(crate) fn to_bgp_elem(&self) -> BgpElem {
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

            match AttrType::from(code) {
                AttrType::ORIGIN => {
                    origin = val.first().and_then(|value| Origin::try_from(*value).ok())
                }
                AttrType::AS_PATH => {
                    if validate_as_path_wire(val) {
                        as_path_wire = Some(val);
                    }
                }
                AttrType::AS4_PATH => {
                    if validate_as_path_wire(val) {
                        as4_path_wire = Some(val);
                    }
                }
                AttrType::NEXT_HOP => {
                    let mut value = val;
                    if let Ok(address) = value.read_address(&afi) {
                        next_hop = Some(address);
                    }
                }
                AttrType::MULTI_EXIT_DISCRIMINATOR => {
                    let mut value = val;
                    if let Ok(number) = value.read_u32() {
                        med = Some(number);
                    }
                }
                AttrType::LOCAL_PREFERENCE => {
                    let mut value = val;
                    if let Ok(number) = value.read_u32() {
                        local_pref = Some(number);
                    }
                }
                AttrType::ATOMIC_AGGREGATE => atomic = true,
                AttrType::AGGREGATOR | AttrType::AS4_AGGREGATOR => {
                    aggregator = decode_aggregator_slice(val)
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
                    }
                }
                AttrType::MP_REACHABLE_NLRI => {
                    if let Ok(address) = parse_mp_reach_next_hop(val, afi, safi, is_add_path) {
                        mp_next_hop = address;
                    }
                }
                // Types the element path keeps as raw bytes, mirroring `get_relevant_attributes`.
                AttrType::Unknown(_)
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
                AttrType::EXTENDED_COMMUNITIES => {
                    for chunk in val.as_chunks::<8>().0 {
                        communities
                            .push(MetaCommunity::Extended(decode_extended_community(*chunk)));
                    }
                }
                AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES => {
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
                _ => {}
            }
        }

        BgpElem {
            timestamp: self.timestamp(),
            elem_type: self.elem_type(),
            peer_ip: self.peer.peer_ip,
            peer_asn: self.peer.peer_asn,
            peer_bgp_id: Some(self.peer.peer_bgp_id),
            prefix: self.prefix(),
            next_hop: next_hop.or(mp_next_hop),
            as_path,
            origin,
            origin_asns,
            local_pref: Some(local_pref.unwrap_or(0)),
            med: Some(med.unwrap_or(0)),
            communities: (!communities.is_empty()).then_some(communities),
            atomic,
            aggr_asn: aggregator.map(|value| value.0),
            aggr_ip: aggregator.map(|value| value.1),
            only_to_customer,
            unknown: (!unknown.is_empty()).then_some(unknown),
            deprecated: (!deprecated.is_empty()).then_some(deprecated),
        }
    }

    /// Returns the RIB entry's originated Unix timestamp as seconds (`f64`).
    #[inline]
    pub fn timestamp(&self) -> f64 {
        self.originated_time as f64
    }

    /// Returns [`ElemType::ANNOUNCE`] (all `TABLE_DUMP_V2` RIB entries are announcements).
    #[inline]
    pub fn elem_type(&self) -> ElemType {
        ElemType::ANNOUNCE
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
/// handling both RFC 6396 §4.3.4 abbreviated next-hop payloads and full RFC 4760 payloads.
fn parse_mp_reach_next_hop(
    mut input: &[u8],
    rib_afi: Afi,
    rib_safi: Safi,
    is_add_path: bool,
) -> Result<Option<IpAddr>, ()> {
    let first_byte_zero = input.first().copied() == Some(0);
    let (afi, safi) = if first_byte_zero {
        let afi = input.read_afi().map_err(|_| ())?;
        let safi = input.read_safi().map_err(|_| ())?;
        (afi, safi)
    } else {
        (rib_afi, rib_safi)
    };

    let nh_len = input.read_u8().map_err(|_| ())? as usize;
    if input.len() < nh_len {
        return Err(());
    }
    let nh_bytes = &input[..nh_len];
    input = &input[nh_len..];

    let nh = match nh_len {
        0 => None,
        4 => Some(NextHopAddress::Ipv4(Ipv4Addr::new(
            nh_bytes[0],
            nh_bytes[1],
            nh_bytes[2],
            nh_bytes[3],
        ))),
        16 => {
            let octets: [u8; 16] = nh_bytes.try_into().expect("16 bytes");
            Some(NextHopAddress::Ipv6(Ipv6Addr::from(octets)))
        }
        24 => {
            let octets: [u8; 16] = nh_bytes[8..24].try_into().expect("16 bytes");
            Some(NextHopAddress::Ipv6(Ipv6Addr::from(octets)))
        }
        32 => {
            let a: [u8; 16] = nh_bytes[0..16].try_into().expect("16 bytes");
            let b: [u8; 16] = nh_bytes[16..32].try_into().expect("16 bytes");
            Some(NextHopAddress::Ipv6LinkLocal(
                Ipv6Addr::from(a),
                Ipv6Addr::from(b),
            ))
        }
        48 => {
            let a: [u8; 16] = nh_bytes[8..24].try_into().expect("16 bytes");
            let b: [u8; 16] = nh_bytes[32..48].try_into().expect("16 bytes");
            Some(NextHopAddress::Ipv6LinkLocal(
                Ipv6Addr::from(a),
                Ipv6Addr::from(b),
            ))
        }
        _ => return Err(()),
    };

    if first_byte_zero {
        if afi == Afi::L2vpn
            || safi == Safi::Evpn
            || afi == Afi::LinkState
            || safi == Safi::MplsLabel
        {
            // Full non-IP-unicast/multicast MP_REACH inside RIB_AFI: fall back to the NLRI parser
            // to match exact validation semantics.
            return Err(());
        }
        let reserved = input.read_u8().map_err(|_| ())?;
        if reserved != 0 {
            warn!("NLRI reserved byte not 0 (parsing NLRI prefixes)");
        }
        if !validate_nlri_prefixes(input, is_add_path, &afi) {
            return Err(());
        }
    }

    Ok(nh.map(|n| n.global_addr()))
}

fn validate_nlri_prefixes_exact(mut data: &[u8], add_path: bool, afi: &Afi) -> bool {
    while !data.is_empty() {
        if data.read_nlri_prefix(afi, add_path).is_err() {
            return false;
        }
    }
    true
}

fn validate_nlri_prefixes(data: &[u8], add_path: bool, afi: &Afi) -> bool {
    if add_path {
        return validate_nlri_prefixes_exact(data, true, afi);
    }
    if data.first() == Some(&0) && validate_nlri_prefixes_exact(data, true, afi) {
        return true;
    }
    validate_nlri_prefixes_exact(data, false, afi)
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
