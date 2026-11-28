#![forbid(unsafe_code)]
/*!
Borrowed element views over the records this path serves: `TABLE_DUMP_V2` `RIB_AFI` entries and
`BGP4MP_AS4` updates.

[`BgpkitParser::next_record_elems`](crate::BgpkitParser::next_record_elems) reads one record body
into a reusable buffer owned by the parser and lends a [`RecordElems`] batch over its RIB entries.
Each [`ElemRef`] yielded by [`RecordElems::iter`] borrows directly from the record body and the
active peer index table. Its accessors decode on demand. An update's next hop is decoded once for
the whole record; a dump entry's `MP_REACH_NLRI` next hop is decoded per call and allocates, and
materialising an element allocates its AS path and communities.
*/

mod element;
mod update;
mod view;

pub use element::ElemRef;
pub use view::*;

use update::{attribute_block_walks, parse_peer_index_vec, update_record_elems};
use view::mp_reach_next_hop;

use crate::error::ParserError;
use crate::models::{
    get_deprecated_attr_type, Afi, AsPath, AsPathSegment, Asn, AsnLength, AttrFlags, AttrRaw,
    AttrType, Bgp4MpType, BgpIdentifier, CommonHeader, Community, ElemType, ExtendedCommunity,
    Ipv6AddrExtCommunity, LargeCommunity, MetaCommunity, NetworkPrefix, Origin, Peer, Safi,
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
use std::net::IpAddr;
use zerocopy::big_endian::U32 as BeU32;
use zerocopy::FromBytes;

const AS_PATH_AS_SET: u8 = 1;
const AS_PATH_AS_SEQUENCE: u8 = 2;
const AS_PATH_CONFED_SEQUENCE: u8 = 3;
const AS_PATH_CONFED_SET: u8 = 4;

use crate::parser::mrt::frame::{FLAG_ADD_PATH, FLAG_AFI_IPV6, FLAG_SAFI_MULTICAST};
/// Set for an element of a `BGP4MP` update. A dump's entry decodes `NEXT_HOP` with the record's
/// family; an update's `NEXT_HOP` is always the IPv4 address RFC 4271 defines.
const FLAG_UPDATE: u8 = 1 << 3;

// One `u8` carries the frame bits and the update bit, so they must not overlap.
const _: () = assert!(FLAG_UPDATE & (FLAG_AFI_IPV6 | FLAG_SAFI_MULTICAST | FLAG_ADD_PATH) == 0);

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

/// Whether a `GEO_PEER_TABLE` body decodes, decided by the owned parser so the RFC 6397 layout has
/// one owner.
fn validate_geo_peer_table(data: &[u8]) -> Result<(), ParserError> {
    crate::parser::mrt::messages::table_dump_v2::geo_peer_table::parse_geo_peer_table(
        &mut bytes::Bytes::copy_from_slice(data),
    )
    .map(|_| ())
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
                        return NextBatch::End;
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
                // Support is decided from the header, not by decoding the record: the walk itself
                // runs once, in `update_record_elems`, for the record this loop returns.
                let subtype = common_header.entry_subtype;
                let would_yield =
                    bgp4mp_is_update(subtype, &parser.elem_view_state.body_buf[..body_len]);
                let supported = would_yield
                    && matches!(
                        Bgp4MpType::try_from(subtype),
                        Ok(Bgp4MpType::MessageAs4)
                            | Ok(Bgp4MpType::MessageAs4Local)
                            | Ok(Bgp4MpType::MessageAs4Addpath)
                            | Ok(Bgp4MpType::MessageLocalAs4Addpath)
                    );
                if !supported {
                    // A record the view cannot read is either a parse error or a record kind it
                    // does not serve. The owned parser answers which: its error goes through the
                    // same handler, and only a record it parses cleanly is a scope limit.
                    let as4 = matches!(
                        Bgp4MpType::try_from(common_header.entry_subtype),
                        Ok(Bgp4MpType::MessageAs4)
                            | Ok(Bgp4MpType::MessageAs4Local)
                            | Ok(Bgp4MpType::MessageAs4Addpath)
                            | Ok(Bgp4MpType::MessageLocalAs4Addpath)
                    );
                    match parser.parse_framed_record(common_header, raw_header.as_slice(), body_len)
                    {
                        Ok(_) if as4 && would_yield => {
                            // The owned path parses it, so the failure is in this walk; say so
                            // rather than drop the record in silence.
                            error!(
                                "next_record_elems could not read a BGP4MP update the parser accepts; use into_elem_iter for this file"
                            );
                        }
                        Ok(_) if !as4 && would_yield => parser
                            .options
                            .warn_view_scope_once("BGP4MP record with 2-byte AS numbers"),
                        Ok(_) => {}
                        Err(failure) => {
                            if !handle_record_parse_error(parser, failure.error, failure.bytes) {
                                parser.elem_view_state.finished = true;
                                return None;
                            }
                        }
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
                match parser.parse_framed_record(common_header, raw_header.as_slice(), body_len) {
                    Ok(_) => parser.options.warn_view_scope_once("other"),
                    Err(failure) => {
                        if !handle_record_parse_error(parser, failure.error, failure.bytes) {
                            parser.elem_view_state.finished = true;
                            return None;
                        }
                    }
                }
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
        } => {
            let record = update_record_elems(
                &mut parser.elem_view_state,
                body_len,
                header,
                peer_ip,
                peer_asn,
                timestamp,
            );
            if record.is_none() {
                // The header said this record yields elements but the walk could not read it, so it
                // is reported once instead of dropped in silence.
                error!(
                    "next_record_elems could not read a BGP4MP update the parser accepts; use into_elem_iter for this file"
                );
            }
            record
        }
    }
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
    /// `BGP4MP` update: one attribute block, the NLRI this record announced or withdrew, and the
    /// next hop every element of it shares.
    Update {
        entries: &'a [UpdateEntry],
        attrs: &'a [u8],
        next_hop: Option<IpAddr>,
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
        next_hop: Option<IpAddr>,
    ) -> Self {
        RecordElems {
            header,
            source: RecordSource::Update {
                entries,
                attrs,
                peer_ip,
                peer_asn,
                timestamp,
                next_hop,
            },
        }
    }

    /// Returns the MRT [`CommonHeader`] of this record.
    #[inline]
    pub fn header(&self) -> &CommonHeader {
        &self.header
    }

    /// The number of entries the record declares: the RIB entry count, or the number of NLRI this
    /// update announced and withdrew.
    ///
    /// This is what the header says, not a promise about how many elements the iterator yields: an
    /// entry naming a peer outside the table, or one the record cannot decode, produces fewer.
    /// Never size a buffer from it without a ceiling, since the count comes from the input.
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
    pub fn iter(&self) -> ElemRefIter<'a> {
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
                next_hop,
            } => IterSource::Update {
                entries,
                attrs,
                peer_ip: *peer_ip,
                peer_asn: *peer_asn,
                timestamp: *timestamp,
                next: 0,
                next_hop: *next_hop,
            },
        };
        ElemRefIter { source }
    }
}

impl<'a> IntoIterator for &RecordElems<'a> {
    type Item = ElemRef<'a>;
    type IntoIter = ElemRefIter<'a>;

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
        next_hop: Option<IpAddr>,
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
                next_hop,
            } => {
                let entry = entries.get(*next)?;
                *next += 1;
                // A withdrawal carries no attributes, exactly as the owned path leaves them unset.
                let attr_bytes: &[u8] = match entry.elem_type {
                    ElemType::ANNOUNCE => attrs,
                    ElemType::WITHDRAW => &[],
                };
                Some(ElemRef::new_update(
                    entry, *peer_ip, *peer_asn, *timestamp, attr_bytes, *next_hop,
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

/// Whether a 4-byte-ASN `AS_PATH` / `AS4_PATH` attribute payload is well formed.
///
/// The owned segment parser decides this: a segment type it rejects, or a count that runs past the
/// payload, fails there exactly as it must here.
fn validate_as_path_wire(wire: &[u8]) -> bool {
    crate::parser::bgp::attributes::validate_as_path_slice(wire, &AsnLength::Bits32)
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
        // NO_EXPORT, written out because the wire value belongs to the attribute module.
        assert_eq!(words[1].get(), 0xFFFF_FF01);

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
        while let Some(record) = parser.next_record_elems() {
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
        while let Some(record) = parser.next_record_elems() {
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
        while let Some(record) = parser.next_record_elems() {
            for elem in &record {
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
        while let Some(record) = parser.next_record_elems() {
            for elem in &record {
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
