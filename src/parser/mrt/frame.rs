//! The one framing path for every MRT consumer.
//!
//! Every reader of an MRT stream needs the same steps: read the common header, reject an
//! unreasonable declared length, read the declared body, and repair the historical `TABLE_DUMP`
//! records that under-declared their length by four bytes. This module owns those steps, and this
//! module only. Two consumers sit on it:
//!
//! - [`Framer`], which lends the body from a caller-owned buffer to the borrowed element path and
//!   to the prefiltered record path;
//! - `mrt_record::read_chunk`, which moves the body into an owned `RawMrtRecord` for the record
//!   iterators. It calls [`Framer`] and keeps only the ownership move, so the wire layout, the
//!   size limit and the legacy repair exist once.
//!
//! Both report a broken stream through [`FrameError`], which carries the bytes read so far, the
//! parsed header when there is one, and whether the reader is already past the record. A consumer
//! that recovers by scanning for the next boundary needs that last bit, so framing has to answer
//! it rather than leave each caller to guess.
//!
//! The body buffer is lent by the consumer rather than owned here: it lets the consumer keep its
//! own buffer alive across records and keeps the returned frame borrowing
//! only that buffer, so the consumer can still mutate other state while the frame is live.
//!
//! The peer index table is deliberately *not* part of a [`Frame`]: `PEER_INDEX_TABLE` records
//! replace it mid-stream, so binding it into a frame would either alias that mutation or force a
//! per-record snapshot. Consumers that resolve `peer_index` values take `&[Peer]` explicitly.

use crate::error::ParserError;
use crate::models::{
    Afi, Asn, AsnLength, Bgp4MpType, CommonHeader, EntryType, NetworkPrefix, TableDumpV2Type,
};
use crate::parser::mrt::mrt_header::{frame_common_header_captured, HeaderBuf};
use crate::parser::ReadUtils;
use std::io::Read;
use std::net::IpAddr;

/// Upper bound on the MRT body length the parser will read into memory.
pub(crate) const MAX_MRT_MESSAGE_LEN: u32 = 16 * 1024 * 1024; // 16 MiB

/// A framing failure with the bytes needed to report it.
#[derive(Debug)]
pub(crate) struct FrameError {
    pub(crate) error: ParserError,
    /// The header, when it parsed but the rest of the record did not.
    pub(crate) header: Option<CommonHeader>,
    pub(crate) bytes: Option<Vec<u8>>,
    /// The declared body was read in full, so the reader starts after this record. Only then may a
    /// consumer continue at the next record instead of scanning for a boundary.
    pub(crate) consumed: bool,
}

/// A framed record whose body borrows the consumer's buffer.
pub(crate) struct Frame<'a> {
    pub(crate) header: CommonHeader,
    /// The raw common-header bytes, for error and core-dump reporting.
    pub(crate) raw_header: HeaderBuf,
    pub(crate) body: &'a [u8],
}

/// Reads consecutive MRT common headers, and the body into the consumer's buffer.
#[derive(Default)]
pub(crate) struct Framer {
    header: HeaderBuf,
}

impl Framer {
    /// Frame the next record into `body`, borrowing it for the frame's lifetime.
    ///
    /// The body buffer keeps its allocation across records; each record clears and refills it, so
    /// a stream of same-sized records does not reallocate.
    #[inline]
    pub(crate) fn next<'a>(
        &mut self,
        input: &mut impl Read,
        body: &'a mut Vec<u8>,
    ) -> Result<Frame<'a>, FrameError> {
        let (body_len, parsed_header) = self.read_body(input, body)?;
        let header = take_header(parsed_header, self.header.as_slice(), &body[..body_len])?;
        Ok(Frame {
            header,
            raw_header: self.header,
            body: &body[..body_len],
        })
    }

    /// Read the declared body into `body` and return its length.
    fn read_body(
        &mut self,
        input: &mut impl Read,
        body: &mut Vec<u8>,
    ) -> Result<(usize, Option<Result<CommonHeader, ParserError>>), FrameError> {
        let framed = match frame_common_header_captured(input, &mut self.header) {
            Ok(framed) => framed,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::UnexpectedEof
                    && self.header.as_slice().is_empty()
                {
                    return Err(FrameError {
                        error: ParserError::EofExpected,
                        header: None,
                        bytes: None,
                        consumed: false,
                    });
                }
                return Err(FrameError {
                    error: error.into(),
                    header: None,
                    bytes: Some(self.header.as_slice().to_vec()),
                    consumed: false,
                });
            }
        };

        // Copy the parsed header out before `framed` keeps borrowing the header buffer.
        let parsed_header = framed.header.as_ref().ok().copied();
        let header_outcome = Some(framed.header);

        if framed.body_length > MAX_MRT_MESSAGE_LEN {
            return Err(FrameError {
                error: ParserError::OversizedRecord {
                    length: framed.body_length,
                },
                header: parsed_header,
                bytes: Some(framed.raw_bytes.to_vec()),
                consumed: false,
            });
        }

        let body_len = framed.body_length as usize;
        // Decompressors return whatever they decoded per call, so reading into a pre-sized slice
        // costs one call per chunk. `read_to_end` into the retained allocation behaves like the
        // owned path on compressed input, and on uncompressed input it measures the same.
        body.clear();
        // A caller that hands in a fresh buffer would otherwise grow it from zero on every record;
        // reserving the declared length makes the read a single allocation, and is a no-op for the
        // reusable buffers the iterators keep.
        body.reserve(body_len);
        if let Err(err) = input.take(body_len as u64).read_to_end(body) {
            return Err(FrameError {
                error: ParserError::IoError(err),
                header: parsed_header,
                bytes: Some(assemble_error_bytes(self.header.as_slice(), body)),
                consumed: false,
            });
        }
        if body.len() != body_len {
            let filled = body.len();
            return Err(truncated_body(
                self.header,
                parsed_header,
                body,
                body_len,
                filled,
            ));
        }

        let body_len = self.apply_legacy_length_correction(input, body, body_len, parsed_header)?;
        Ok((body_len, header_outcome))
    }

    /// Preserve stream alignment across historical TABLE_DUMP v1 records that under-declared their
    /// body length by 4 bytes.
    fn apply_legacy_length_correction(
        &mut self,
        input: &mut impl Read,
        body: &mut Vec<u8>,
        body_len: usize,
        parsed_header: Option<CommonHeader>,
    ) -> Result<usize, FrameError> {
        let Some(common_header) = parsed_header else {
            return Ok(body_len);
        };
        if common_header.entry_type != EntryType::TABLE_DUMP
            || !crate::parser::mrt::messages::table_dump::needs_legacy_length_correction(
                common_header.entry_subtype,
                &body[..body_len],
            )
        {
            return Ok(body_len);
        }

        let needed = body_len + 4;
        if body.len() < needed {
            body.resize(needed, 0);
        }
        match read_slice_full(input, &mut body[body_len..needed]) {
            Ok(4) => {
                log::debug!(
                    "recovered historical TABLE_DUMP record whose declared length was four bytes short (timestamp={}, subtype={}, declared_length={})",
                    common_header.timestamp,
                    common_header.entry_subtype,
                    common_header.length
                );
                Ok(needed)
            }
            Ok(read) => Err(FrameError {
                error: ParserError::IoError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated historical TABLE_DUMP length correction",
                )),
                header: Some(common_header),
                consumed: false,
                bytes: Some(assemble_error_bytes(
                    self.header.as_slice(),
                    &body[..body_len + read],
                )),
            }),
            Err((err, read)) => Err(FrameError {
                error: ParserError::IoError(err),
                header: Some(common_header),
                consumed: false,
                bytes: Some(assemble_error_bytes(
                    self.header.as_slice(),
                    &body[..body_len + read],
                )),
            }),
        }
    }
}

/// Turn the header outcome of a framing attempt into the header, or the error to report.
fn take_header(
    parsed: Option<Result<CommonHeader, ParserError>>,
    raw_header: &[u8],
    body: &[u8],
) -> Result<CommonHeader, FrameError> {
    match parsed {
        Some(Ok(header)) => Ok(header),
        // A rejected header's body was read in full, so the reader is past this record.
        Some(Err(error)) => Err(FrameError {
            error,
            header: None,
            bytes: Some(assemble_error_bytes(raw_header, body)),
            consumed: true,
        }),
        None => Err(FrameError {
            error: ParserError::EofExpected,
            header: None,
            bytes: None,
            consumed: false,
        }),
    }
}

fn truncated_body(
    header: HeaderBuf,
    parsed_header: Option<CommonHeader>,
    body: &[u8],
    expected: usize,
    read: usize,
) -> FrameError {
    FrameError {
        error: ParserError::IoError(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("truncated MRT body: expected {expected} bytes, read {read}"),
        )),
        header: parsed_header,
        consumed: false,
        bytes: Some(assemble_error_bytes(
            header.as_slice(),
            &body[..read.min(body.len())],
        )),
    }
}

/// Read up to `buf.len()` bytes, retrying `Interrupted` and preserving the count read on error.
fn read_slice_full(
    input: &mut impl Read,
    buf: &mut [u8],
) -> Result<usize, (std::io::Error, usize)> {
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err((e, filled)),
        }
    }
    Ok(filled)
}

pub(crate) fn assemble_error_bytes(header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + body.len());
    out.extend_from_slice(header);
    out.extend_from_slice(body);
    out
}

/// Address family and RIB flags packed for the borrowed element views.
pub(crate) const FLAG_AFI_IPV6: u8 = 1 << 0;
pub(crate) const FLAG_SAFI_MULTICAST: u8 = 1 << 1;
pub(crate) const FLAG_ADD_PATH: u8 = 1 << 2;

/// AFI and flag byte for a RIB subtype. `None` for non-RIB subtypes.
#[inline]
pub(crate) fn rib_flags(v2_type: TableDumpV2Type) -> Option<(Afi, u8)> {
    match v2_type {
        TableDumpV2Type::RibIpv4Unicast => Some((Afi::Ipv4, 0)),
        TableDumpV2Type::RibIpv4Multicast => Some((Afi::Ipv4, FLAG_SAFI_MULTICAST)),
        TableDumpV2Type::RibIpv6Unicast => Some((Afi::Ipv6, FLAG_AFI_IPV6)),
        TableDumpV2Type::RibIpv6Multicast => Some((Afi::Ipv6, FLAG_AFI_IPV6 | FLAG_SAFI_MULTICAST)),
        TableDumpV2Type::RibIpv4UnicastAddPath => Some((Afi::Ipv4, FLAG_ADD_PATH)),
        TableDumpV2Type::RibIpv4MulticastAddPath => {
            Some((Afi::Ipv4, FLAG_SAFI_MULTICAST | FLAG_ADD_PATH))
        }
        TableDumpV2Type::RibIpv6UnicastAddPath => Some((Afi::Ipv6, FLAG_AFI_IPV6 | FLAG_ADD_PATH)),
        TableDumpV2Type::RibIpv6MulticastAddPath => Some((
            Afi::Ipv6,
            FLAG_AFI_IPV6 | FLAG_SAFI_MULTICAST | FLAG_ADD_PATH,
        )),
        _ => None,
    }
}

/// What a framed record is, with the fields a record-level consumer needs.
///
/// This is the one place that maps an entry type and subtype to those fields. A consumer either
/// uses them or parses the record the general way; nothing here is the only path to an answer.
pub(crate) enum RecordKind {
    /// `TABLE_DUMP_V2` / `PEER_INDEX_TABLE`: replaces the dump's peer table.
    PeerIndex,
    /// `TABLE_DUMP_V2` / `GEO_PEER_TABLE`: validated, then ignored.
    GeoPeer,
    /// `TABLE_DUMP_V2` RIB record: one prefix, and entries that follow the header.
    Rib {
        prefix: NetworkPrefix,
        entry_count: u16,
        flags: u8,
        entries_offset: usize,
    },
    /// `BGP4MP` / `BGP4MP_ET` record: the peer and the time are in the record header.
    Bgp4Mp {
        peer_ip: IpAddr,
        peer_asn: Asn,
        timestamp: f64,
    },
    /// Legacy types, unknown subtypes, and records the general parser must handle.
    Other,
}

/// Classify a framed record.
pub(crate) fn classify(header: &CommonHeader, body: &[u8]) -> RecordKind {
    if header.entry_type == EntryType::TABLE_DUMP_V2 {
        let Ok(v2_type) = TableDumpV2Type::try_from(header.entry_subtype) else {
            return RecordKind::Other;
        };
        if v2_type == TableDumpV2Type::PeerIndexTable {
            return RecordKind::PeerIndex;
        }
        if v2_type == TableDumpV2Type::GeoPeerTable {
            return RecordKind::GeoPeer;
        }
        let Some((afi, flags)) = rib_flags(v2_type) else {
            return RecordKind::Other;
        };
        return match rib_header(body, afi) {
            Ok((prefix, entry_count, header_len)) => RecordKind::Rib {
                prefix,
                entry_count,
                flags,
                entries_offset: header_len,
            },
            Err(_) => RecordKind::Other,
        };
    }

    if matches!(header.entry_type, EntryType::BGP4MP | EntryType::BGP4MP_ET) {
        let timestamp = match header.microsecond_timestamp {
            Some(micro) => header.timestamp as f64 + micro as f64 / 1_000_000.0,
            None => header.timestamp as f64,
        };
        if let Ok((peer_ip, peer_asn)) = bgp4mp_peer(header.entry_subtype, body) {
            return RecordKind::Bgp4Mp {
                peer_ip,
                peer_asn,
                timestamp,
            };
        }
    }
    RecordKind::Other
}

/// Prefix, entry count and header length of a RIB record.
#[inline]
fn rib_header(mut body: &[u8], afi: Afi) -> Result<(NetworkPrefix, u16, usize), ParserError> {
    let total = body.len();
    let _sequence = body.read_u32()?;
    let prefix = body.read_nlri_prefix(&afi, false)?;
    let entry_count = body.read_u16()?;
    Ok((prefix, entry_count, total - body.len()))
}

/// How many bytes one AS number takes in this `BGP4MP` subtype's header.
pub(crate) fn bgp4mp_asn_len(subtype: u16) -> Option<AsnLength> {
    use Bgp4MpType::*;
    Some(match Bgp4MpType::try_from(subtype).ok()? {
        MessageAs4
        | StateChangeAs4
        | MessageAs4Local
        | MessageAs4Addpath
        | MessageLocalAs4Addpath => AsnLength::Bits32,
        Message | MessageLocal | MessageAddpath | MessageLocalAddpath | StateChange => {
            AsnLength::Bits16
        }
    })
}

/// The peer named by a BGP4MP record header.
fn bgp4mp_peer(subtype: u16, body: &[u8]) -> Result<(IpAddr, Asn), ParserError> {
    let asn_len = bgp4mp_asn_len(subtype)
        .ok_or_else(|| ParserError::Unsupported(format!("BGP4MP subtype {subtype}")))?;
    let mut body = body;
    let peer_asn = body.read_asn(asn_len)?;
    let _local_asn = body.read_asn(asn_len)?;
    let _interface_index = body.read_u16()?;
    let afi = body.read_afi()?;
    // Only the unicast and multicast families name an address; other families leave the peer
    // address unread, so the record needs the general parser.
    if !matches!(afi, Afi::Ipv4 | Afi::Ipv6) {
        return Err(ParserError::Unsupported(format!(
            "BGP4MP record with address family {afi:?}"
        )));
    }
    let peer_ip = body.read_address(&afi)?;
    Ok((peer_ip, peer_asn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Bgp4MpEnum, MrtMessage, MrtRecord, TableDumpV2Message};
    use crate::BgpkitParser;
    use std::io::Cursor;

    /// A real TABLE_DUMP_V2 slice: one PEER_INDEX_TABLE and 399 RIB records.
    const RIB_FIXTURE: &str = "tests/fixtures/routeviews/bview.slice.gz";
    const UPDATES_FIXTURE: &str = "tests/fixtures/ripe/rrc15/2010.02/updates.20100227.1600.gz";

    /// All records of a fixture as one byte stream, plus the records the parser produced.
    fn fixture(path: &str) -> (Vec<u8>, Vec<MrtRecord>) {
        let mut bytes = Vec::new();
        for raw in BgpkitParser::new(path)
            .expect("open fixture")
            .into_raw_record_iter()
        {
            bytes.extend_from_slice(&raw.raw_bytes());
        }
        let records = BgpkitParser::new(path)
            .expect("open fixture")
            .into_record_iter()
            .collect();
        (bytes, records)
    }

    /// Every framed record must agree with the record the parser produced for the same position,
    /// and the classification must agree with the record type, so a classifier that always said
    /// `Other` would fail here.
    #[test]
    fn frames_match_parsed_records() {
        for path in [RIB_FIXTURE, UPDATES_FIXTURE] {
            let (bytes, records) = fixture(path);
            let mut framer = Framer::default();
            let mut body = Vec::new();
            let mut input = Cursor::new(bytes);
            let mut checked = 0usize;
            let mut rib_records = 0usize;
            let mut bgp4mp_records = 0usize;

            for expected in records {
                let frame = framer
                    .next(&mut input, &mut body)
                    .unwrap_or_else(|_| panic!("framing failed for {path}"));
                assert_eq!(frame.header, expected.common_header, "{path}");
                let kind = classify(&frame.header, frame.body);

                match (&expected.message, kind) {
                    (
                        MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(message)),
                        RecordKind::Rib {
                            prefix,
                            entry_count,
                            ..
                        },
                    ) => {
                        assert_eq!(prefix, message.prefix, "{path}");
                        assert_eq!(entry_count as usize, message.rib_entries.len(), "{path}");
                        rib_records += 1;
                    }
                    (
                        MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(_)),
                        RecordKind::PeerIndex,
                    ) => {}
                    (
                        MrtMessage::TableDumpV2Message(TableDumpV2Message::GeoPeerTable(_)),
                        RecordKind::GeoPeer,
                    ) => {}
                    (
                        MrtMessage::Bgp4Mp(record),
                        RecordKind::Bgp4Mp {
                            peer_asn, peer_ip, ..
                        },
                    ) => {
                        // Both message and state-change records carry the peer in the header.
                        let (expected_asn, expected_ip) = match record {
                            Bgp4MpEnum::Message(message) => (message.peer_asn, message.peer_ip),
                            Bgp4MpEnum::StateChange(state) => (state.peer_asn, state.peer_ip),
                        };
                        assert_eq!(peer_asn, expected_asn, "{path}");
                        assert_eq!(peer_ip, expected_ip, "{path}");
                        bgp4mp_records += 1;
                    }
                    (_, RecordKind::Other) => {}
                    (_, _) => panic!("{path}: classification does not match the parsed record"),
                }
                checked += 1;
            }
            assert!(checked > 0, "{path} framed no records");
            // Each fixture must exercise the classifier for its record family.
            if path == RIB_FIXTURE {
                assert!(rib_records > 0, "{path}: no RIB record classified");
            } else {
                assert!(bgp4mp_records > 0, "{path}: no BGP4MP record classified");
            }
        }
    }
}

#[cfg(test)]
mod error_parity_tests {
    use super::*;
    use crate::parser::mrt::mrt_record::chunk_mrt_record_with_context;
    use std::io::Cursor;

    fn header(entry_type: u16, subtype: u16, length: u32, extra: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(&1u32.to_be_bytes());
        wire.extend_from_slice(&entry_type.to_be_bytes());
        wire.extend_from_slice(&subtype.to_be_bytes());
        wire.extend_from_slice(&length.to_be_bytes());
        wire.extend_from_slice(extra);
        wire
    }

    /// The owned record path and the borrowing element path must report a broken stream the same
    /// way: same error text, same bytes, and the same answer to "is the reader past this record".
    #[test]
    fn both_paths_report_identical_framing_errors() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("truncated header", vec![0u8; 6]),
            ("empty input", Vec::new()),
            (
                "oversized length",
                header(16, 4, MAX_MRT_MESSAGE_LEN + 1, &[]),
            ),
            ("truncated body", header(16, 4, 10, &[1, 2, 3])),
            ("unknown entry type", header(199, 1, 4, &[0xaa; 4])),
        ];

        for (label, input) in cases {
            let owned =
                chunk_mrt_record_with_context(&mut Cursor::new(input.clone())).expect_err(label);
            let mut body = Vec::new();
            let framed = match Framer::default().next(&mut Cursor::new(input), &mut body) {
                Ok(_) => panic!("{label}: the framed path should fail too"),
                Err(error) => error,
            };

            assert_eq!(
                owned.error.to_string(),
                framed.error.to_string(),
                "{label}: error text"
            );
            assert_eq!(owned.bytes, framed.bytes, "{label}: error bytes");
            assert_eq!(
                owned.record_consumed, framed.consumed,
                "{label}: record consumed"
            );
            assert_eq!(owned.common_header, framed.header, "{label}: parsed header");
        }
    }
}
