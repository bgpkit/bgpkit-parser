//! One framing path for every MRT consumer.
//!
//! Every reader of an MRT stream needs the same three steps: read the common header, read the
//! declared body, and decide what the record is. This module owns those steps and hands out a
//! [`Frame`] whose body is borrowed from a caller-owned buffer, so no path allocates per record.
//!
//! The body buffer is lent by the consumer rather than owned here: it lets the consumer keep its
//! own buffer alive across records (the high-water trick) and keeps the returned frame borrowing
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
    pub(crate) bytes: Option<Vec<u8>>,
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
    parsed_header: Option<Result<CommonHeader, ParserError>>,
}

impl Framer {
    /// Frame the next record into `body`, borrowing it for the frame's lifetime.
    ///
    /// `body.len()` is treated as the high-water mark across records: a shorter record reuses the
    /// already-initialised prefix and never zeroes the tail.
    #[inline]
    pub(crate) fn next<'a>(
        &mut self,
        input: &mut impl Read,
        body: &'a mut Vec<u8>,
    ) -> Result<Frame<'a>, FrameError> {
        let body_len = self.read_body(input, body)?;
        let header = self.take_header(body)?;
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
    ) -> Result<usize, FrameError> {
        let framed = match frame_common_header_captured(input, &mut self.header) {
            Ok(framed) => framed,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::UnexpectedEof
                    && self.header.as_slice().is_empty()
                {
                    return Err(FrameError {
                        error: ParserError::EofExpected,
                        bytes: None,
                    });
                }
                return Err(FrameError {
                    error: error.into(),
                    bytes: Some(self.header.as_slice().to_vec()),
                });
            }
        };

        self.parsed_header = Some(framed.header);

        if framed.body_length > MAX_MRT_MESSAGE_LEN {
            return Err(FrameError {
                error: ParserError::OversizedRecord {
                    length: framed.body_length,
                },
                bytes: Some(framed.raw_bytes.to_vec()),
            });
        }

        let body_len = framed.body_length as usize;
        // Decompressors return whatever they decoded per call, so reading into a pre-sized slice
        // costs one call per chunk. `read_to_end` into the retained allocation behaves like the
        // owned path on compressed input, and on uncompressed input it measures the same.
        body.clear();
        if let Err(err) = input.take(body_len as u64).read_to_end(body) {
            return Err(FrameError {
                error: ParserError::IoError(err),
                bytes: Some(assemble_error_bytes(self.header.as_slice(), body)),
            });
        }
        if body.len() != body_len {
            let filled = body.len();
            return Err(truncated_body(self.header, body, body_len, filled));
        }

        self.apply_legacy_length_correction(input, body, body_len)
    }

    /// Preserve stream alignment across historical TABLE_DUMP v1 records that under-declared their
    /// body length by 4 bytes.
    fn apply_legacy_length_correction(
        &mut self,
        input: &mut impl Read,
        body: &mut Vec<u8>,
        body_len: usize,
    ) -> Result<usize, FrameError> {
        let Some(Ok(common_header)) = self.parsed_header.as_ref() else {
            return Ok(body_len);
        };
        let common_header = *common_header;
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
                bytes: Some(assemble_error_bytes(
                    self.header.as_slice(),
                    &body[..body_len + read],
                )),
            }),
            Err((err, read)) => Err(FrameError {
                error: ParserError::IoError(err),
                bytes: Some(assemble_error_bytes(
                    self.header.as_slice(),
                    &body[..body_len + read],
                )),
            }),
        }
    }

    fn take_header(&mut self, body: &[u8]) -> Result<CommonHeader, FrameError> {
        match self.parsed_header.take() {
            Some(Ok(header)) => Ok(header),
            Some(Err(error)) => Err(FrameError {
                error,
                bytes: Some(assemble_error_bytes(self.header.as_slice(), body)),
            }),
            None => Err(FrameError {
                error: ParserError::EofExpected,
                bytes: None,
            }),
        }
    }
}

fn truncated_body(header: HeaderBuf, body: &[u8], expected: usize, read: usize) -> FrameError {
    FrameError {
        error: ParserError::IoError(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("truncated MRT body: expected {expected} bytes, read {read}"),
        )),
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

/// The peer named by a BGP4MP record header.
fn bgp4mp_peer(subtype: u16, body: &[u8]) -> Result<(IpAddr, Asn), ParserError> {
    use Bgp4MpType::*;
    let msg_type = Bgp4MpType::try_from(subtype)?;
    let asn_len = match msg_type {
        MessageAs4
        | StateChangeAs4
        | MessageAs4Local
        | MessageAs4Addpath
        | MessageLocalAs4Addpath => AsnLength::Bits32,
        _ => AsnLength::Bits16,
    };
    let mut body = body;
    let peer_asn = body.read_asn(asn_len)?;
    let _local_asn = body.read_asn(asn_len)?;
    let _interface_index = body.read_u16()?;
    let afi = body.read_afi()?;
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
