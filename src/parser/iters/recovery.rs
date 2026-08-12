//! Opt-in MRT framing recovery.
//!
//! Recovery is deliberately separate from the default iterators. It never attempts to
//! reconstruct a damaged record: bytes are skipped until a conservatively validated chain of
//! records is found, and the skipped range is reported as a [`RecoveryEvent::Gap`].

use crate::models::{Bgp4MpType, EntryType, MrtRecord};
use crate::parser::iters::record_matches_filters;
use crate::parser::mrt::messages::bgp4mp::uses_zebra_compat;
use crate::parser::mrt::mrt_header::parse_common_header_with_bytes;
use crate::parser::mrt::mrt_record::parse_mrt_record_with_zebra_compat;
use crate::parser::{BgpkitParser, Elementor, ParserError, ParserErrorWithBytes, ParserOptions};
use bytes::Bytes;
use std::fmt::{Display, Formatter};
use std::io::{self, Read};

const DEFAULT_MAX_SCAN_BYTES: usize = 1024 * 1024;
const DEFAULT_CONFIRMATION_RECORDS: u8 = 3;
const MAX_RECOVERY_RECORD_LEN: u32 = 65_599;

/// Settings for opt-in MRT framing recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryConfig {
    max_scan_bytes: usize,
    confirmation_records: u8,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
            confirmation_records: DEFAULT_CONFIRMATION_RECORDS,
        }
    }
}

impl RecoveryConfig {
    /// Set the maximum number of bytes searched after a damaged record.
    pub const fn with_max_scan_bytes(mut self, max_scan_bytes: usize) -> Self {
        self.max_scan_bytes = max_scan_bytes;
        self
    }

    /// Set the number of consecutive records required to confirm a recovered boundary.
    ///
    /// A value of zero is treated as one.
    pub const fn with_confirmation_records(mut self, confirmation_records: u8) -> Self {
        self.confirmation_records = confirmation_records;
        self
    }

    pub const fn max_scan_bytes(&self) -> usize {
        self.max_scan_bytes
    }

    pub const fn confirmation_records(&self) -> u8 {
        self.confirmation_records
    }
}

/// Evidence used to validate the first record following a recovered gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum RecoveryEvidence {
    /// A deprecated MRT Type-5 record and its confirmation chain parsed structurally.
    LegacyMrtChain,
    /// A BGP4MP message contained an exact embedded BGP marker and length.
    BgpMarkerChain,
    /// A BGP4MP state-change record, which has no embedded BGP message header.
    Bgp4MpStateChangeChain,
}

/// A byte range discarded while restoring MRT record framing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecoveryGap {
    /// Inclusive offset in the decompressed MRT byte stream.
    pub start_offset: u64,
    /// Exclusive offset in the decompressed MRT byte stream.
    pub end_offset: u64,
    /// Error raised while parsing at `start_offset`.
    pub cause: String,
    /// Structural evidence used to accept `end_offset` as a new boundary.
    pub evidence: RecoveryEvidence,
    /// Number of consecutive records validated at the recovered boundary.
    pub confirmed_records: u8,
}

impl RecoveryGap {
    pub const fn skipped_bytes(&self) -> u64 {
        self.end_offset - self.start_offset
    }
}

/// An item produced by a recovering iterator.
#[derive(Debug)]
pub enum RecoveryEvent<T> {
    Item(T),
    Gap(RecoveryGap),
}

/// A framing error for which no sufficiently strong recovery boundary was found.
#[derive(Debug)]
pub struct RecoveryError {
    pub offset: u64,
    pub scanned_bytes: u64,
    pub error: ParserErrorWithBytes,
}

impl Display for RecoveryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MRT recovery failed at decompressed offset {} after scanning {} bytes: {}",
            self.offset, self.scanned_bytes, self.error
        )
    }
}

impl std::error::Error for RecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Iterator over parsed MRT records and explicit recovery gaps.
pub struct RecoveringRecordIterator<R> {
    reader: ReplayReader<R>,
    config: RecoveryConfig,
    filters: Vec<crate::parser::Filter>,
    elementor: Elementor,
    options: ParserOptions,
    finished: bool,
}

impl<R> RecoveringRecordIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>, config: RecoveryConfig) -> Self {
        Self {
            reader: ReplayReader::new(parser.reader),
            config,
            filters: parser.filters,
            elementor: Elementor::new(),
            options: parser.options,
            finished: false,
        }
    }
}

impl<R: Read> Iterator for RecoveringRecordIterator<R> {
    type Item = Result<RecoveryEvent<MrtRecord>, RecoveryError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        loop {
            let record_start = self.reader.position();
            match parse_mrt_record_with_zebra_compat(&mut self.reader) {
                Ok((record, used_zebra_compat)) => {
                    self.reader.discard_before_current();
                    if used_zebra_compat {
                        self.options.warn_zebra_compat_once();
                    }

                    if record_matches_filters(&record, &self.filters, &mut self.elementor) {
                        return Some(Ok(RecoveryEvent::Item(record)));
                    }
                }
                Err(error) if matches!(error.error, ParserError::EofExpected) => {
                    self.finished = true;
                    return None;
                }
                Err(error) if is_non_eof_io_error(&error.error) => {
                    self.finished = true;
                    return Some(Err(RecoveryError {
                        offset: record_start,
                        scanned_bytes: 0,
                        error,
                    }));
                }
                Err(error) => match self.find_recovery(record_start, &error) {
                    Ok(Some((end_offset, evidence, confirmed_records))) => {
                        let gap = RecoveryGap {
                            start_offset: record_start,
                            end_offset,
                            cause: error.to_string(),
                            evidence,
                            confirmed_records,
                        };
                        match self.reader.move_to(end_offset) {
                            Ok(true) => {
                                self.reader.discard_before_current();
                                return Some(Ok(RecoveryEvent::Gap(gap)));
                            }
                            Ok(false) => {
                                self.finished = true;
                                return Some(Err(RecoveryError {
                                    offset: record_start,
                                    scanned_bytes: end_offset.saturating_sub(record_start),
                                    error,
                                }));
                            }
                            Err(io_error) => {
                                self.finished = true;
                                return Some(Err(RecoveryError {
                                    offset: record_start,
                                    scanned_bytes: end_offset.saturating_sub(record_start),
                                    error: ParserErrorWithBytes::from(ParserError::IoError(
                                        io_error,
                                    )),
                                }));
                            }
                        }
                    }
                    Ok(None) => {
                        self.finished = true;
                        return Some(Err(RecoveryError {
                            offset: record_start,
                            scanned_bytes: self
                                .reader
                                .buffered_end()
                                .saturating_sub(record_start)
                                .min(self.config.max_scan_bytes as u64),
                            error,
                        }));
                    }
                    Err(io_error) => {
                        self.finished = true;
                        return Some(Err(RecoveryError {
                            offset: record_start,
                            scanned_bytes: self.reader.position().saturating_sub(record_start),
                            error: ParserErrorWithBytes::from(ParserError::IoError(io_error)),
                        }));
                    }
                },
            }
        }
    }
}

impl<R: Read> RecoveringRecordIterator<R> {
    fn find_recovery(
        &mut self,
        failed_start: u64,
        _error: &ParserErrorWithBytes,
    ) -> io::Result<Option<(u64, RecoveryEvidence, u8)>> {
        let confirmations = self.config.confirmation_records.max(1);
        for distance in 1..=self.config.max_scan_bytes {
            let candidate_offset = failed_start + distance as u64;
            if !self.reader.move_to(candidate_offset)? {
                return Ok(None);
            }
            if let Some((evidence, confirmed)) =
                validate_chain(&mut self.reader, candidate_offset, confirmations)?
            {
                return Ok(Some((candidate_offset, evidence, confirmed)));
            }
        }
        Ok(None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamFamily {
    Legacy,
    Bgp4Mp,
}

struct Candidate {
    family: StreamFamily,
    evidence: RecoveryEvidence,
}

fn validate_chain<R: Read>(
    reader: &mut ReplayReader<R>,
    offset: u64,
    required: u8,
) -> io::Result<Option<(RecoveryEvidence, u8)>> {
    if !reader.move_to(offset)? {
        return Ok(None);
    }
    let mut family = None;
    let mut evidence = None;
    let mut confirmed = 0u8;

    while confirmed < required {
        let record_start = reader.position();
        let Some(candidate) = read_candidate(reader)? else {
            reader.move_to(record_start)?;
            if confirmed > 0 && reader.at_clean_eof()? {
                return Ok(evidence.map(|evidence| (evidence, confirmed)));
            }
            return Ok(None);
        };
        if family.is_some_and(|expected| expected != candidate.family) {
            return Ok(None);
        }
        family.get_or_insert(candidate.family);
        evidence.get_or_insert(candidate.evidence);
        confirmed += 1;

        if confirmed < required && reader.at_clean_eof()? {
            return Ok(evidence.map(|evidence| (evidence, confirmed)));
        }
    }

    Ok(evidence.map(|evidence| (evidence, confirmed)))
}

fn read_candidate<R: Read>(reader: &mut ReplayReader<R>) -> io::Result<Option<Candidate>> {
    let parsed_header = match parse_common_header_with_bytes(reader) {
        Ok(header) => header,
        Err(error) => return parser_error_as_candidate(error),
    };
    let header = parsed_header.header;

    let family = match header.entry_type {
        EntryType::BGP if legacy_header_is_plausible(header.entry_subtype, header.length) => {
            StreamFamily::Legacy
        }
        EntryType::BGP4MP | EntryType::BGP4MP_ET
            if Bgp4MpType::try_from(header.entry_subtype).is_ok()
                && header.length <= MAX_RECOVERY_RECORD_LEN =>
        {
            StreamFamily::Bgp4Mp
        }
        _ => return Ok(None),
    };

    if header
        .microsecond_timestamp
        .is_some_and(|value| value >= 1_000_000)
    {
        return Ok(None);
    }

    let mut body = vec![0u8; header.length as usize];
    if let Err(error) = reader.read_exact(&mut body) {
        return if error.kind() == io::ErrorKind::UnexpectedEof {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let raw_record = crate::RawMrtRecord {
        common_header: header,
        header_bytes: parsed_header.raw_bytes,
        message_bytes: Bytes::from(body),
    };

    let evidence = match family {
        StreamFamily::Legacy => raw_record
            .clone()
            .parse()
            .ok()
            .map(|_| RecoveryEvidence::LegacyMrtChain),
        StreamFamily::Bgp4Mp => strict_bgp4mp_evidence(&raw_record),
    };
    Ok(evidence.map(|evidence| Candidate { family, evidence }))
}

fn parser_error_as_candidate(error: ParserError) -> io::Result<Option<Candidate>> {
    match error {
        ParserError::IoError(error) | ParserError::EofError(error)
            if error.kind() != io::ErrorKind::UnexpectedEof =>
        {
            Err(error)
        }
        _ => Ok(None),
    }
}

fn legacy_header_is_plausible(subtype: u16, length: u32) -> bool {
    match subtype {
        1 => (16..=65_535).contains(&length),
        3 => length == 10,
        5 => (22..=4_089).contains(&length),
        6 => (14..=65_535).contains(&length),
        7 => length == 12,
        _ => false,
    }
}

fn strict_bgp4mp_evidence(raw_record: &crate::RawMrtRecord) -> Option<RecoveryEvidence> {
    let msg_type = Bgp4MpType::try_from(raw_record.common_header.entry_subtype).ok()?;
    if matches!(
        msg_type,
        Bgp4MpType::StateChange | Bgp4MpType::StateChangeAs4
    ) {
        let body = &raw_record.message_bytes;
        if uses_zebra_compat(raw_record.common_header.entry_subtype, body) {
            if body.len() != 8 {
                return None;
            }
        } else {
            let asn_pair_len = if matches!(msg_type, Bgp4MpType::StateChange) {
                4
            } else {
                8
            };
            let afi_offset = asn_pair_len + 2;
            let afi = u16::from_be_bytes(body.get(afi_offset..afi_offset + 2)?.try_into().ok()?);
            let address_len = match afi {
                1 => 4,
                2 => 16,
                _ => return None,
            };
            if body.len() != asn_pair_len + 4 + address_len * 2 + 4 {
                return None;
            }
        }
        raw_record.clone().parse().ok()?;
        return Some(RecoveryEvidence::Bgp4MpStateChangeChain);
    }

    let body = &raw_record.message_bytes;
    let asn_pair_len = match msg_type {
        Bgp4MpType::Message
        | Bgp4MpType::MessageLocal
        | Bgp4MpType::MessageAddpath
        | Bgp4MpType::MessageLocalAddpath => 4,
        Bgp4MpType::MessageAs4
        | Bgp4MpType::MessageAs4Local
        | Bgp4MpType::MessageAs4Addpath
        | Bgp4MpType::MessageLocalAs4Addpath => 8,
        Bgp4MpType::StateChange | Bgp4MpType::StateChangeAs4 => return None,
    };

    let marker_offset = if uses_zebra_compat(raw_record.common_header.entry_subtype, body) {
        asn_pair_len
    } else {
        let afi_offset = asn_pair_len + 2;
        let afi = u16::from_be_bytes(body.get(afi_offset..afi_offset + 2)?.try_into().ok()?);
        let address_len = match afi {
            1 => 4,
            2 => 16,
            _ => return None,
        };
        asn_pair_len + 4 + address_len * 2
    };

    let bgp_header = body.get(marker_offset..marker_offset + 19)?;
    if bgp_header[..16] != [0xff; 16] {
        return None;
    }
    let bgp_length = u16::from_be_bytes([bgp_header[16], bgp_header[17]]) as usize;
    let bgp_type = bgp_header[18];
    if !(19..=65_535).contains(&bgp_length)
        || !(1..=4).contains(&bgp_type)
        || marker_offset + bgp_length != body.len()
    {
        return None;
    }
    match bgp_type {
        1 if bgp_length > 4_096 => return None,
        2 if bgp_length < 23 => return None,
        3 if bgp_length < 21 => return None,
        4 if bgp_length != 19 => return None,
        _ => {}
    }

    raw_record.clone().parse().ok()?;
    Some(RecoveryEvidence::BgpMarkerChain)
}

fn is_non_eof_io_error(error: &ParserError) -> bool {
    matches!(
        error,
        ParserError::IoError(error) | ParserError::EofError(error)
            if error.kind() != io::ErrorKind::UnexpectedEof
    )
}

struct ReplayReader<R> {
    inner: R,
    data: Vec<u8>,
    start: usize,
    cursor: usize,
    base_offset: u64,
}

impl<R> ReplayReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            data: Vec::new(),
            start: 0,
            cursor: 0,
            base_offset: 0,
        }
    }

    fn position(&self) -> u64 {
        self.base_offset + (self.cursor - self.start) as u64
    }

    fn buffered_end(&self) -> u64 {
        self.base_offset + (self.data.len() - self.start) as u64
    }

    fn discard_before_current(&mut self) {
        self.base_offset = self.position();
        self.start = self.cursor;
        if self.start >= 64 * 1024 && self.start * 2 >= self.data.len() {
            self.data.drain(..self.start);
            self.cursor -= self.start;
            self.start = 0;
        }
    }
}

impl<R: Read> ReplayReader<R> {
    fn move_to(&mut self, offset: u64) -> io::Result<bool> {
        if offset < self.base_offset {
            return Ok(false);
        }
        while offset > self.buffered_end() {
            self.cursor = self.data.len();
            let remaining = (offset - self.buffered_end()).min(8_192) as usize;
            let mut scratch = vec![0u8; remaining];
            let read = self.read(&mut scratch)?;
            if read == 0 {
                return Ok(false);
            }
        }
        self.cursor = self.start + (offset - self.base_offset) as usize;
        Ok(true)
    }

    fn at_clean_eof(&mut self) -> io::Result<bool> {
        let position = self.position();
        let mut byte = [0u8; 1];
        let read = self.read(&mut byte)?;
        self.move_to(position)?;
        Ok(read == 0)
    }
}

impl<R: Read> Read for ReplayReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.cursor < self.data.len() {
            let count = output.len().min(self.data.len() - self.cursor);
            output[..count].copy_from_slice(&self.data[self.cursor..self.cursor + count]);
            self.cursor += count;
            return Ok(count);
        }

        let read = self.inner.read(output)?;
        self.data.extend_from_slice(&output[..read]);
        self.cursor += read;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Asn, Bgp4MpEnum, Bgp4MpMessage, BgpMessage, CommonHeader, MrtMessage};
    use bytes::{BufMut, BytesMut};
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};

    fn legacy_state(timestamp: u32) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_u32(timestamp);
        bytes.put_u16(EntryType::BGP as u16);
        bytes.put_u16(3);
        bytes.put_u32(10);
        bytes.put_u16(64512);
        bytes.put_slice(&[192, 0, 2, 1]);
        bytes.put_u16(1);
        bytes.put_u16(2);
        bytes.to_vec()
    }

    fn bgp4mp_keepalive(timestamp: u32) -> Vec<u8> {
        MrtRecord {
            common_header: CommonHeader {
                timestamp,
                microsecond_timestamp: None,
                entry_type: EntryType::BGP4MP,
                entry_subtype: Bgp4MpType::Message as u16,
                length: 0,
            },
            message: MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(Bgp4MpMessage {
                msg_type: Bgp4MpType::Message,
                peer_asn: Asn::new_16bit(64_496),
                local_asn: Asn::new_16bit(64_497),
                interface_index: 0,
                peer_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                bgp_message: BgpMessage::KeepAlive,
            })),
        }
        .encode()
        .unwrap()
        .to_vec()
    }

    #[test]
    fn recovers_at_three_record_legacy_chain() {
        let first = legacy_state(100);
        let mut input = first.clone();
        input.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x01]);
        input.extend_from_slice(&legacy_state(101));
        input.extend_from_slice(&legacy_state(102));
        input.extend_from_slice(&legacy_state(103));

        let parser = BgpkitParser::from_reader(Cursor::new(input));
        let events = parser
            .into_recovering_record_iter(RecoveryConfig::default())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(events.len(), 5);
        assert!(matches!(events[0], RecoveryEvent::Item(_)));
        let RecoveryEvent::Gap(gap) = &events[1] else {
            panic!("expected recovery gap")
        };
        assert_eq!(gap.start_offset, first.len() as u64);
        assert_eq!(gap.end_offset, first.len() as u64 + 5);
        assert_eq!(gap.confirmed_records, 3);
        assert_eq!(gap.evidence, RecoveryEvidence::LegacyMrtChain);
        assert!(events[2..]
            .iter()
            .all(|event| matches!(event, RecoveryEvent::Item(_))));
    }

    #[test]
    fn rejects_chain_shorter_than_configured_before_non_eof_garbage() {
        let mut input = vec![0xff; 12];
        input.extend_from_slice(&legacy_state(101));
        input.extend_from_slice(&legacy_state(102));
        input.extend_from_slice(&[1, 2, 3]);

        let parser = BgpkitParser::from_reader(Cursor::new(input));
        let result = parser
            .into_recovering_record_iter(RecoveryConfig::default())
            .next()
            .expect("one error");
        assert!(result.is_err());
    }

    #[test]
    fn accepts_short_confirmation_chain_at_clean_eof() {
        let mut input = vec![0xff; 12];
        input.extend_from_slice(&legacy_state(101));
        input.extend_from_slice(&legacy_state(102));

        let parser = BgpkitParser::from_reader(Cursor::new(input));
        let events = parser
            .into_recovering_record_iter(RecoveryConfig::default())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let RecoveryEvent::Gap(gap) = &events[0] else {
            panic!("expected gap")
        };
        assert_eq!(gap.confirmed_records, 2);
    }

    #[test]
    fn recovers_bgp4mp_using_exact_embedded_bgp_headers() {
        let first = bgp4mp_keepalive(100);
        let mut input = first.clone();
        input.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        input.extend_from_slice(&bgp4mp_keepalive(101));
        input.extend_from_slice(&bgp4mp_keepalive(102));
        input.extend_from_slice(&bgp4mp_keepalive(103));

        let parser = BgpkitParser::from_reader(Cursor::new(input));
        let events = parser
            .into_recovering_record_iter(RecoveryConfig::default())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let RecoveryEvent::Gap(gap) = &events[1] else {
            panic!("expected recovery gap")
        };
        assert_eq!(gap.start_offset, first.len() as u64);
        assert_eq!(gap.end_offset, first.len() as u64 + 4);
        assert_eq!(gap.evidence, RecoveryEvidence::BgpMarkerChain);
        assert_eq!(gap.confirmed_records, 3);
    }

    #[test]
    fn rejects_bgp4mp_candidate_with_inexact_embedded_length() {
        let encoded = bgp4mp_keepalive(100);
        let header = CommonHeader {
            timestamp: 100,
            microsecond_timestamp: None,
            entry_type: EntryType::BGP4MP,
            entry_subtype: Bgp4MpType::Message as u16,
            length: (encoded.len() - 12) as u32,
        };
        let mut body = encoded[12..].to_vec();
        // 16-bit ASN/IPv4 BGP4MP envelope is 16 bytes; corrupt the BGP length field.
        body[32..34].copy_from_slice(&20u16.to_be_bytes());
        let raw = crate::RawMrtRecord {
            common_header: header,
            header_bytes: Bytes::copy_from_slice(&encoded[..12]),
            message_bytes: Bytes::from(body),
        };
        assert!(strict_bgp4mp_evidence(&raw).is_none());
    }
}
