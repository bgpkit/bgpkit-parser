//! Opt-in MRT framing recovery.
//!
//! Recovery is deliberately separate from the default iterators. It never attempts to
//! reconstruct a damaged record: bytes are skipped until a conservatively validated chain of
//! records is found, and the skipped range is reported as a [`RecoveryEvent::Gap`].
//!
//! Damage is classified before scanning. When a record frames correctly — its header and
//! declared length were consumed exactly — but its body fails to parse, and intact records
//! (or a clean end of stream) follow at the declared boundary, exactly that record is
//! skipped without scanning. Damage that extends to the end of the stream is reported as a
//! terminal gap rather than an error, so trailing truncation — the most common real-world
//! corruption — still yields every intact record plus an explicit account of the discarded
//! tail. A [`RecoveryError`] is reserved for I/O failures, unsupported input, and scan
//! windows exhausted without finding a boundary mid-stream.
//!
//! The undamaged fast path reads straight from the underlying reader; bytes are only
//! buffered while a recovery scan is in progress.

use crate::models::{Bgp4MpType, BgpElem, EntryType, MrtRecord};
use crate::parser::iters::{record_matches_filters, write_mrt_core_dump};
use crate::parser::mrt::messages::bgp4mp::uses_zebra_compat;
use crate::parser::mrt::mrt_header::parse_common_header_with_bytes;
use crate::parser::mrt::mrt_record::{
    chunk_mrt_record, parse_mrt_record_with_zebra_compat, raw_record_uses_zebra_compat,
};
use crate::parser::{
    BgpkitParser, Elementor, Filter, ParserError, ParserErrorWithBytes, ParserOptions,
};
use crate::Filterable;
use bytes::Bytes;
use std::fmt::{Display, Formatter};
use std::io::{self, Read};

const DEFAULT_MAX_SCAN_BYTES: usize = 1024 * 1024;
const DEFAULT_CONFIRMATION_RECORDS: u8 = 3;
const MAX_RECOVERY_RECORD_LEN: u32 = 65_599;
const SCAN_FILL_CHUNK: usize = 8_192;

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
    /// The damaged record's framing was intact: complete MRT records of any type (or a
    /// clean end of stream) followed at its declared end offset, so exactly that record
    /// was skipped without scanning.
    AlignedRecordChain,
    /// No boundary was validated before the stream ended; the gap extends to the end of
    /// the input.
    EndOfStream,
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
    /// Number of consecutive records validated at the recovered boundary. Zero when the
    /// gap ends at the end of the stream.
    pub confirmed_records: u8,
}

impl RecoveryGap {
    /// Return the number of skipped bytes, or zero for an invalid inverted range.
    pub const fn skipped_bytes(&self) -> u64 {
        self.end_offset.saturating_sub(self.start_offset)
    }
}

/// An item produced by a recovering iterator.
#[derive(Debug)]
pub enum RecoveryEvent<T> {
    Item(T),
    Gap(RecoveryGap),
}

/// A framing error for which no recovery boundary was found within the scan window, an
/// I/O failure, or unsupported input.
///
/// Damage that extends to the end of the stream is reported as a terminal
/// [`RecoveryEvent::Gap`] instead of this error.
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
    reader: CarryoverReader<R>,
    config: RecoveryConfig,
    filters: Vec<Filter>,
    elementor: Elementor,
    options: ParserOptions,
    core_dump: bool,
    unsupported_input: Option<String>,
    finished: bool,
}

impl<R> RecoveringRecordIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>, config: RecoveryConfig) -> Self {
        let unsupported_input = parser.text_dump_iter.is_some().then(|| {
            "text-dump parsers have no MRT record representation; iterate elements instead"
                .to_string()
        });
        Self {
            reader: CarryoverReader::new(parser.reader),
            config,
            filters: parser.filters,
            elementor: Elementor::new(),
            options: parser.options,
            core_dump: parser.core_dump,
            unsupported_input,
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
        if let Some(message) = self.unsupported_input.take() {
            self.finished = true;
            return Some(Err(RecoveryError {
                offset: 0,
                scanned_bytes: 0,
                error: ParserErrorWithBytes::from(ParserError::Unsupported(message)),
            }));
        }

        loop {
            let record_start = self.reader.position();
            let raw_record = match chunk_mrt_record(&mut self.reader) {
                Ok(raw_record) => raw_record,
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
                Err(error) => return self.recover(record_start, None, error),
            };

            let used_zebra_compat = raw_record_uses_zebra_compat(&raw_record);
            match raw_record.clone().parse() {
                Ok(record) => {
                    if used_zebra_compat {
                        self.options.warn_zebra_compat_once();
                    }
                    if record_matches_filters(&record, &self.filters, &mut self.elementor) {
                        return Some(Ok(RecoveryEvent::Item(record)));
                    }
                }
                Err(error) => {
                    // The header and declared length were consumed exactly, so the
                    // stream may still be aligned even though the body is unparsable.
                    let framed_end = self.reader.position();
                    let error = ParserErrorWithBytes {
                        error,
                        bytes: Some(raw_record.raw_bytes().to_vec()),
                    };
                    return self.recover(record_start, Some(framed_end), error);
                }
            }
        }
    }
}

impl<R: Read> RecoveringRecordIterator<R> {
    fn recover(
        &mut self,
        record_start: u64,
        framed_end: Option<u64>,
        error: ParserErrorWithBytes,
    ) -> Option<Result<RecoveryEvent<MrtRecord>, RecoveryError>> {
        write_mrt_core_dump(self.core_dump, error.bytes.clone());
        let consumed = error.bytes.clone().unwrap_or_default();
        debug_assert_eq!(record_start + consumed.len() as u64, self.reader.position());
        let confirmations = self.config.confirmation_records.max(1);
        let max_scan_bytes = self.config.max_scan_bytes;
        let mut window = ReplayReader::seeded(&mut self.reader, consumed, record_start);

        if let Some(framed_end) = framed_end {
            match confirm_aligned_boundary(&mut window, framed_end, confirmations) {
                Ok(Some(confirmed_records)) => {
                    let leftover = window.into_leftover(framed_end);
                    self.reader.resume_with(leftover, framed_end);
                    return Some(Ok(RecoveryEvent::Gap(RecoveryGap {
                        start_offset: record_start,
                        end_offset: framed_end,
                        cause: error.to_string(),
                        evidence: RecoveryEvidence::AlignedRecordChain,
                        confirmed_records,
                    })));
                }
                Ok(None) => {}
                Err(io_error) => {
                    self.finished = true;
                    return Some(Err(RecoveryError {
                        offset: record_start,
                        scanned_bytes: 0,
                        error: ParserErrorWithBytes::from(ParserError::IoError(io_error)),
                    }));
                }
            }
        }

        match find_recovery(&mut window, record_start, max_scan_bytes, confirmations) {
            Ok(ScanOutcome::Found {
                offset,
                evidence,
                confirmed_records,
            }) => {
                let leftover = window.into_leftover(offset);
                self.reader.resume_with(leftover, offset);
                Some(Ok(RecoveryEvent::Gap(RecoveryGap {
                    start_offset: record_start,
                    end_offset: offset,
                    cause: error.to_string(),
                    evidence,
                    confirmed_records,
                })))
            }
            Ok(ScanOutcome::EndOfStream { end_offset }) => {
                let leftover = window.into_leftover(end_offset);
                self.reader.resume_with(leftover, end_offset);
                Some(Ok(RecoveryEvent::Gap(RecoveryGap {
                    start_offset: record_start,
                    end_offset,
                    cause: error.to_string(),
                    evidence: RecoveryEvidence::EndOfStream,
                    confirmed_records: 0,
                })))
            }
            Ok(ScanOutcome::WindowExhausted) => {
                self.finished = true;
                Some(Err(RecoveryError {
                    offset: record_start,
                    scanned_bytes: max_scan_bytes as u64,
                    error,
                }))
            }
            Err(io_error) => {
                self.finished = true;
                Some(Err(RecoveryError {
                    offset: record_start,
                    scanned_bytes: window.position().saturating_sub(record_start),
                    error: ParserErrorWithBytes::from(ParserError::IoError(io_error)),
                }))
            }
        }
    }
}

/// Iterator over BGP elements and explicit recovery gaps.
///
/// Filters are applied per element; each record is converted to elements exactly once.
pub struct RecoveringElemIterator<R> {
    inner: RecoveringRecordIterator<R>,
    elementor: Elementor,
    filters: Vec<Filter>,
    cache_elems: Vec<BgpElem>,
}

impl<R> RecoveringElemIterator<R> {
    pub(crate) fn new(mut parser: BgpkitParser<R>, config: RecoveryConfig) -> Self {
        // Elements are filtered here; strip the parser filters so the inner record
        // iterator does not also convert every record for record-level matching.
        let filters = std::mem::take(&mut parser.filters);
        Self {
            inner: RecoveringRecordIterator::new(parser, config),
            elementor: Elementor::new(),
            filters,
            cache_elems: Vec::new(),
        }
    }
}

impl<R: Read> Iterator for RecoveringElemIterator<R> {
    type Item = Result<RecoveryEvent<BgpElem>, RecoveryError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(elem) = self.cache_elems.pop() {
                return Some(Ok(RecoveryEvent::Item(elem)));
            }
            match self.inner.next()? {
                Ok(RecoveryEvent::Item(record)) => {
                    let mut elems = self.elementor.record_to_elems(record);
                    elems.retain(|elem| elem.match_filters(&self.filters));
                    elems.reverse();
                    self.cache_elems = elems;
                }
                Ok(RecoveryEvent::Gap(gap)) => return Some(Ok(RecoveryEvent::Gap(gap))),
                Err(error) => return Some(Err(error)),
            }
        }
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

enum ScanOutcome {
    Found {
        offset: u64,
        evidence: RecoveryEvidence,
        confirmed_records: u8,
    },
    EndOfStream {
        end_offset: u64,
    },
    WindowExhausted,
}

/// Confirm that intact records (of any MRT type) parse at the failed record's declared
/// end offset, distinguishing an unparsable-but-correctly-framed record from framing
/// damage. A clean end of stream on the boundary is consistent with intact framing.
fn confirm_aligned_boundary<R: Read>(
    window: &mut ReplayReader<R>,
    boundary: u64,
    required: u8,
) -> io::Result<Option<u8>> {
    if !window.move_to(boundary)? {
        return Ok(None);
    }
    let mut confirmed = 0u8;
    while confirmed < required {
        match parse_mrt_record_with_zebra_compat(window) {
            Ok(_) => confirmed += 1,
            Err(error) => {
                return match error.error {
                    ParserError::EofExpected => Ok(Some(confirmed)),
                    ParserError::IoError(inner) | ParserError::EofError(inner)
                        if inner.kind() != io::ErrorKind::UnexpectedEof =>
                    {
                        Err(inner)
                    }
                    _ => Ok(None),
                };
            }
        }
    }
    Ok(Some(confirmed))
}

fn is_anchor_entry_type(bytes: [u8; 2]) -> bool {
    let value = u16::from_be_bytes(bytes);
    value == EntryType::BGP as u16
        || value == EntryType::BGP4MP as u16
        || value == EntryType::BGP4MP_ET as u16
}

fn find_recovery<R: Read>(
    window: &mut ReplayReader<R>,
    failed_start: u64,
    max_scan_bytes: usize,
    confirmations: u8,
) -> io::Result<ScanOutcome> {
    for distance in 1..=max_scan_bytes {
        let candidate = failed_start + distance as u64;
        // Cheap anchor pre-filter: only offsets whose entry-type field matches a
        // recoverable stream family warrant header parsing and chain validation.
        let Some(entry_type) = window.peek_two_at(candidate + 4)? else {
            return Ok(ScanOutcome::EndOfStream {
                end_offset: window.buffered_end(),
            });
        };
        if !is_anchor_entry_type(entry_type) {
            continue;
        }
        if let Some((evidence, confirmed_records)) =
            validate_chain(window, candidate, confirmations)?
        {
            return Ok(ScanOutcome::Found {
                offset: candidate,
                evidence,
                confirmed_records,
            });
        }
    }
    Ok(ScanOutcome::WindowExhausted)
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
            return Ok(None);
        };
        if family.is_some_and(|expected| expected != candidate.family) {
            return Ok(None);
        }
        family.get_or_insert(candidate.family);
        evidence.get_or_insert(candidate.evidence);
        confirmed += 1;
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

    let mut body = Vec::with_capacity(header.length as usize);
    reader
        .by_ref()
        .take(header.length as u64)
        .read_to_end(&mut body)?;
    if body.len() != header.length as usize {
        // The stream ended inside the candidate body.
        return Ok(None);
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

/// Reader adapter that tracks the absolute decompressed-stream offset and can be handed
/// back unconsumed bytes after a recovery scan read past the resume boundary.
struct CarryoverReader<R> {
    inner: R,
    carryover: Vec<u8>,
    carry_pos: usize,
    offset: u64,
}

impl<R> CarryoverReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            carryover: Vec::new(),
            carry_pos: 0,
            offset: 0,
        }
    }

    fn position(&self) -> u64 {
        self.offset
    }

    /// Resume reading at `offset`, serving `bytes` (followed by any bytes already held
    /// but not yet served) before the underlying reader.
    fn resume_with(&mut self, mut bytes: Vec<u8>, offset: u64) {
        bytes.extend_from_slice(&self.carryover[self.carry_pos..]);
        self.carryover = bytes;
        self.carry_pos = 0;
        self.offset = offset;
    }
}

impl<R: Read> Read for CarryoverReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.carry_pos < self.carryover.len() {
            let count = output.len().min(self.carryover.len() - self.carry_pos);
            output[..count]
                .copy_from_slice(&self.carryover[self.carry_pos..self.carry_pos + count]);
            self.carry_pos += count;
            self.offset += count as u64;
            if self.carry_pos == self.carryover.len() {
                self.carryover.clear();
                self.carry_pos = 0;
            }
            return Ok(count);
        }
        let read = self.inner.read(output)?;
        self.offset += read as u64;
        Ok(read)
    }
}

/// Bounded lookahead buffer used only while scanning for a recovery boundary.
///
/// It is seeded with the bytes already consumed by the failed record and buffers further
/// bytes on demand so candidate boundaries can be revisited. It exists only for the
/// duration of one recovery attempt; the undamaged fast path never copies through it.
struct ReplayReader<R> {
    inner: R,
    data: Vec<u8>,
    cursor: usize,
    base_offset: u64,
}

impl<R> ReplayReader<R> {
    fn seeded(inner: R, data: Vec<u8>, base_offset: u64) -> Self {
        Self {
            inner,
            data,
            cursor: 0,
            base_offset,
        }
    }

    fn position(&self) -> u64 {
        self.base_offset + self.cursor as u64
    }

    fn buffered_end(&self) -> u64 {
        self.base_offset + self.data.len() as u64
    }

    /// Consume the window, returning the buffered bytes at and beyond `offset`.
    fn into_leftover(mut self, offset: u64) -> Vec<u8> {
        let index = (offset.saturating_sub(self.base_offset) as usize).min(self.data.len());
        self.data.split_off(index)
    }
}

impl<R: Read> ReplayReader<R> {
    /// Buffer through `offset` and place the cursor there. Returns false when the stream
    /// ends first or `offset` precedes the window.
    fn move_to(&mut self, offset: u64) -> io::Result<bool> {
        if offset < self.base_offset {
            return Ok(false);
        }
        let target = (offset - self.base_offset) as usize;
        while self.data.len() < target {
            let filled = self.data.len();
            let chunk = (target - filled).min(SCAN_FILL_CHUNK);
            self.data.resize(filled + chunk, 0);
            let read = self.inner.read(&mut self.data[filled..])?;
            self.data.truncate(filled + read);
            if read == 0 {
                self.cursor = self.data.len();
                return Ok(false);
            }
        }
        self.cursor = target;
        Ok(true)
    }

    /// Read two bytes at `offset`, buffering as needed. Returns `None` when the stream
    /// ends first. Callers re-position with [`Self::move_to`] before parsing.
    fn peek_two_at(&mut self, offset: u64) -> io::Result<Option<[u8; 2]>> {
        if !self.move_to(offset + 2)? {
            return Ok(None);
        }
        let index = (offset - self.base_offset) as usize;
        Ok(Some([self.data[index], self.data[index + 1]]))
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

    /// A record with a well-formed common header and declared length, whose body cannot
    /// be parsed as a BGP4MP message.
    fn framed_record_with_garbage_body(timestamp: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_u32(timestamp);
        bytes.put_u16(EntryType::BGP4MP as u16);
        bytes.put_u16(Bgp4MpType::Message as u16);
        bytes.put_u32(body.len() as u32);
        bytes.put_slice(body);
        bytes.to_vec()
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
    fn emits_terminal_gap_when_chain_too_short_before_non_eof_garbage() {
        let mut input = vec![0xff; 12];
        input.extend_from_slice(&legacy_state(101));
        input.extend_from_slice(&legacy_state(102));
        input.extend_from_slice(&[1, 2, 3]);
        let total = input.len() as u64;

        let parser = BgpkitParser::from_reader(Cursor::new(input));
        let events = parser
            .into_recovering_record_iter(RecoveryConfig::default())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // A two-record chain is below the configured confirmation count, so nothing is
        // recovered; the damage extends to the end of the stream and is reported as a
        // terminal gap rather than an error.
        assert_eq!(events.len(), 1);
        let RecoveryEvent::Gap(gap) = &events[0] else {
            panic!("expected terminal gap")
        };
        assert_eq!(gap.start_offset, 0);
        assert_eq!(gap.end_offset, total);
        assert_eq!(gap.evidence, RecoveryEvidence::EndOfStream);
        assert_eq!(gap.confirmed_records, 0);
    }

    #[test]
    fn emits_terminal_gap_when_chain_too_short_at_clean_eof() {
        let mut input = vec![0xff; 12];
        input.extend_from_slice(&legacy_state(101));
        input.extend_from_slice(&legacy_state(102));
        let total = input.len() as u64;

        let parser = BgpkitParser::from_reader(Cursor::new(input));
        let events = parser
            .into_recovering_record_iter(RecoveryConfig::default())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(events.len(), 1);
        let RecoveryEvent::Gap(gap) = &events[0] else {
            panic!("expected terminal gap")
        };
        assert_eq!(gap.start_offset, 0);
        assert_eq!(gap.end_offset, total);
        assert_eq!(gap.evidence, RecoveryEvidence::EndOfStream);
        assert_eq!(gap.confirmed_records, 0);
    }

    #[test]
    fn truncated_final_record_yields_terminal_gap() {
        let mut input = bgp4mp_keepalive(100);
        input.extend_from_slice(&bgp4mp_keepalive(101));
        let boundary = input.len() as u64;
        let tail = bgp4mp_keepalive(102);
        input.extend_from_slice(&tail[..10]);
        let total = input.len() as u64;

        let parser = BgpkitParser::from_reader(Cursor::new(input));
        let events = parser
            .into_recovering_record_iter(RecoveryConfig::default())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], RecoveryEvent::Item(_)));
        assert!(matches!(events[1], RecoveryEvent::Item(_)));
        let RecoveryEvent::Gap(gap) = &events[2] else {
            panic!("expected terminal gap")
        };
        assert_eq!(gap.start_offset, boundary);
        assert_eq!(gap.end_offset, total);
        assert_eq!(gap.evidence, RecoveryEvidence::EndOfStream);
        assert_eq!(gap.confirmed_records, 0);
    }

    #[test]
    fn skips_exactly_one_framed_record_with_unparsable_body() {
        let first = bgp4mp_keepalive(100);
        let bad = framed_record_with_garbage_body(101, &[0xde, 0xad, 0xbe]);
        let mut input = first.clone();
        input.extend_from_slice(&bad);
        input.extend_from_slice(&bgp4mp_keepalive(102));
        input.extend_from_slice(&bgp4mp_keepalive(103));
        input.extend_from_slice(&bgp4mp_keepalive(104));

        let parser = BgpkitParser::from_reader(Cursor::new(input));
        let events = parser
            .into_recovering_record_iter(RecoveryConfig::default())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // The bad record framed correctly, so exactly its bytes are skipped without a
        // boundary scan and all following records survive.
        assert_eq!(events.len(), 5);
        assert!(matches!(events[0], RecoveryEvent::Item(_)));
        let RecoveryEvent::Gap(gap) = &events[1] else {
            panic!("expected aligned-boundary gap")
        };
        assert_eq!(gap.start_offset, first.len() as u64);
        assert_eq!(gap.end_offset, (first.len() + bad.len()) as u64);
        assert_eq!(gap.evidence, RecoveryEvidence::AlignedRecordChain);
        assert_eq!(gap.confirmed_records, 3);
        assert!(events[2..]
            .iter()
            .all(|event| matches!(event, RecoveryEvent::Item(_))));
    }

    #[test]
    fn skips_framed_record_with_unparsable_body_at_clean_eof() {
        let first = bgp4mp_keepalive(100);
        let bad = framed_record_with_garbage_body(101, &[0xde, 0xad, 0xbe]);
        let mut input = first.clone();
        input.extend_from_slice(&bad);

        let parser = BgpkitParser::from_reader(Cursor::new(input));
        let events = parser
            .into_recovering_record_iter(RecoveryConfig::default())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], RecoveryEvent::Item(_)));
        let RecoveryEvent::Gap(gap) = &events[1] else {
            panic!("expected aligned-boundary gap")
        };
        assert_eq!(gap.start_offset, first.len() as u64);
        assert_eq!(gap.end_offset, (first.len() + bad.len()) as u64);
        assert_eq!(gap.evidence, RecoveryEvidence::AlignedRecordChain);
        assert_eq!(gap.confirmed_records, 0);
    }

    #[test]
    fn misframed_record_falls_back_to_boundary_scan() {
        let first = bgp4mp_keepalive(100);
        // A header whose declared length overlaps the next record: the declared
        // boundary is misaligned, so aligned-boundary confirmation must fail and the
        // byte scan must find the true boundary.
        let mut bad = BytesMut::new();
        bad.put_u32(101);
        bad.put_u16(EntryType::BGP4MP as u16);
        bad.put_u16(Bgp4MpType::Message as u16);
        bad.put_u32(5);
        let mut input = first.clone();
        input.extend_from_slice(&bad);
        input.extend_from_slice(&[0xde, 0xad, 0xbe]);
        input.extend_from_slice(&bgp4mp_keepalive(102));
        input.extend_from_slice(&bgp4mp_keepalive(103));
        input.extend_from_slice(&bgp4mp_keepalive(104));

        let parser = BgpkitParser::from_reader(Cursor::new(input));
        let events = parser
            .into_recovering_record_iter(RecoveryConfig::default())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(events.len(), 5);
        let RecoveryEvent::Gap(gap) = &events[1] else {
            panic!("expected recovery gap")
        };
        assert_eq!(gap.start_offset, first.len() as u64);
        assert_eq!(gap.end_offset, (first.len() + bad.len() + 3) as u64);
        assert_eq!(gap.evidence, RecoveryEvidence::BgpMarkerChain);
        assert_eq!(gap.confirmed_records, 3);
        assert!(events[2..]
            .iter()
            .all(|event| matches!(event, RecoveryEvent::Item(_))));
    }

    #[test]
    fn text_dump_parser_yields_unsupported_error() {
        let dump = "BGP table version is 1, local router ID is 1.2.3.4, vrf id 0\n\
Default local pref 100, local AS 65001\n\n\
    Network          Next Hop            Metric LocPrf Weight Path\n\
 *> 1.0.0.0/24       10.0.0.1                 0             0 13335 i\n";
        let parser = BgpkitParser::from_text_reader(dump.as_bytes()).unwrap();
        let mut iter = parser.into_recovering_record_iter(RecoveryConfig::default());

        let error = iter.next().expect("one error").unwrap_err();
        assert!(matches!(error.error.error, ParserError::Unsupported(_)));
        assert!(iter.next().is_none());
    }

    #[test]
    fn recovering_elem_iter_passes_gaps_through() {
        let first = legacy_state(100);
        let mut input = first.clone();
        input.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x01]);
        input.extend_from_slice(&legacy_state(101));
        input.extend_from_slice(&legacy_state(102));
        input.extend_from_slice(&legacy_state(103));

        let parser = BgpkitParser::from_reader(Cursor::new(input));
        let events = parser
            .into_recovering_elem_iter(RecoveryConfig::default())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // State-change records yield no elements, so only the gap surfaces.
        assert_eq!(events.len(), 1);
        let RecoveryEvent::Gap(gap) = &events[0] else {
            panic!("expected recovery gap")
        };
        assert_eq!(gap.start_offset, first.len() as u64);
        assert_eq!(gap.end_offset, first.len() as u64 + 5);
    }

    #[test]
    fn skipped_bytes_is_zero_for_inverted_range() {
        let gap = RecoveryGap {
            start_offset: 10,
            end_offset: 5,
            cause: String::new(),
            evidence: RecoveryEvidence::LegacyMrtChain,
            confirmed_records: 3,
        };

        assert_eq!(gap.skipped_bytes(), 0);
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
