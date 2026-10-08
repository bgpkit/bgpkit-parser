/*!
Iterator implementations for bgpkit-parser.

This module contains different iterator implementations for parsing BGP data:
- `default`: Standard iterators that skip errors (RecordIterator, ElemIterator)
- `fallible`: Fallible iterators that return Results (FallibleRecordIterator, FallibleElemIterator)
- `update`: Iterators for BGP UPDATE messages (UpdateIterator, FallibleUpdateIterator)
- `route`: Route-level iterators (RouteIterator, FallibleRouteIterator)
- `recovery`: Iterators that survive damaged MRT framing (RecoveringRecordIterator,
  RecoveringElemIterator, RecoveryEvent)
- `diagnostic`: Per-record dissection and validation reporting (DiagnosticIterator,
  DissectingDiagnosticIterator)
- `raw`: Raw MRT records with their original bytes (RawRecordIterator,
  FilteredRawRecordIterator)

It also contains the trait implementations that enable BgpkitParser to be used with
Rust's iterator syntax.
*/

pub mod default;
mod diagnostic;
pub mod fallible;
mod raw;
mod recovery;
mod route;
mod update;

// Re-export all iterator types for convenience
pub use default::{ElemIterator, RecordIterator};
pub use diagnostic::{
    record_validation_warnings, span_record_warnings, DiagnosticEvent, DiagnosticIterator,
    DissectedDiagnosticEvent, DissectingDiagnosticIterator,
};
pub use fallible::{FallibleElemIterator, FallibleRecordIterator};
pub use raw::{FilteredRawRecordIterator, RawRecordIterator};
pub use recovery::{
    RecoveringElemIterator, RecoveringRecordIterator, RecoveryConfig, RecoveryError, RecoveryEvent,
    RecoveryEvidence, RecoveryGap,
};
pub use route::{FallibleRouteIterator, RouteIterator};
pub use update::{
    Bgp4MpUpdate, FallibleUpdateIterator, LegacyBgpUpdate, MrtUpdate, TableDumpV2Entry,
    UpdateIterator,
};

use crate::error::{ParserError, ParserErrorWithBytes};
use crate::models::BgpElem;
use crate::models::{MrtMessage, MrtRecord, TableDumpV2Message};
use crate::parser::mrt::mrt_record::parse_chunked_record_with_zebra_compat;
use crate::parser::{chunk_mrt_record, BgpkitParser};
use crate::RawMrtRecord;
use crate::{Elementor, Filter, Filterable};
use log::{debug, error, warn};
use std::io::Read;
use std::path::Path;

// Classify stream failures while framing: body parsing can also return
// skippable IoErrors, but a failed decompressor must not be polled again.
fn next_fallible_raw_record(
    reader: &mut impl Read,
    finished: &mut bool,
) -> Option<Result<RawMrtRecord, ParserErrorWithBytes>> {
    if *finished {
        return None;
    }
    match chunk_mrt_record(reader) {
        Ok(record) => Some(Ok(record)),
        Err(error) if matches!(error.error, ParserError::EofExpected) => {
            *finished = true;
            None
        }
        Err(error) => {
            if let ParserError::IoError(io_error) | ParserError::EofError(io_error) = &error.error {
                // A resumed pull starts a fresh header, so retrying is only safe
                // when the failed read consumed nothing; otherwise the partial
                // framing bytes are gone and the stream stays misaligned.
                let nothing_consumed = error.bytes.as_ref().is_none_or(Vec::is_empty);
                *finished = !(nothing_consumed
                    && matches!(
                        io_error.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ));
            }
            Some(Err(error))
        }
    }
}

fn next_fallible_record<R: Read>(
    parser: &mut BgpkitParser<R>,
    finished: &mut bool,
) -> Option<Result<MrtRecord, ParserErrorWithBytes>> {
    let raw_record = match next_fallible_raw_record(&mut parser.reader, finished)? {
        Ok(record) => record,
        Err(error) => return Some(Err(error)),
    };
    Some(match parse_chunked_record_with_zebra_compat(raw_record) {
        Ok((record, used_zebra_compat)) => {
            if used_zebra_compat {
                parser.warn_zebra_compat_once();
            }
            Ok(record)
        }
        Err(error) => Err(error),
    })
}

#[inline]
pub(crate) fn record_matches_filters(
    record: &MrtRecord,
    filters: &[Filter],
    elementor: &mut Elementor,
) -> bool {
    if filters.is_empty() {
        return true;
    }
    if matches!(
        &record.message,
        MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(_))
    ) {
        let _ = elementor.record_to_elems(record.clone());
        return true;
    }
    // Filters match on the elem projection. Records that produce no elems
    // (KEEPALIVE, OPEN, NOTIFICATION, state changes) can therefore never
    // match and are dropped from record iteration while filters are active.
    let elems = elementor.record_to_elems(record.clone());
    if elems.is_empty() {
        debug!(
            "filters active: record of type {:?} yields no elems and is dropped",
            record.common_header.entry_type
        );
        return false;
    }
    elems.iter().any(|element| element.match_filters(filters))
}

/// Shared body-parse error policy for record-producing iterators.
///
/// Mirrors the historical `RecordIterator` behavior: warnings honor
/// `disable_warnings()`, core dumps are written for recoverable classes,
/// and a fatal `ParseError` with core dumps enabled stops the iterator so
/// a later failure cannot overwrite the dump. Returns `true` to continue
/// iterating, `false` to stop.
pub(crate) fn handle_record_parse_error<R>(
    parser: &mut crate::parser::BgpkitParser<R>,
    error: ParserError,
    bytes: Option<Vec<u8>>,
) -> bool {
    match error {
        ParserError::TruncatedMsg(err_str) | ParserError::Unsupported(err_str) => {
            if parser.options.show_warnings {
                warn!("parser warn: {}", err_str);
            }
            write_mrt_core_dump(parser.core_dump, bytes);
            true
        }
        ParserError::ParseError(err_str) => {
            parser.log_parse_error_once(&err_str);
            write_mrt_core_dump(parser.core_dump, bytes);
            // stop after writing the dump so later failures don't overwrite it
            !parser.core_dump
        }
        ParserError::EofExpected => {
            // normal end of file
            false
        }
        ParserError::IoError(err) | ParserError::EofError(err) => {
            // when reaching IO error, stop iterating
            error!("{:?}", err);
            write_mrt_core_dump(parser.core_dump, bytes);
            false
        }
        #[cfg(feature = "oneio")]
        ParserError::OneIoError(_) => false,
        ParserError::FilterError(_) => {
            // this should not happen at this stage
            false
        }
        // Labeled NLRI parsing errors - treat as malformed and skip
        ParserError::InvalidLabeledNlriLength
        | ParserError::TruncatedLabeledNlri
        | ParserError::TruncatedPrefix
        | ParserError::MaxLabelStackDepthExceeded
        | ParserError::PeerMaxLabelsExceeded
        | ParserError::InvalidPrefix => {
            if parser.options.show_warnings {
                warn!("parser warn: labeled NLRI parsing error: {:?}", error);
            }
            true
        }
    }
}

pub(crate) fn write_mrt_core_dump(enabled: bool, bytes: Option<Vec<u8>>) {
    write_mrt_core_dump_to_path(enabled, bytes, "mrt_core_dump");
}

pub(crate) fn write_mrt_core_dump_to_path<P: AsRef<Path>>(
    enabled: bool,
    bytes: Option<Vec<u8>>,
    path: P,
) {
    if enabled {
        if let Some(bytes) = bytes {
            std::fs::write(path, bytes).expect("Unable to write to mrt_core_dump");
        }
    }
}

/// Use [ElemIterator] as the default iterator to return [BgpElem]s instead of [MrtRecord]s.
impl<R: Read> IntoIterator for BgpkitParser<R> {
    type Item = BgpElem;
    type IntoIter = ElemIterator<R>;

    fn into_iter(self) -> Self::IntoIter {
        ElemIterator::new(self)
    }
}

impl<R> BgpkitParser<R> {
    pub fn into_record_iter(self) -> RecordIterator<R> {
        RecordIterator::new(self)
    }

    pub fn into_elem_iter(self) -> ElemIterator<R> {
        ElemIterator::new(self)
    }

    pub fn into_raw_record_iter(self) -> RawRecordIterator<R> {
        RawRecordIterator::new(self)
    }

    /// Creates an iterator over raw MRT records with record-level filter
    /// semantics applied.
    ///
    /// Like [`into_raw_record_iter`](Self::into_raw_record_iter), but only
    /// records passing the parser's filters are yielded (same semantics as
    /// [`into_record_iter`](Self::into_record_iter): filters match on the
    /// elem projection, so no-elem records such as KEEPALIVEs are dropped
    /// while filters are active, and the `PeerIndexTable` always passes).
    /// The yielded records carry their original wire bytes — no
    /// re-encoding — which is what byte-exact consumers (hex output,
    /// re-dissection) need. Every record body is parsed once inside the
    /// iterator and the parsed record is yielded alongside, so consumers
    /// do not parse the bytes twice; parse failures follow the same
    /// variant-aware diagnostics as the record iterator.
    ///
    /// # Example
    /// ```no_run
    /// use bgpkit_parser::BgpkitParser;
    ///
    /// let parser = BgpkitParser::new("updates.mrt").unwrap();
    /// for (raw, _) in parser.into_filtered_raw_record_iter() {
    ///     println!("{}", raw.raw_bytes().len());
    /// }
    /// ```
    pub fn into_filtered_raw_record_iter(self) -> FilteredRawRecordIterator<R> {
        FilteredRawRecordIterator::new(self)
    }

    /// Creates an opt-in iterator that reports skipped byte ranges while recovering MRT framing.
    ///
    /// Recovery never reconstructs a damaged record. It scans for a structurally valid boundary,
    /// confirms a chain of records, emits [`RecoveryEvent::Gap`], and then resumes normal parsing.
    /// Damage extending to the end of the stream is reported as a terminal gap. Offsets in
    /// recovery events refer to the decompressed MRT byte stream.
    pub fn into_recovering_record_iter(
        self,
        config: RecoveryConfig,
    ) -> RecoveringRecordIterator<R> {
        RecoveringRecordIterator::new(self, config)
    }

    /// Creates an opt-in iterator over BGP elements that reports skipped byte ranges while
    /// recovering MRT framing.
    ///
    /// Behaves like [`into_recovering_record_iter`](Self::into_recovering_record_iter) but
    /// converts each recovered record to [`BgpElem`]s, applying the parser's filters per
    /// element.
    pub fn into_recovering_elem_iter(self, config: RecoveryConfig) -> RecoveringElemIterator<R> {
        RecoveringElemIterator::new(self, config)
    }

    /// Creates an iterator over BGP announcements from MRT data.
    ///
    /// This iterator yields `MrtUpdate` items from both UPDATES files (BGP4MP messages)
    /// and RIB dump files (TableDump/TableDumpV2 messages). It's a middle ground
    /// between `into_record_iter()` and `into_elem_iter()`:
    ///
    /// - More focused than `into_record_iter()` as it only returns BGP announcements
    /// - More efficient than `into_elem_iter()` as it doesn't duplicate attributes per prefix
    ///
    /// The iterator returns an `MrtUpdate` enum with variants:
    /// - `Bgp4MpUpdate`: BGP UPDATE messages from UPDATES files
    /// - `LegacyBgpUpdate`: Deprecated MRT Type 5 BGP UPDATE messages
    /// - `TableDumpV2Entry`: RIB entries from TableDumpV2 RIB dumps
    /// - `TableDumpMessage`: Legacy TableDump v1 messages
    ///
    /// # Example
    /// ```no_run
    /// use bgpkit_parser::{BgpkitParser, MrtUpdate};
    ///
    /// let parser = BgpkitParser::new("updates.mrt").unwrap();
    /// for update in parser.into_update_iter() {
    ///     match update {
    ///         MrtUpdate::Bgp4MpUpdate(u) => {
    ///             println!("Peer {} announced {} prefixes",
    ///                 u.peer_ip,
    ///                 u.message.announced_prefixes.len()
    ///             );
    ///         }
    ///         MrtUpdate::LegacyBgpUpdate(u) => {
    ///             println!("Legacy UPDATE from peer {}", u.peer_ip);
    ///         }
    ///         MrtUpdate::TableDumpV2Entry(e) => {
    ///             println!("RIB entry for {} with {} peers",
    ///                 e.prefix,
    ///                 e.rib_entries.len()
    ///             );
    ///         }
    ///         MrtUpdate::TableDumpMessage(m) => {
    ///             println!("Legacy table dump for {}", m.prefix);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn into_update_iter(self) -> UpdateIterator<R> {
        UpdateIterator::new(self)
    }

    /// Creates an iterator over lightweight route elements from MRT data.
    ///
    /// This iterator yields [`BgpRouteElem`](crate::models::BgpRouteElem)
    /// values and only parses route identity, peer metadata, timestamp, and
    /// AS path. Use [`into_elem_iter`](Self::into_elem_iter) when you need
    /// the full [`BgpElem`] attribute set. Filters that only depend on route
    /// fields are supported; `community` filters do not match route elements.
    ///
    /// With [RFC 7606 error handling](Self::enable_rfc7606_error_handling), the route iterator
    /// checks every attribute header like the element iterators do, but parses only the values
    /// of ORIGIN, AS_PATH, AS4_PATH, MP_REACH_NLRI and MP_UNREACH_NLRI. A value error in any
    /// other attribute, such as a truncated D-PATH, goes unnoticed: the route iterator may keep
    /// routes the element iterators withdraw, never the reverse.
    pub fn into_route_iter(self) -> RouteIterator<R> {
        RouteIterator::new(self)
    }

    /// Creates a fallible iterator over MRT records that returns parsing errors.
    ///
    /// Malformed records can be skipped. A framing I/O or decompression error
    /// is yielded once and then ends iteration permanently, except for an
    /// `Interrupted` or `WouldBlock` read that consumed no framing bytes, which
    /// leaves the stream retryable. Normal EOF also ends iteration permanently.
    ///
    /// # Example
    /// ```no_run
    /// use bgpkit_parser::BgpkitParser;
    ///
    /// let parser = BgpkitParser::new("updates.mrt").unwrap();
    /// for result in parser.into_fallible_record_iter() {
    ///     match result {
    ///         Ok(record) => {
    ///             // Process the record
    ///         }
    ///         Err(e) => {
    ///             // Handle the error
    ///             eprintln!("Error parsing record: {}", e);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn into_fallible_record_iter(self) -> FallibleRecordIterator<R> {
        FallibleRecordIterator::new(self)
    }

    /// Creates a fallible iterator over BGP elements that returns parsing errors.
    ///
    /// Uses the same stream-error termination policy as
    /// [`into_fallible_record_iter`](Self::into_fallible_record_iter).
    ///
    /// # Example
    /// ```no_run
    /// use bgpkit_parser::BgpkitParser;
    ///
    /// let parser = BgpkitParser::new("updates.mrt").unwrap();
    /// for result in parser.into_fallible_elem_iter() {
    ///     match result {
    ///         Ok(elem) => {
    ///             // Process the element
    ///         }
    ///         Err(e) => {
    ///             // Handle the error
    ///             eprintln!("Error parsing element: {}", e);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn into_fallible_elem_iter(self) -> FallibleElemIterator<R> {
        FallibleElemIterator::new(self)
    }

    /// Creates a fallible iterator over BGP announcements that returns parsing errors.
    ///
    /// Unlike the default `into_update_iter()`, this iterator returns
    /// `Result<MrtUpdate, ParserErrorWithBytes>` allowing users to handle parsing
    /// errors explicitly instead of having them logged and skipped. Uses the same
    /// stream-error termination policy as
    /// [`into_fallible_record_iter`](Self::into_fallible_record_iter).
    ///
    /// # Example
    /// ```no_run
    /// use bgpkit_parser::{BgpkitParser, MrtUpdate};
    ///
    /// let parser = BgpkitParser::new("updates.mrt").unwrap();
    /// for result in parser.into_fallible_update_iter() {
    ///     match result {
    ///         Ok(MrtUpdate::Bgp4MpUpdate(update)) => {
    ///             println!("Peer {} announced {} prefixes",
    ///                 update.peer_ip,
    ///                 update.message.announced_prefixes.len()
    ///             );
    ///         }
    ///         Ok(_) => { /* handle other variants */ }
    ///         Err(e) => {
    ///             eprintln!("Error parsing: {}", e);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn into_fallible_update_iter(self) -> FallibleUpdateIterator<R> {
        FallibleUpdateIterator::new(self)
    }

    /// Creates a fallible iterator over lightweight route elements.
    ///
    /// Uses the same stream-error termination policy as
    /// [`into_fallible_record_iter`](Self::into_fallible_record_iter).
    pub fn into_fallible_route_iter(self) -> FallibleRouteIterator<R> {
        FallibleRouteIterator::new(self)
    }

    /// Creates an iterator that classifies each MRT record for malformed-data investigation.
    ///
    /// This iterator emits every record with its raw bytes attached: clean
    /// records have empty warning lists, records with recoverable RFC 7606
    /// validation findings carry them in `warnings`, and fatal parse errors
    /// retain the consumed bytes plus a best-effort partial dissection tree
    /// showing where parsing stopped. It ignores parser filters so that
    /// malformed records cannot be hidden by element-oriented matching. Text-dump parsers yield
    /// no diagnostic events because they have no MRT record representation.
    ///
    /// # Example
    /// ```no_run
    /// use bgpkit_parser::{BgpkitParser, DiagnosticEvent};
    ///
    /// for event in BgpkitParser::new("updates.mrt")?.into_diagnostic_iter() {
    ///     match event {
    ///         DiagnosticEvent::Record { record, raw, warnings } => {
    ///             if warnings.is_empty() {
    ///                 println!("{record}");
    ///             } else {
    ///                 eprintln!("validation findings: {warnings:?}");
    ///                 raw.write_raw_bytes("malformed-record.mrt")?;
    ///             }
    ///         }
    ///         DiagnosticEvent::ParseError { error, raw_bytes, .. } => {
    ///             eprintln!("parse error: {error}");
    ///             if let Some(raw_bytes) = raw_bytes {
    ///                 std::fs::write("malformed-record.mrt", raw_bytes)?;
    ///             }
    ///         }
    ///         _ => {}
    ///     }
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn into_diagnostic_iter(self) -> DiagnosticIterator<R> {
        DiagnosticIterator::new(self)
    }

    /// Creates an Elementor pre-initialized with PeerIndexTable and an iterator over raw records.
    ///
    /// This is useful for parallel processing where the Elementor needs to be shared across threads.
    /// The Elementor is created with the PeerIndexTable from the first record if present,
    /// otherwise a new Elementor is created.
    ///
    /// # Example
    /// See the `parallel_records_to_elem` example for full usage.
    /// ```ignore
    /// use bgpkit_parser::BgpkitParser;
    ///
    /// let parser = BgpkitParser::new_cached(url, "/tmp")?;
    /// let (elementor, records) = parser.into_elementor_and_raw_record_iter();
    /// ```
    ///
    pub fn into_elementor_and_raw_record_iter(
        self,
    ) -> (Elementor, impl Iterator<Item = RawMrtRecord>)
    where
        R: Read,
    {
        let mode = self.options.error_handling;
        let mut raw_iter = RawRecordIterator::new(self).peekable();
        let elementor = match raw_iter.peek().cloned().and_then(|r| r.parse().ok()) {
            Some(MrtRecord {
                message: MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(pit)),
                ..
            }) => {
                raw_iter.next();
                Elementor::with_peer_table(pit).with_error_handling(mode)
            }
            _ => Elementor::new().with_error_handling(mode),
        };
        (elementor, raw_iter)
    }

    /// Creates an Elementor pre-initialized with PeerIndexTable and an iterator over parsed records.
    ///
    /// This is useful for parallel processing where the Elementor needs to be shared across threads.
    /// The Elementor is created with the PeerIndexTable from the first record if present,
    /// otherwise a new Elementor is created.
    ///
    /// # Example
    /// See the `parallel_records_to_elem` example for full usage.
    pub fn into_elementor_and_record_iter(self) -> (Elementor, impl Iterator<Item = MrtRecord>)
    where
        R: Read,
    {
        let mode = self.options.error_handling;
        let mut record_iter = RecordIterator::new(self).peekable();
        let elementor = match record_iter.peek().cloned() {
            Some(MrtRecord {
                message: MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(pit)),
                ..
            }) => {
                record_iter.next();
                Elementor::with_peer_table(pit).with_error_handling(mode)
            }
            _ => Elementor::new().with_error_handling(mode),
        };
        (elementor, record_iter)
    }
}
