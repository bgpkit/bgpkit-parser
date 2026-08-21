/*!
The RawMrtRecord Iterator module provides functionality for iterating over raw MRT records
from a BGP data source. This iterator is responsible for:

* Reading and parsing raw MRT records sequentially from an input stream
* Handling parsing errors and warnings appropriately
* Providing a clean interface for processing MRT records one at a time

The iterator implements error recovery strategies, allowing it to skip malformed records
when possible and continue processing the remaining data. It also supports configurable
warning messages and core dump generation for debugging purposes.
*/

use crate::parser::iters::{
    handle_record_parse_error, record_matches_filters, write_mrt_core_dump,
};
use crate::parser::mrt::mrt_record::raw_record_uses_zebra_compat;
use crate::{
    chunk_mrt_record, BgpkitParser, Elementor, Filter, MrtRecord, ParserError, RawMrtRecord,
};
use log::{error, warn};
use std::io::Read;

pub struct RawRecordIterator<R> {
    parser: BgpkitParser<R>,
    count: u64,
}

impl<R> RawRecordIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        RawRecordIterator { parser, count: 0 }
    }
}

impl<R: Read> Iterator for RawRecordIterator<R> {
    type Item = RawMrtRecord;

    fn next(&mut self) -> Option<RawMrtRecord> {
        // Text-dump parsers have no MRT-record representation; short-circuit.
        if self.parser.text_dump_iter.is_some() {
            return None;
        }
        self.count += 1;
        loop {
            match chunk_mrt_record(&mut self.parser.reader) {
                Ok(raw_record) => return Some(raw_record),
                Err(e) => match e.error {
                    ParserError::TruncatedMsg(err_str) | ParserError::Unsupported(err_str) => {
                        if self.parser.options.show_warnings {
                            warn!("parser warn: {}", err_str);
                        }
                        write_mrt_core_dump(self.parser.core_dump, e.bytes);
                        continue;
                    }
                    ParserError::ParseError(err_str) => {
                        error!("parser error: {}", err_str);
                        write_mrt_core_dump(self.parser.core_dump, e.bytes);
                        if self.parser.core_dump {
                            return None;
                        } else {
                            continue;
                        }
                    }
                    ParserError::EofExpected => {
                        // normal end of file
                        return None;
                    }
                    ParserError::IoError(err) | ParserError::EofError(err) => {
                        // when reaching IO error, stop iterating
                        error!("{:?}", err);
                        write_mrt_core_dump(self.parser.core_dump, e.bytes);
                        return None;
                    }
                    #[cfg(feature = "oneio")]
                    ParserError::OneIoError(_) => return None,
                    ParserError::FilterError(_) => {
                        // this should not happen at this stage
                        return None;
                    }
                    // Labeled NLRI parsing errors - treat as malformed and skip
                    ParserError::InvalidLabeledNlriLength
                    | ParserError::TruncatedLabeledNlri
                    | ParserError::TruncatedPrefix
                    | ParserError::MaxLabelStackDepthExceeded
                    | ParserError::PeerMaxLabelsExceeded
                    | ParserError::InvalidPrefix => {
                        if self.parser.options.show_warnings {
                            warn!("parser warn: labeled NLRI parsing error: {:?}", e.error);
                        }
                        continue;
                    }
                },
            }
        }
    }
}

/// Iterator over raw MRT records with record-level filter semantics
/// applied.
///
/// Behaves like [`RawRecordIterator`] for chunking, but only yields the
/// raw bytes of records that pass the parser's filters under the same
/// semantics as [`RecordIterator`](crate::RecordIterator): filters match
/// on the elem projection, so records that produce no elems (KEEPALIVE,
/// OPEN, NOTIFICATION, state changes) are dropped while filters are
/// active, and the `PeerIndexTable` always passes through so RIB peer
/// resolution keeps working.
///
/// The yielded [`RawMrtRecord`]s carry the *original* wire bytes — no
/// re-encoding is involved — which is what byte-exact outputs (hex dumps,
/// re-dissection) require. When filters required a parse for matching,
/// the parsed record is yielded alongside (`Some`), so consumers that
/// render the record do not need to parse the bytes a second time; the
/// no-filter fast path skips parsing and yields `None`.
///
/// Shortened Zebra BGP4MP records are detected and warned about once,
/// matching the record iterator's data-quality diagnostic.
pub struct FilteredRawRecordIterator<R> {
    inner: RawRecordIterator<R>,
    elementor: Elementor,
    filters: Vec<Filter>,
}

impl<R> FilteredRawRecordIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        let filters = parser.filters.clone();
        FilteredRawRecordIterator {
            inner: RawRecordIterator::new(parser),
            elementor: Elementor::new(),
            filters,
        }
    }

    /// Zebra detection delegates to the parser's own warn-once state, so
    /// `disable_warnings()` is honored and a parser that already warned
    /// before conversion does not warn again.
    fn warn_zebra_once(&mut self, raw: &RawMrtRecord) {
        if raw_record_uses_zebra_compat(raw) {
            self.inner.parser.warn_zebra_compat_once();
        }
    }
}

impl<R: Read> Iterator for FilteredRawRecordIterator<R> {
    type Item = (RawMrtRecord, Option<MrtRecord>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.filters.is_empty() {
            // No filtering needed: yield the raw chunks untouched without
            // paying for a parse.
            let raw = self.inner.next()?;
            self.warn_zebra_once(&raw);
            return Some((raw, None));
        }
        loop {
            let raw = self.inner.next()?;
            self.warn_zebra_once(&raw);
            // Body-parse failures share the record iterator's
            // variant-aware error policy (warnings vs. errors, core
            // dumps, stop-after-dump).
            let record = match raw.clone().parse() {
                Ok(record) => record,
                Err(error) => {
                    if !handle_record_parse_error(
                        &mut self.inner.parser,
                        error,
                        Some(raw.raw_bytes().to_vec()),
                    ) {
                        return None;
                    }
                    continue;
                }
            };
            if record_matches_filters(&record, &self.filters, &mut self.elementor) {
                return Some((raw, Some(record)));
            }
        }
    }
}

#[cfg(test)]
mod filtered_tests {
    use super::*;
    use crate::models::*;
    use std::io::Cursor;

    fn bgp4mp_record(timestamp: u32, bgp_message: BgpMessage) -> Vec<u8> {
        let body_of = |update: &BgpUpdateMessage| update.encode(AsnLength::Bits32).unwrap();
        let body = match &bgp_message {
            BgpMessage::Update(update) => body_of(update),
            BgpMessage::KeepAlive => Vec::new().into(),
            _ => unreachable!("test builds updates and keepalives only"),
        };
        let mut bgp = vec![0xFF; 16];
        bgp.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
        bgp.push(bgp_message.msg_type() as u8);
        bgp.extend_from_slice(&body);

        let mut mrt_body = Vec::new();
        mrt_body.extend_from_slice(&64496u32.to_be_bytes());
        mrt_body.extend_from_slice(&64497u32.to_be_bytes());
        mrt_body.extend_from_slice(&0u16.to_be_bytes());
        mrt_body.extend_from_slice(&1u16.to_be_bytes());
        mrt_body.extend_from_slice(&[192, 0, 2, 1]);
        mrt_body.extend_from_slice(&[192, 0, 2, 2]);
        mrt_body.extend_from_slice(&bgp);

        let mut wire = Vec::new();
        wire.extend_from_slice(&timestamp.to_be_bytes());
        wire.extend_from_slice(&(EntryType::BGP4MP as u16).to_be_bytes());
        wire.extend_from_slice(&(Bgp4MpType::MessageAs4 as u16).to_be_bytes());
        wire.extend_from_slice(&(mrt_body.len() as u32).to_be_bytes());
        wire.extend_from_slice(&mrt_body);
        wire
    }

    fn keepalive(timestamp: u32) -> Vec<u8> {
        bgp4mp_record(timestamp, BgpMessage::KeepAlive)
    }

    fn update(timestamp: u32) -> Vec<u8> {
        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        attributes.add_attr(AttributeValue::AsPath(AsPath::from_sequence([65000])).into());
        attributes.add_attr(AttributeValue::NextHop("192.0.2.254".parse().unwrap()).into());
        bgp4mp_record(
            timestamp,
            BgpMessage::Update(BgpUpdateMessage {
                withdrawn_prefixes: vec![],
                attributes,
                announced_prefixes: vec!["198.51.100.0/24".parse().unwrap()],
            }),
        )
    }

    #[test]
    fn no_filters_yield_original_bytes_exactly() {
        let mut input = keepalive(1);
        let upd = update(2);
        input.extend_from_slice(&upd);

        let parser = BgpkitParser::from_reader(Cursor::new(input.clone()));
        let yielded: Vec<Vec<u8>> = parser
            .into_filtered_raw_record_iter()
            .map(|(raw, _)| raw.raw_bytes().to_vec())
            .collect();
        assert_eq!(yielded.len(), 2);
        assert_eq!(yielded[0], input[..input.len() - upd.len()].to_vec());
        assert_eq!(yielded[1], upd);
    }

    #[test]
    fn filters_drop_no_elem_records_and_preserve_bytes() {
        let keep = keepalive(1);
        let upd = update(2);
        let mut input = keep.clone();
        input.extend_from_slice(&upd);

        let parser = BgpkitParser::from_reader(Cursor::new(input))
            .add_filter("prefix", "198.51.100.0/24")
            .unwrap();
        let yielded: Vec<(Vec<u8>, bool)> = parser
            .into_filtered_raw_record_iter()
            .map(|(raw, record)| (raw.raw_bytes().to_vec(), record.is_some()))
            .collect();

        // the keepalive is dropped; the update passes with byte-exact bytes
        // and its parse carried along (no re-parse needed downstream)
        assert_eq!(yielded.len(), 1);
        assert_eq!(yielded[0].0, upd);
        assert!(yielded[0].1);
    }
}
