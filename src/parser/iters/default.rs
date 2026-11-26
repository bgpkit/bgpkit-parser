/*!
Default iterator implementations that skip errors and return successfully parsed items.
*/
use crate::models::*;
use crate::parser::iters::{handle_record_parse_error, record_matches_filters};
use crate::parser::mrt::mrt_elem::PendingElems;
use crate::parser::BgpkitParser;
use crate::{Elementor, Filterable};
use std::io::Read;

#[cfg(test)]
mod tests;

/*********
MrtRecord Iterator
**********/

pub struct RecordIterator<R> {
    pub parser: BgpkitParser<R>,
    pub count: u64,
    elementor: Elementor,
    /// Whether the parser's filters are applied once per record.
    ///
    /// Elem iterators test every elem they build, so a record-level pass costs
    /// a full elem conversion per record (plus a record clone) that is thrown
    /// away. They construct this iterator with the pass disabled.
    prefilter: bool,
}

impl<R> RecordIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        RecordIterator {
            parser,
            count: 0,
            elementor: Elementor::new(),
            prefilter: true,
        }
    }

    /// Skip the record-level filter pass for an iterator whose consumer filters
    /// the elems it builds anyway.
    pub(crate) fn without_prefilter(mut self) -> Self {
        self.prefilter = false;
        self
    }
}

impl<R: Read> Iterator for RecordIterator<R> {
    type Item = MrtRecord;

    fn next(&mut self) -> Option<MrtRecord> {
        // Text-dump parsers have no MRT-record representation; short-circuit
        // instead of spinning forever on Unsupported errors from next_record().
        if self.parser.text_dump_iter.is_some() {
            return None;
        }
        self.count += 1;
        // A record whose single RIB prefix cannot satisfy a prefix filter yields no matching
        // elements, so it can be skipped before its body is parsed.
        let prefix_pushdown =
            crate::parser::filter::has_record_prefix_constraint(&self.parser.filters);
        loop {
            let next_record = if prefix_pushdown {
                self.parser.next_record_prefiltered()
            } else {
                self.parser.next_record()
            };
            return match next_record {
                Ok(v) => {
                    if !self.prefilter
                        || record_matches_filters(&v, &self.parser.filters, &mut self.elementor)
                    {
                        Some(v)
                    } else {
                        continue;
                    }
                }
                Err(e) => {
                    if handle_record_parse_error(&mut self.parser, e.error, e.bytes) {
                        continue;
                    }
                    None
                }
            };
        }
    }
}

/*********
BgpElem Iterator
**********/

pub struct ElemIterator<R> {
    pending: PendingElems,
    record_iter: RecordIterator<R>,
    elementor: Elementor,
    count: u64,
}

impl<R> ElemIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        ElemIterator {
            record_iter: RecordIterator::new(parser).without_prefilter(),
            count: 0,
            pending: PendingElems::Empty,
            elementor: Elementor::new(),
        }
    }
}

impl<R: Read> Iterator for ElemIterator<R> {
    type Item = BgpElem;

    fn next(&mut self) -> Option<BgpElem> {
        self.count += 1;

        // Fast path: drain streaming text-dump elems directly, with filter support.
        if let Some(iter) = &mut self.record_iter.parser.text_dump_iter {
            for elem in iter.by_ref() {
                if elem.match_filters(&self.record_iter.parser.filters) {
                    return Some(elem);
                }
            }
            return None;
        }

        loop {
            // drain the current record's elems before reading the next record
            while let Some(elem) = self.pending.next_elem(self.elementor.peer_table.as_ref()) {
                if elem.match_filters(&self.record_iter.parser.filters) {
                    return Some(elem);
                }
            }
            // records without elems leave nothing pending, and the loop moves on to the next
            let record = self.record_iter.next()?;
            self.pending = self.elementor.ingest(record);
        }
    }
}
