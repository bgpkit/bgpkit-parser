/*!
Default iterator implementations that skip errors and return successfully parsed items.
*/
use crate::models::*;
use crate::parser::iters::{handle_record_parse_error, record_matches_filters};
use crate::parser::mrt::mrt_elem::PendingElems;
use crate::parser::BgpkitParser;
use crate::{Elementor, Filterable};
use std::io::Read;

/*********
MrtRecord Iterator
**********/

pub struct RecordIterator<R> {
    pub parser: BgpkitParser<R>,
    pub count: u64,
    elementor: Elementor,
}

impl<R> RecordIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        RecordIterator {
            parser,
            count: 0,
            elementor: Elementor::new(),
        }
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
        loop {
            return match self.parser.next_record() {
                Ok(v) => {
                    if record_matches_filters(&v, &self.parser.filters, &mut self.elementor) {
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
            record_iter: RecordIterator::new(parser),
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
