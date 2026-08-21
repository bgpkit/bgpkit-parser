/*!
Default iterator implementations that skip errors and return successfully parsed items.
*/
use crate::models::*;
use crate::parser::iters::{handle_record_parse_error, record_matches_filters};
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
    cache_elems: Vec<BgpElem>,
    record_iter: RecordIterator<R>,
    elementor: Elementor,
    count: u64,
}

impl<R> ElemIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        ElemIterator {
            record_iter: RecordIterator::new(parser),
            count: 0,
            cache_elems: vec![],
            elementor: Elementor::new(),
        }
    }
}

impl<R: Read> Iterator for ElemIterator<R> {
    type Item = BgpElem;

    fn next(&mut self) -> Option<BgpElem> {
        self.count += 1;

        loop {
            // Fast path: drain streaming text-dump elems directly, with filter support.
            if let Some(iter) = &mut self.record_iter.parser.text_dump_iter {
                for elem in iter.by_ref() {
                    if elem.match_filters(&self.record_iter.parser.filters) {
                        return Some(elem);
                    }
                }
                return None;
            }

            if self.cache_elems.is_empty() {
                // refill cache elems
                loop {
                    match self.record_iter.next() {
                        None => {
                            // no more records
                            return None;
                        }
                        Some(r) => {
                            let mut elems = self.elementor.record_to_elems(r);
                            if elems.is_empty() {
                                // somehow this record does not contain any elems, continue to parse next record
                                continue;
                            } else {
                                elems.reverse();
                                self.cache_elems = elems;
                                break;
                            }
                        }
                    }
                }
                // when reaching here, the `self.cache_elems` has been refilled with some more elems
            }

            // popping cached elems. note that the original elems order is preseved by reversing the
            // vector before putting it on to cache_elems.
            let elem = self.cache_elems.pop()?;
            if elem.match_filters(&self.record_iter.parser.filters) {
                return Some(elem);
            }
        }
    }
}
