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
        // A record skipped here never raises its parse error, and core-dump mode stops at the
        // first one, so pushdown is off while dumping.
        let record_pushdown = !self.parser.core_dump
            && crate::parser::filter::has_record_level_constraint(&self.parser.filters);
        loop {
            let next_record = if record_pushdown {
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

/// What one framed record produced for the element iterator.
enum Refill {
    /// `batch` now holds elements to drain.
    Batch,
    /// The record went to the owned path, which filled `pending`.
    Owned,
    /// End of input, or an error the parser cannot recover from.
    End,
}

pub struct ElemIterator<R> {
    pending: PendingElems,
    /// Rejects an entry before its element is built, when a predicate can decide it from attributes.
    screen: Option<std::sync::Arc<crate::parser::attr_scan::EntryScreen>>,
    /// Elements materialised from one borrowed RIB record, drained before anything else.
    batch: std::vec::IntoIter<BgpElem>,
    /// Whether records are dispatched per frame. A core dump needs the owned iterator to read the
    /// stream itself, because it has to hand back the bytes around a parse error.
    framed: bool,
    record_iter: RecordIterator<R>,
    elementor: Elementor,
    count: u64,
}

impl<R> ElemIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        // The framed path reads records through the parser's own buffer; the element loop applies
        // the screen and the filters to what it produces.
        let framed = !parser.core_dump;
        let screen =
            crate::parser::attr_scan::EntryScreen::new(&parser.filters).map(std::sync::Arc::new);
        ElemIterator {
            screen,
            record_iter: RecordIterator::new(parser).without_prefilter(),
            count: 0,
            pending: PendingElems::Empty,
            batch: Vec::new().into_iter(),
            framed,
            elementor: Elementor::new(),
        }
    }
}

impl<R: Read> ElemIterator<R> {
    /// Read one framed record and route it: RIB dump records are materialised from the borrowed
    /// view, everything else is parsed by the owned path.
    fn refill(&mut self) -> Refill {
        use crate::parser::iters::elem_ref::NextBatch;

        match self.record_iter.parser.next_elem_batch() {
            NextBatch::Rib(record) => {
                // The declared entry count is attacker-controlled; cap the reservation so a
                // malformed record cannot ask for a large allocation per record.
                let mut elems = Vec::with_capacity(record.len().min(1024));
                let screen = self.screen.clone();
                for elem in record.iter() {
                    // An entry the screen can reject from its bytes never becomes an element.
                    if let Some(screen) = screen.as_deref() {
                        if !screen.admits_bytes(elem.attrs_bytes()) {
                            continue;
                        }
                    }
                    elems.push(elem.to_bgp_elem());
                }
                // The loop above is the last use of `record`, so its borrow of the parser's
                // buffers has ended and the filters can be read here.
                let filters = &self.record_iter.parser.filters;
                if !filters.is_empty() {
                    elems.retain(|elem| elem.match_filters(filters));
                }
                self.batch = elems.into_iter();
                Refill::Batch
            }
            NextBatch::Other {
                header,
                raw_header,
                body_len,
            } => {
                match self.record_iter.parser.parse_framed_record(
                    header,
                    raw_header.as_slice(),
                    body_len,
                ) {
                    Ok(record) => {
                        self.pending = self.elementor.ingest(record);
                        Refill::Owned
                    }
                    Err(failure) => {
                        if handle_record_parse_error(
                            &mut self.record_iter.parser,
                            failure.error,
                            failure.bytes,
                        ) {
                            Refill::Owned
                        } else {
                            Refill::End
                        }
                    }
                }
            }
            NextBatch::End => Refill::End,
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
            // Anything already produced comes out first: materialised RIB elements, then the owned
            // iterator's pending elements.
            if let Some(elem) = self.batch.next() {
                return Some(elem);
            }
            while let Some(elem) = self.pending.next_elem(self.elementor.peer_table.as_ref()) {
                if elem.match_filters(&self.record_iter.parser.filters) {
                    return Some(elem);
                }
            }

            if self.framed {
                match self.refill() {
                    Refill::Batch | Refill::Owned => continue,
                    Refill::End => return None,
                }
            }
            let record = self.record_iter.next()?;
            // This branch is core-dump mode: it builds every element and lets the filter decide.
            self.pending = self.elementor.ingest(record);
        }
    }
}
