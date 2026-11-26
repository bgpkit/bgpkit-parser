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
        let record_pushdown =
            crate::parser::filter::has_record_prefix_constraint(&self.parser.filters)
                || crate::parser::filter::has_record_peer_constraint(&self.parser.filters)
                || crate::parser::filter::has_record_timestamp_constraint(&self.parser.filters)
                || crate::parser::filter::has_record_type_constraint(&self.parser.filters);
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

/// What one refill attempt produced.
enum Refill {
    /// `batch` now holds elements to drain.
    Batch,
    /// One record was ingested into `pending`; continue with the owned path.
    Owned,
    /// No more records.
    End,
}

pub struct ElemIterator<R> {
    pending: PendingElems,
    /// Elements materialised from one borrowed RIB record, drained before the owned path.
    batch: std::vec::IntoIter<BgpElem>,
    /// Whether the borrowed RIB engine may still serve this stream. Turned off for good as soon as
    /// a record it cannot serve appears, so a mixed stream never re-reads a record.
    borrowed: bool,
    record_iter: RecordIterator<R>,
    elementor: Elementor,
    count: u64,
}

impl<R> ElemIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        // The borrowed engine applies no filters and needs the parser's own record buffer, so it is
        // only used when nothing else has claimed either.
        let borrowed = parser.filters.is_empty() && !parser.core_dump;
        ElemIterator {
            record_iter: RecordIterator::new(parser).without_prefilter(),
            count: 0,
            pending: PendingElems::Empty,
            batch: Vec::new().into_iter(),
            borrowed,
            elementor: Elementor::new(),
        }
    }
}

impl<R: Read> ElemIterator<R> {
    /// Refill `batch` from the borrowed RIB engine, or fall back to the owned path for one record.
    fn refill(&mut self) -> Refill {
        use crate::parser::iters::elem_ref::NextBatch;

        match self.record_iter.parser.next_elem_batch() {
            NextBatch::Rib(mut record) => {
                let mut elems = Vec::with_capacity(record.len());
                for elem in record.iter() {
                    elems.push(elem.to_bgp_elem());
                }
                self.batch = elems.into_iter();
                Refill::Batch
            }
            NextBatch::Other { header, body_len } => {
                // Not a RIB dump record: parse it the owned way and let the owned iterator take
                // over the rest of the stream.
                self.borrowed = false;
                match self
                    .record_iter
                    .parser
                    .parse_framed_record(header, body_len)
                {
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
            NextBatch::End => {
                self.borrowed = false;
                Refill::End
            }
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

        // Unfiltered RIB dumps are served straight from the borrowed record view: no intermediate
        // MrtRecord, no per-entry attribute model.
        if self.borrowed {
            if let Some(elem) = self.batch.next() {
                return Some(elem);
            }
            loop {
                match self.refill() {
                    Refill::Batch => {
                        if let Some(elem) = self.batch.next() {
                            return Some(elem);
                        }
                    }
                    Refill::Owned => break,
                    Refill::End => return None,
                }
            }
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
