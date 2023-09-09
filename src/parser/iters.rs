/*!
Provides parser iterator implementation.
*/
use crate::error::ParserError;
use crate::models::*;
use crate::mrt_record::try_parse_mrt_record_with_buffer;
use crate::parser::BgpkitParser;
use crate::{Elementor, Filterable};
use std::io::Read;

/// Use [ElemIterator] as the default iterator to return [BgpElem]s instead of [MrtRecord]s.
impl<R: Read> IntoIterator for BgpkitParser<R> {
    type Item = Result<BgpElem, ParserError>;
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
}

/*********
MrtRecord Iterator
**********/

pub struct RecordIterator<R> {
    pub parser: BgpkitParser<R>,
    pub count: u64,
    elementor: Elementor,
    had_fatal_error: bool,
    buffer: Vec<u8>,
}

impl<R> RecordIterator<R> {
    fn new(parser: BgpkitParser<R>) -> Self {
        RecordIterator {
            parser,
            count: 0,
            elementor: Elementor::new(),
            had_fatal_error: false,
            buffer: Vec::with_capacity(4096),
        }
    }
}

impl<R: Read> Iterator for RecordIterator<R> {
    type Item = Result<MrtRecord, ParserError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.had_fatal_error {
            return None;
        }

        loop {
            self.count += 1;
            let record =
                match try_parse_mrt_record_with_buffer(&mut self.parser.reader, &mut self.buffer) {
                    Ok(None) => return None,
                    Ok(Some(v)) => v,
                    Err(err @ (ParserError::IoError(_) | ParserError::UnrecognizedMrtType(_))) => {
                        self.had_fatal_error = true;
                        return Some(Err(err));
                    }
                    Err(err) => return Some(Err(err)),
                };

            if self.parser.filters.is_empty() {
                return Some(Ok(record));
            }

            if let MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(_)) =
                &record.message
            {
                let _ = self.elementor.record_to_elems(record.clone());
                return Some(Ok(record));
            }

            let elems = self.elementor.record_to_elems(record.clone());
            if elems.iter().any(|e| e.match_filters(&self.parser.filters)) {
                return Some(Ok(record));
            }
        }
    }
}

/*********
BgpElem Iterator
**********/

pub struct ElemIterator<R> {
    parser: BgpkitParser<R>,
    element_queue: Vec<BgpElem>,
    elementor: Elementor,
    had_fatal_error: bool,
    buffer: Vec<u8>,
}

impl<R> ElemIterator<R> {
    fn new(parser: BgpkitParser<R>) -> Self {
        ElemIterator {
            parser,
            element_queue: vec![],
            elementor: Elementor::new(),
            had_fatal_error: false,
            buffer: Vec::with_capacity(4096),
        }
    }
}

impl<R: Read> Iterator for ElemIterator<R> {
    type Item = Result<BgpElem, ParserError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(element) = self.element_queue.pop() {
                return Some(Ok(element));
            }

            if self.had_fatal_error {
                return None;
            }

            let record =
                match try_parse_mrt_record_with_buffer(&mut self.parser.reader, &mut self.buffer) {
                    Ok(None) => return None,
                    Ok(Some(v)) => v,
                    Err(err @ (ParserError::IoError(_) | ParserError::UnrecognizedMrtType(_))) => {
                        self.had_fatal_error = true;
                        return Some(Err(err));
                    }
                    Err(err) => return Some(Err(err)),
                };

            let new_elements = self.elementor.record_to_elems(record);
            self.element_queue.extend(new_elements.into_iter().rev());
            self.element_queue
                .retain(|element| element.match_filters(&self.parser.filters));
        }
    }
}
