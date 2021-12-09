/*!
Provides parser iterator implementation.
*/
use log::{error, warn};
use bgp_models::mrt::MrtRecord;
use crate::{BgpElem, Elementor};
use crate::error::ParserErrorKind;
use crate::parser::BgpkitParser;
use crate::Filterable;

/// Use [BgpElemIterator] as the default iterator to return [BgpElem]s instead of [MrtRecord]s.
impl IntoIterator for BgpkitParser {
    type Item = BgpElem;
    type IntoIter = ElemIterator;

    fn into_iter(self) -> Self::IntoIter {
        ElemIterator::new(self)
    }
}

impl BgpkitParser {
    pub fn into_record_iter(self) -> RecordIterator {
        RecordIterator::new(self)
    }
    pub fn into_elem_iter(self) -> ElemIterator {
        ElemIterator::new(self)
    }
}

/*********
MrtRecord Iterator
**********/

pub struct RecordIterator {
    pub parser: BgpkitParser,
    pub count: u64,
}

impl RecordIterator {
    fn new(parser: BgpkitParser) -> RecordIterator {
        RecordIterator {
            parser , count: 0,
        }
    }
}

impl Iterator for RecordIterator {
    type Item = MrtRecord;

    fn next(&mut self) -> Option<MrtRecord> {
        self.count += 1;
        match self.parser.next() {
            Ok(v) => {
                // if None, the reaches EoF.
                Some(v)
            },
            Err(e) => {
                match e.error {
                    ParserErrorKind::TruncatedMsg(e)| ParserErrorKind::Unsupported(e)
                    | ParserErrorKind::UnknownAttr(e) | ParserErrorKind::Deprecated(e) => {
                        warn!("Parsing error: {}", e);
                        self.next()
                    }
                    ParserErrorKind::ParseError(err_str) => {
                        warn!("Parsing error: {}", err_str);
                        if self.parser.core_dump {
                            if let Some(bytes) = e.bytes {
                                std::fs::write("mrt_cord_dump", bytes).expect("Unable to write to mrt_core_dump");
                            }
                            None
                        } else {
                            self.next()
                        }
                    }
                    ParserErrorKind::EofExpected =>{
                        // normal end of file
                        None
                    }
                    ParserErrorKind::IoError(err)| ParserErrorKind::EofError(err) => {
                        // when reaching IO error, stop iterating
                        error!("{:?}", err);
                        if self.parser.core_dump {
                            if let Some(bytes) = e.bytes {
                                std::fs::write("mrt_core_dump", bytes).expect("Unable to write to mrt_core_dump");
                            }
                        }
                        None
                    }
                    ParserErrorKind::RemoteIoError(_) | ParserErrorKind::FilterError(_)=> {
                        // this should not happen at this stage
                        None
                    }
                }
            },
        }
    }
}

/*********
BgpElem Iterator
**********/

pub struct ElemIterator {
    cache_elems: Vec<BgpElem>,
    record_iter: RecordIterator,
    elementor: Elementor,
    count: u64,
}

impl ElemIterator {
    fn new(parser: BgpkitParser) -> ElemIterator {
        ElemIterator { record_iter: RecordIterator::new(parser) , count: 0 , cache_elems: vec![], elementor: Elementor::new()}
    }
}

impl Iterator for ElemIterator {
    type Item = BgpElem;

    fn next(&mut self) -> Option<BgpElem> {
        self.count += 1;

        if self.cache_elems.is_empty() {
            // refill cache elems
            loop {
                match self.record_iter.next() {
                    None => {
                        // no more records
                        return None
                    }
                    Some(r) => {
                        let mut elems =  self.elementor.record_to_elems(r);
                        if elems.len()>0 {
                            elems.reverse();
                            self.cache_elems = elems;
                            break
                        } else {
                            // somehow this record does not contain any elems, continue to parse next record
                            continue
                        }
                    }
                }
            }
            // when reaching here, the `self.cache_elems` has been refilled with some more elems
        }

        // popping cached elems. note that the original elems order is preseved by reversing the
        // vector before putting it on to cache_elems.
        let elem = match self.cache_elems.pop() {
            None => {None}
            Some(i) => {Some(i)}
        };
        match elem {
            None => None,
            Some(e) => match e.match_filters(&self.record_iter.parser.filters) {
                true => {Some(e)}
                false => {self.next()}
            }
        }
    }
}
