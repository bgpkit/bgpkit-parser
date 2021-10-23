use std::io::Read;
use bgp_models::mrt::MrtRecord;

#[macro_use]
pub(crate) mod utils;
pub(crate) mod mrt;
pub(crate) mod bgp;
pub(crate) mod iters;

pub(crate) use self::utils::*;
pub(crate) use bgp::attributes::AttributeParser;
pub(crate) use mrt::{parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message, parse_mrt_record, };

pub use crate::error::ParserError;
pub use mrt::mrt_elem::{BgpElem, Elementor, ElemType};

pub struct BgpkitParser<T: Read> {
    input: T,
}

impl<T: Read> BgpkitParser<T> {
    pub fn new(input: T) -> BgpkitParser<T> {
        BgpkitParser {
            // input: Some(BufReader::new(input)),
            input: input,
        }
    }

    /// This is used in for loop `for item in parser{}`
    pub fn next(&mut self) -> Result<MrtRecord, ParserError> {
        parse_mrt_record(&mut self.input)
    }
}

