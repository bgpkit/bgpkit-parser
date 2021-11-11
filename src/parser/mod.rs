use std::io::Read;
use bgp_models::mrt::MrtRecord;

#[macro_use]
pub mod utils;
pub mod mrt;
pub mod bmp;
pub mod bgp;
pub mod iters;
pub mod rislive;

pub(crate) use self::utils::*;
pub(crate) use bgp::attributes::AttributeParser;
pub(crate) use mrt::{parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message, parse_mrt_record, };

pub use crate::error::ParserError;
pub use mrt::mrt_elem::{BgpElem, Elementor, ElemType};
use crate::io::get_reader;

pub struct BgpkitParser {
    reader: Box<dyn Read>
}

impl BgpkitParser {
    /// Creating a new parser from a object that implements [Read] trait.
    pub fn new(path: &str) -> BgpkitParser{
        BgpkitParser{
            reader: get_reader(path)
        }
    }

    /// This is used in for loop `for item in parser{}`
    pub fn next(&mut self) -> Result<MrtRecord, ParserError> {
        parse_mrt_record(&mut self.reader)
    }
}


