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

pub use crate::error::{ParserError, ParserErrorKind};
pub use mrt::mrt_elem::Elementor;
pub use bgp_models::prelude::{BgpElem, ElemType};
use crate::io::get_reader;

pub struct BgpkitParser {
    reader: Box<dyn Read>,
    core_dump: bool,
}

impl BgpkitParser {
    /// Creating a new parser from a object that implements [Read] trait.
    pub fn new(path: &str) -> Result<BgpkitParser, ParserError>{
        let reader = get_reader(path)?;
        Ok(
            BgpkitParser{
                reader,
                core_dump: false
            }
        )
    }

    pub fn enable_core_dump(self) -> BgpkitParser {
        BgpkitParser{
            reader: self.reader,
            core_dump: true
        }
    }

    /// This is used in for loop `for item in parser{}`
    pub fn next(&mut self) -> Result<MrtRecord, ParserError> {
        parse_mrt_record(&mut self.reader)
    }
}


