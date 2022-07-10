use std::io::Read;
use bgp_models::mrt::MrtRecord;

#[macro_use]
pub mod utils;
pub mod mrt;
pub mod bmp;
pub mod bgp;
pub mod iters;
pub mod rislive;
pub mod filter;

pub(crate) use self::utils::*;
pub(crate) use bgp::attributes::AttributeParser;
pub(crate) use mrt::{parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message, parse_mrt_record, };

pub use crate::error::{ParserError, ParserErrorKind};
pub use mrt::mrt_elem::Elementor;
use bgp_models::prelude::ElemType;
use crate::Filter;
use crate::io::get_reader;

pub struct BgpkitParser {
    reader: Box<dyn Read>,
    core_dump: bool,
    filters: Vec<Filter>,
    options: ParserOptions
}

pub(crate) struct ParserOptions {
    show_warnings: bool
}
impl Default for ParserOptions {
    fn default() -> Self {
        ParserOptions{
            show_warnings: true
        }
    }
}

unsafe impl Send for BgpkitParser {}

impl BgpkitParser {
    /// Creating a new parser from a object that implements [Read] trait.
    pub fn new(path: &str) -> Result<BgpkitParser, ParserError>{
        let reader = get_reader(path)?;
        Ok(
            BgpkitParser{
                reader,
                core_dump: false,
                filters: vec![],
                options: ParserOptions::default()
            }
        )
    }

    pub fn enable_core_dump(self) -> BgpkitParser {
        BgpkitParser{
            reader: self.reader,
            core_dump: true,
            filters: self.filters,
            options: self.options
        }
    }

    pub fn disable_unknown_attr_warning(self) -> BgpkitParser {
        let mut options = self.options;
        options.disable_warning = true;
        BgpkitParser{
            reader: self.reader,
            core_dump: self.core_dump,
            filters: self.filters,
            options
        }
    }

    pub fn add_filter(self, filter_type: &str, filter_value: &str) -> Result<BgpkitParser, ParserError> {
        let mut filters = self.filters;
        filters.push(Filter::new(filter_type, filter_value)?);
        Ok(
            BgpkitParser {
                reader: self.reader,
                core_dump: self.core_dump,
                filters,
                options: ParserOptions::default()
            }
        )
    }

    /// This is used in for loop `for item in parser{}`
    pub fn next(&mut self) -> Result<MrtRecord, ParserError> {
        parse_mrt_record(&mut self.reader)
    }
}


