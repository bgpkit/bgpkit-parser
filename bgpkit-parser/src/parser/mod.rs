use std::io::Read;

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
pub(crate) use mrt::{parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message, parse_mrt_record};

pub use crate::error::{ParserErrorWithBytes, ParserError};
pub use mrt::mrt_elem::Elementor;
use bgp_models::prelude::MrtRecord;
use oneio::get_reader;
use crate::Filter;

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
    pub fn new(path: &str) -> Result<BgpkitParser, ParserErrorWithBytes>{
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

    /// Creating a new parser from a object that implements [Read] trait.
    pub fn new_with_reader(reader: Box<dyn Read>) -> Result<BgpkitParser, ParserErrorWithBytes>{
        Ok(
            BgpkitParser{
                reader: Box::new(reader),
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

    pub fn disable_warnings(self) -> BgpkitParser {
        let mut options = self.options;
        options.show_warnings = false;
        BgpkitParser{
            reader: self.reader,
            core_dump: self.core_dump,
            filters: self.filters,
            options
        }
    }

    pub fn add_filter(self, filter_type: &str, filter_value: &str) -> Result<BgpkitParser, ParserErrorWithBytes> {
        let mut filters = self.filters;
        filters.push(Filter::new(filter_type, filter_value)?);
        Ok(
            BgpkitParser {
                reader: self.reader,
                core_dump: self.core_dump,
                filters,
                options: self.options
            }
        )
    }

    /// This is used in for loop `for item in parser{}`
    pub fn next_record(&mut self) -> Result<MrtRecord, ParserErrorWithBytes> {
        parse_mrt_record(&mut self.reader)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_reader() {
        // bzip2 reader for compressed file
        let http_stream = ureq::get("http://archive.routeviews.org/route-views.ny/bgpdata/2023.02/UPDATES/updates.20230215.0630.bz2")
            .call().unwrap().into_reader();
        let reader = Box::new(
            bzip2::read::BzDecoder::new(http_stream)
        );
        assert_eq!(12683, BgpkitParser::new_with_reader(reader).unwrap().into_elem_iter().count());

        // remote reader for uncompressed updates file
        let reader = ureq::get("https://spaces.bgpkit.org/parser/update-example")
            .call().unwrap().into_reader();
        assert_eq!(8160, BgpkitParser::new_with_reader(reader).unwrap().into_elem_iter().count());
    }
}

