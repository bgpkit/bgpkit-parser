use std::io::Read;

#[macro_use]
pub mod utils;
pub mod bgp;
pub mod bmp;
pub mod filter;
pub mod iters;
pub mod mrt;
pub mod rislive;

pub(crate) use self::utils::*;
pub(crate) use bgp::attributes::AttributeParser;
pub(crate) use mrt::{
    parse_bgp4mp, parse_mrt_record, parse_table_dump_message, parse_table_dump_v2_message,
};

pub use crate::error::{ParserError, ParserErrorWithBytes};
use crate::Filter;
use bgp_models::prelude::MrtRecord;
pub use mrt::mrt_elem::Elementor;
use oneio::get_reader;

pub struct BgpkitParser<R> {
    reader: R,
    core_dump: bool,
    filters: Vec<Filter>,
    options: ParserOptions,
}

pub(crate) struct ParserOptions {
    show_warnings: bool,
}
impl Default for ParserOptions {
    fn default() -> Self {
        ParserOptions {
            show_warnings: true,
        }
    }
}

impl BgpkitParser<Box<dyn Read + Send>> {
    /// Creating a new parser from a object that implements [Read] trait.
    pub fn new(path: &str) -> Result<Self, ParserErrorWithBytes> {
        let reader = get_reader(path)?;
        Ok(BgpkitParser {
            reader,
            core_dump: false,
            filters: vec![],
            options: ParserOptions::default(),
        })
    }
}

impl<R: Read> BgpkitParser<R> {
    /// Creating a new parser from a object that implements [Read] trait.
    pub fn from_reader(reader: R) -> Self {
        BgpkitParser {
            reader,
            core_dump: false,
            filters: vec![],
            options: ParserOptions::default(),
        }
    }

    /// This is used in for loop `for item in parser{}`
    pub fn next_record(&mut self) -> Result<MrtRecord, ParserErrorWithBytes> {
        parse_mrt_record(&mut self.reader)
    }
}

impl<R> BgpkitParser<R> {
    pub fn enable_core_dump(self) -> Self {
        BgpkitParser {
            reader: self.reader,
            core_dump: true,
            filters: self.filters,
            options: self.options,
        }
    }

    pub fn disable_warnings(self) -> Self {
        let mut options = self.options;
        options.show_warnings = false;
        BgpkitParser {
            reader: self.reader,
            core_dump: self.core_dump,
            filters: self.filters,
            options,
        }
    }

    pub fn add_filter(
        self,
        filter_type: &str,
        filter_value: &str,
    ) -> Result<Self, ParserErrorWithBytes> {
        let mut filters = self.filters;
        filters.push(Filter::new(filter_type, filter_value)?);
        Ok(BgpkitParser {
            reader: self.reader,
            core_dump: self.core_dump,
            filters,
            options: self.options,
        })
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
        let reader = bzip2::read::BzDecoder::new(http_stream);
        assert_eq!(
            12683,
            BgpkitParser::from_reader(reader).into_elem_iter().count()
        );

        // remote reader for uncompressed updates file
        let reader = ureq::get("https://spaces.bgpkit.org/parser/update-example")
            .call()
            .unwrap()
            .into_reader();
        assert_eq!(
            8160,
            BgpkitParser::from_reader(reader).into_elem_iter().count()
        );
    }
}
