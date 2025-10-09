/*!
Iterator implementations for bgpkit-parser.

This module contains different iterator implementations for parsing BGP data:
- `default`: Standard iterators that skip errors (RecordIterator, ElemIterator)
- `fallible`: Fallible iterators that return Results (FallibleRecordIterator, FallibleElemIterator)

It also contains the trait implementations that enable BgpkitParser to be used with
Rust's iterator syntax.
*/

pub mod default;
pub mod fallible;
mod raw;

// Re-export all iterator types for convenience
pub use default::{ElemIterator, RecordIterator};
pub use fallible::{FallibleElemIterator, FallibleRecordIterator};
pub use raw::RawRecordIterator;

use crate::models::BgpElem;
use crate::parser::BgpkitParser;
use std::io::Read;

/// Use [ElemIterator] as the default iterator to return [BgpElem]s instead of [MrtRecord]s.
impl<R: Read> IntoIterator for BgpkitParser<R> {
    type Item = BgpElem;
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

    pub fn into_raw_record_iter(self) -> RawRecordIterator<R> {
        RawRecordIterator::new(self)
    }

    /// Creates a fallible iterator over MRT records that returns parsing errors.
    ///
    /// # Example
    /// ```no_run
    /// use bgpkit_parser::BgpkitParser;
    ///
    /// let parser = BgpkitParser::new("updates.mrt").unwrap();
    /// for result in parser.into_fallible_record_iter() {
    ///     match result {
    ///         Ok(record) => {
    ///             // Process the record
    ///         }
    ///         Err(e) => {
    ///             // Handle the error
    ///             eprintln!("Error parsing record: {}", e);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn into_fallible_record_iter(self) -> FallibleRecordIterator<R> {
        FallibleRecordIterator::new(self)
    }

    /// Creates a fallible iterator over BGP elements that returns parsing errors.
    ///
    /// # Example
    /// ```no_run
    /// use bgpkit_parser::BgpkitParser;
    ///
    /// let parser = BgpkitParser::new("updates.mrt").unwrap();
    /// for result in parser.into_fallible_elem_iter() {
    ///     match result {
    ///         Ok(elem) => {
    ///             // Process the element
    ///         }
    ///         Err(e) => {
    ///             // Handle the error
    ///             eprintln!("Error parsing element: {}", e);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn into_fallible_elem_iter(self) -> FallibleElemIterator<R> {
        FallibleElemIterator::new(self)
    }
}
