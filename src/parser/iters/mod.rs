/*!
Iterator implementations for bgpkit-parser.

This module contains different iterator implementations for parsing BGP data:
- `default`: Standard iterators that skip errors (RecordIterator, ElemIterator)
- `fallible`: Fallible iterators that return Results (FallibleRecordIterator, FallibleElemIterator)
- `update`: Iterators for BGP UPDATE messages (UpdateIterator, FallibleUpdateIterator)

It also contains the trait implementations that enable BgpkitParser to be used with
Rust's iterator syntax.
*/

pub mod default;
pub mod fallible;
mod raw;
mod update;

// Re-export all iterator types for convenience
pub use default::{ElemIterator, RecordIterator};
pub use fallible::{FallibleElemIterator, FallibleRecordIterator};
pub use raw::RawRecordIterator;
pub use update::{
    Bgp4MpUpdate, FallibleUpdateIterator, MrtUpdate, TableDumpV2Entry, UpdateIterator,
};

use crate::models::BgpElem;
use crate::models::{MrtMessage, MrtRecord, TableDumpV2Message};
use crate::parser::BgpkitParser;
use crate::Elementor;
use crate::RawMrtRecord;
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

    /// Creates an iterator over BGP announcements from MRT data.
    ///
    /// This iterator yields `MrtUpdate` items from both UPDATES files (BGP4MP messages)
    /// and RIB dump files (TableDump/TableDumpV2 messages). It's a middle ground
    /// between `into_record_iter()` and `into_elem_iter()`:
    ///
    /// - More focused than `into_record_iter()` as it only returns BGP announcements
    /// - More efficient than `into_elem_iter()` as it doesn't duplicate attributes per prefix
    ///
    /// The iterator returns an `MrtUpdate` enum with variants:
    /// - `Bgp4MpUpdate`: BGP UPDATE messages from UPDATES files
    /// - `TableDumpV2Entry`: RIB entries from TableDumpV2 RIB dumps
    /// - `TableDumpMessage`: Legacy TableDump v1 messages
    ///
    /// # Example
    /// ```no_run
    /// use bgpkit_parser::{BgpkitParser, MrtUpdate};
    ///
    /// let parser = BgpkitParser::new("updates.mrt").unwrap();
    /// for update in parser.into_update_iter() {
    ///     match update {
    ///         MrtUpdate::Bgp4MpUpdate(u) => {
    ///             println!("Peer {} announced {} prefixes",
    ///                 u.peer_ip,
    ///                 u.message.announced_prefixes.len()
    ///             );
    ///         }
    ///         MrtUpdate::TableDumpV2Entry(e) => {
    ///             println!("RIB entry for {} with {} peers",
    ///                 e.prefix,
    ///                 e.rib_entries.len()
    ///             );
    ///         }
    ///         MrtUpdate::TableDumpMessage(m) => {
    ///             println!("Legacy table dump for {}", m.prefix);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn into_update_iter(self) -> UpdateIterator<R> {
        UpdateIterator::new(self)
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

    /// Creates a fallible iterator over BGP announcements that returns parsing errors.
    ///
    /// Unlike the default `into_update_iter()`, this iterator returns
    /// `Result<MrtUpdate, ParserErrorWithBytes>` allowing users to handle parsing
    /// errors explicitly instead of having them logged and skipped.
    ///
    /// # Example
    /// ```no_run
    /// use bgpkit_parser::{BgpkitParser, MrtUpdate};
    ///
    /// let parser = BgpkitParser::new("updates.mrt").unwrap();
    /// for result in parser.into_fallible_update_iter() {
    ///     match result {
    ///         Ok(MrtUpdate::Bgp4MpUpdate(update)) => {
    ///             println!("Peer {} announced {} prefixes",
    ///                 update.peer_ip,
    ///                 update.message.announced_prefixes.len()
    ///             );
    ///         }
    ///         Ok(_) => { /* handle other variants */ }
    ///         Err(e) => {
    ///             eprintln!("Error parsing: {}", e);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn into_fallible_update_iter(self) -> FallibleUpdateIterator<R> {
        FallibleUpdateIterator::new(self)
    }

    /// Creates an Elementor pre-initialized with PeerIndexTable and an iterator over raw records.
    ///
    /// This is useful for parallel processing where the Elementor needs to be shared across threads.
    /// The Elementor is created with the PeerIndexTable from the first record if present,
    /// otherwise a new Elementor is created.
    ///
    /// # Example
    /// See the `parallel_records_to_elem` example for full usage.
    /// ```ignore
    /// use bgpkit_parser::BgpkitParser;
    ///
    /// let parser = BgpkitParser::new_cached(url, "/tmp")?;
    /// let (elementor, records) = parser.into_elementor_and_raw_record_iter();
    /// ```
    ///
    pub fn into_elementor_and_raw_record_iter(
        self,
    ) -> (Elementor, impl Iterator<Item = RawMrtRecord>)
    where
        R: Read,
    {
        let mut raw_iter = RawRecordIterator::new(self).peekable();
        let elementor = match raw_iter.peek().cloned().and_then(|r| r.parse().ok()) {
            Some(MrtRecord {
                message: MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(pit)),
                ..
            }) => {
                raw_iter.next();
                Elementor::with_peer_table(pit)
            }
            _ => Elementor::new(),
        };
        (elementor, raw_iter)
    }

    /// Creates an Elementor pre-initialized with PeerIndexTable and an iterator over parsed records.
    ///
    /// This is useful for parallel processing where the Elementor needs to be shared across threads.
    /// The Elementor is created with the PeerIndexTable from the first record if present,
    /// otherwise a new Elementor is created.
    ///
    /// # Example
    /// See the `parallel_records_to_elem` example for full usage.
    pub fn into_elementor_and_record_iter(self) -> (Elementor, impl Iterator<Item = MrtRecord>)
    where
        R: Read,
    {
        let mut record_iter = RecordIterator::new(self).peekable();
        let elementor = match record_iter.peek().cloned() {
            Some(MrtRecord {
                message: MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(pit)),
                ..
            }) => {
                record_iter.next();
                Elementor::with_peer_table(pit)
            }
            _ => Elementor::new(),
        };
        (elementor, record_iter)
    }
}
