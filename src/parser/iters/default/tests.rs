//! Alignment tests for the skip-and-continue iterators: a rejected header must
//! leave the reader at a record boundary, or stop iteration when it cannot.

use crate::models::*;
use crate::parser::BgpkitParser;
use crate::{ParserError, RawMrtRecord};
use bytes::{BufMut, BytesMut};
use std::io::Cursor;

/// A record of type 0x7777 whose 20-byte body reads as a plausible common
/// header, so reading only the 12 header bytes would desynchronise the stream.
fn unknown_type_record() -> Vec<u8> {
    let mut wire = BytesMut::new();
    wire.put_u32(946_684_800);
    wire.put_u16(0x7777);
    wire.put_u16(0);
    wire.put_u32(20);
    wire.put_slice(&[0, 0, 0, 1, 0, 5, 0, 7, 0, 0, 0, 32]);
    wire.put_slice(&[0xaa; 8]);
    wire.to_vec()
}

/// A legacy BGP KEEPALIVE record (type BGP, subtype 7).
fn keepalive_record(timestamp: u32) -> Vec<u8> {
    let body = [0, 1, 192, 0, 2, 1, 0, 2, 192, 0, 2, 2];
    let header = CommonHeader {
        timestamp,
        microsecond_timestamp: None,
        entry_type: EntryType::BGP,
        entry_subtype: 7,
        length: body.len() as u32,
    };
    let mut wire = header.encode().to_vec();
    wire.extend_from_slice(&body);
    wire
}

/// A header declaring a body larger than the parser will read, followed by
/// bytes that would parse as a valid record if the iterator carried on.
fn oversized_record() -> Vec<u8> {
    let mut wire = BytesMut::new();
    wire.put_u32(1);
    wire.put_u16(EntryType::BGP as u16);
    wire.put_u16(7);
    wire.put_u32(17 * 1024 * 1024);
    wire.to_vec()
}

#[test]
fn record_iter_skips_unknown_entry_type_whole() {
    let mut wire = unknown_type_record();
    wire.extend_from_slice(&keepalive_record(946_684_801));
    wire.extend_from_slice(&keepalive_record(946_684_802));

    let records: Vec<MrtRecord> = BgpkitParser::from_reader(Cursor::new(wire))
        .into_record_iter()
        .collect();

    let timestamps: Vec<u32> = records
        .iter()
        .map(|record| record.common_header.timestamp)
        .collect();
    assert_eq!(timestamps, vec![946_684_801, 946_684_802]);
}

#[test]
fn raw_record_iter_skips_unknown_entry_type_whole() {
    let mut wire = unknown_type_record();
    wire.extend_from_slice(&keepalive_record(946_684_801));

    let records: Vec<RawMrtRecord> = BgpkitParser::from_reader(Cursor::new(wire))
        .into_raw_record_iter()
        .collect();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].common_header.timestamp, 946_684_801);
}

#[test]
fn record_iter_stops_at_oversized_length() {
    let mut wire = keepalive_record(946_684_801);
    wire.extend_from_slice(&oversized_record());
    wire.extend_from_slice(&keepalive_record(946_684_802));

    let records: Vec<MrtRecord> = BgpkitParser::from_reader(Cursor::new(wire))
        .into_record_iter()
        .collect();

    let timestamps: Vec<u32> = records
        .iter()
        .map(|record| record.common_header.timestamp)
        .collect();
    assert_eq!(timestamps, vec![946_684_801]);
}

#[test]
fn fallible_record_iter_yields_unknown_type_error_then_next_record() {
    let mut wire = unknown_type_record();
    wire.extend_from_slice(&keepalive_record(946_684_801));

    let mut iter = BgpkitParser::from_reader(Cursor::new(wire)).into_fallible_record_iter();

    let error = iter.next().expect("unknown-type error").unwrap_err();
    assert!(matches!(error.error, ParserError::ParseError(_)));
    assert_eq!(
        error.bytes.as_deref(),
        Some(unknown_type_record().as_slice())
    );
    let record = iter.next().expect("following record").unwrap();
    assert_eq!(record.common_header.timestamp, 946_684_801);
    assert!(iter.next().is_none());
}

#[test]
fn fallible_record_iter_ends_after_oversized_length() {
    let mut wire = oversized_record();
    wire.extend_from_slice(&keepalive_record(946_684_801));

    let mut iter = BgpkitParser::from_reader(Cursor::new(wire)).into_fallible_record_iter();

    let error = iter.next().expect("oversized error").unwrap_err();
    assert!(matches!(
        error.error,
        ParserError::OversizedRecord { length } if length == 17 * 1024 * 1024
    ));
    assert!(iter.next().is_none());
}
