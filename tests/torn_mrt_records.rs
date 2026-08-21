//! Regression coverage for torn MRT writes in the early RIPE RIS archive.
//!
//! `rrc00/2000.03/updates.20000325.0345.gz` is physically corrupt: the historical
//! collector emitted two short writes into an otherwise well-formed stream. The
//! damage is confined to the first ~4.6 KiB of the 151,804-byte uncompressed body,
//! but the parser cannot resynchronize past either one, so it recovers 4 of the
//! file's 2,580 records.
//!
//! **Offset 188 — a 10-byte truncated record header:**
//!
//! ```text
//! 38 dc 36 68  00 05  00 01  00 00 | 38 dc 36 71 00 05 00 03 ...
//! ^timestamp   ^BGP   ^UPDATE ^only 2 of the 4 Length bytes
//!  953955944    (5)    (1)                       ^next record starts here
//! ```
//!
//! The writer stopped after 10 of the 12 header bytes. The parser therefore reads
//! `Length` as the four bytes `00 00 38 dc`, whose low half is stolen from the next
//! record's timestamp (`0x38dc3671`), giving 14,556. It consumes 14,556 bytes —
//! roughly 200 real records — and fails with [`ParserError::TruncatedMsg`], leaving
//! the reader at offset 14,756, which is not a record boundary.
//!
//! **Offset 4554 — 14 orphan body bytes:**
//!
//! ```text
//! cb 2d 13 | 40 03 04 cb 25 ff 7e | 18 d1 f7 aa
//! ^attr tail ^NEXT_HOP 203.37.255.126 ^NLRI 209.247.170.0/24
//! ```
//!
//! The tail of a BGP UPDATE body left over after a complete STATE_CHANGE record.
//! Timestamps run backwards across this point (953956818 before, 953955969 after),
//! consistent with interleaved buffer flushes.
//!
//! Deleting those 24 bytes makes the file parse cleanly — 2,580 records (2,239
//! UPDATE, 307 STATE_CHANGE, 34 KEEPALIVE), 5,378 elements, zero errors — so there
//! is no body-level parsing defect here. What is missing is stream
//! resynchronization: on a framing error the reader has no pushback and cannot scan
//! forward for the next plausible common header, so every iterator either retries
//! at the same wrong offset or stops.
//!
//! The assertions below therefore pin **current, lossy** behaviour rather than
//! desired behaviour. Every count is a deterministic function of the fixture bytes.
//! If a change adds resynchronization, these numbers are expected to rise to the
//! recoverable totals quoted above.
//!
//! The same signature appears in every neighbouring rrc00 2000.03 file — exactly two
//! torn writes, one in the first ~200 bytes and one just past 4 KiB — so this is a
//! property of the historical writer, not of this one file.

use bgpkit_parser::models::EntryType;
use bgpkit_parser::{BgpkitParser, DiagnosticEvent, MrtUpdate, ParserError};
use std::collections::BTreeMap;

const FIXTURE: &str = "tests/fixtures/ripe/rrc00/2000.03/updates.20000325.0345.gz";

/// Records ahead of the first torn write, all of which parse normally. The fixture
/// holds 2,580 recoverable records and 5,378 recoverable elements, so all but these
/// four are lost.
const RECORDS_BEFORE_FIRST_TORN_WRITE: usize = 4;
/// Errors produced while the parser hunts forward 12 bytes at a time after
/// desynchronizing. It never re-aligns, because the true record boundary is not a
/// multiple of 12 from where the oversized read left it.
const DESYNCHRONIZED_ERRORS: usize = 128;

/// Header the parser manufactures from the 10-byte torn write at offset 188.
const TORN_HEADER_TIMESTAMP: u32 = 953_955_944;
const TORN_HEADER_LENGTH: u32 = 14_556;

fn repo_fixture(path: &str) -> String {
    format!("{}/{path}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn torn_writes_desynchronize_raw_record_framing() {
    let source = repo_fixture(FIXTURE);
    let mut raw_records = 0usize;
    let mut headers = BTreeMap::<(u16, u16), usize>::new();

    for raw_record in BgpkitParser::new(&source).unwrap().into_raw_record_iter() {
        raw_records += 1;
        *headers
            .entry((
                raw_record.common_header.entry_type as u16,
                raw_record.common_header.entry_subtype,
            ))
            .or_default() += 1;
    }

    // Only 5 of the fixture's 2,580 records reach framing — 4 genuine ones plus the
    // 14,556-byte torn "record" — after which the parser frames 3 more headers out of
    // misaligned bytes.
    assert_eq!(raw_records, 8);
    assert_eq!(
        headers,
        BTreeMap::from([
            (
                (EntryType::NULL as u16, 256),
                3 // pure garbage, framed mid-record after desynchronizing
            ),
            (
                (EntryType::BGP as u16, 1),
                4 // 3 genuine UPDATEs plus the torn 14,556-byte "record"
            ),
            ((EntryType::BGP as u16, 7), 1),
        ])
    );
}

#[test]
fn torn_writes_lose_all_but_four_records() {
    let source = repo_fixture(FIXTURE);

    // Skipping iterators: the error arms can only retry at the same wrong offset or
    // stop, so 2,576 of 2,580 records and 5,374 of 5,378 elements are lost.
    assert_eq!(
        BgpkitParser::new(&source)
            .unwrap()
            .into_record_iter()
            .count(),
        RECORDS_BEFORE_FIRST_TORN_WRITE
    );
    assert_eq!(
        BgpkitParser::new(&source).unwrap().into_elem_iter().count(),
        RECORDS_BEFORE_FIRST_TORN_WRITE
    );
    assert_eq!(
        BgpkitParser::new(&source)
            .unwrap()
            .into_route_iter()
            .count(),
        RECORDS_BEFORE_FIRST_TORN_WRITE
    );
    // One of the four surviving records is a KEEPALIVE, so the update iterator sees
    // one fewer.
    assert_eq!(
        BgpkitParser::new(&source)
            .unwrap()
            .into_update_iter()
            .count(),
        RECORDS_BEFORE_FIRST_TORN_WRITE - 1
    );

    // Fallible iterators surface the same loss as errors instead of silence.
    let mut records = 0usize;
    let mut record_errors = 0usize;
    for result in BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_record_iter()
    {
        match result {
            Ok(_) => records += 1,
            Err(_) => record_errors += 1,
        }
    }
    assert_eq!(records, RECORDS_BEFORE_FIRST_TORN_WRITE);
    assert_eq!(record_errors, DESYNCHRONIZED_ERRORS);

    let mut elements = 0usize;
    let mut element_errors = 0usize;
    for result in BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_elem_iter()
    {
        match result {
            Ok(_) => elements += 1,
            Err(_) => element_errors += 1,
        }
    }
    assert_eq!(elements, RECORDS_BEFORE_FIRST_TORN_WRITE);
    assert_eq!(element_errors, DESYNCHRONIZED_ERRORS);

    let mut updates = 0usize;
    let mut update_errors = 0usize;
    for result in BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_update_iter()
    {
        match result {
            Ok(MrtUpdate::LegacyBgpUpdate(_)) => updates += 1,
            Ok(update) => panic!("unexpected MRT update: {update:?}"),
            Err(_) => update_errors += 1,
        }
    }
    assert_eq!(updates, RECORDS_BEFORE_FIRST_TORN_WRITE - 1);
    assert_eq!(update_errors, DESYNCHRONIZED_ERRORS);

    let mut routes = 0usize;
    let mut route_errors = 0usize;
    for result in BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_route_iter()
    {
        match result {
            Ok(_) => routes += 1,
            Err(_) => route_errors += 1,
        }
    }
    assert_eq!(routes, RECORDS_BEFORE_FIRST_TORN_WRITE);
    assert_eq!(route_errors, DESYNCHRONIZED_ERRORS);
}

#[test]
fn diagnostic_iterator_reports_both_torn_writes() {
    let source = repo_fixture(FIXTURE);
    let events: Vec<DiagnosticEvent> = BgpkitParser::new(&source)
        .unwrap()
        .into_diagnostic_iter()
        .collect();

    // Four clean records, then one body error, then one framing error which
    // terminates the iterator by design.
    assert_eq!(events.len(), RECORDS_BEFORE_FIRST_TORN_WRITE + 2);
    for event in &events[..RECORDS_BEFORE_FIRST_TORN_WRITE] {
        let DiagnosticEvent::Record { record, .. } = event else {
            panic!("expected a clean record, got {event:?}");
        };
        assert_eq!(record.common_header.entry_type, EntryType::BGP);
    }

    // The 14,556-byte body read fails, but the manufactured header itself framed, so
    // the iterator reports it and continues.
    let DiagnosticEvent::ParseError {
        error,
        common_header,
        raw_bytes,
        ..
    } = &events[RECORDS_BEFORE_FIRST_TORN_WRITE]
    else {
        panic!(
            "expected a parse error for the torn header, got {:?}",
            events[RECORDS_BEFORE_FIRST_TORN_WRITE]
        );
    };
    let ParserError::TruncatedMsg(message) = error else {
        panic!("expected TruncatedMsg, got {error:?}");
    };
    assert_eq!(
        message,
        "not enough bytes to read. remaining: 14542, required: 33274"
    );
    let header = common_header.expect("the torn header parsed, so it is retained");
    assert_eq!(header.timestamp, TORN_HEADER_TIMESTAMP);
    assert_eq!(header.entry_type, EntryType::BGP);
    assert_eq!(header.entry_subtype, 1);
    assert_eq!(header.length, TORN_HEADER_LENGTH);
    assert_eq!(
        raw_bytes.as_deref().map(<[u8]>::len),
        Some(12 + TORN_HEADER_LENGTH as usize)
    );

    // The oversized read left the stream mid-record, so the next 12 bytes are not a
    // header. There is no header to report, and the framing error terminates
    // iteration rather than reinterpreting the remaining bytes.
    let DiagnosticEvent::ParseError {
        error,
        common_header,
        raw_bytes,
        ..
    } = &events[RECORDS_BEFORE_FIRST_TORN_WRITE + 1]
    else {
        panic!(
            "expected a framing error after desynchronizing, got {:?}",
            events[RECORDS_BEFORE_FIRST_TORN_WRITE + 1]
        );
    };
    let ParserError::ParseError(message) = error else {
        panic!("expected ParseError, got {error:?}");
    };
    assert_eq!(message, "cannot parse entry type: 32305");
    assert!(common_header.is_none());
    assert_eq!(raw_bytes.as_deref().map(<[u8]>::len), Some(12));
}
