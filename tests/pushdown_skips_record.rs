//! A record rejected by a record-level filter is never parsed: it produces no parse error, and
//! the records behind it are still read.

use bgpkit_parser::{BgpkitParser, Filter};
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::io::Cursor;
use std::sync::{Mutex, Once, OnceLock};

const RIB_FIXTURE: &str = "tests/fixtures/routeviews/bview.slice.gz";

/// Collects this binary's log lines so a test can tell whether a record was parsed.
struct CaptureLogger;

static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
static INSTALL: Once = Once::new();

fn lines() -> &'static Mutex<Vec<String>> {
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

impl Log for CaptureLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= Level::Warn
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            lines()
                .lock()
                .expect("log buffer")
                .push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

fn install_logger() {
    INSTALL.call_once(|| {
        let _ = log::set_boxed_logger(Box::new(CaptureLogger));
        log::set_max_level(LevelFilter::Warn);
    });
    lines().lock().expect("log buffer").clear();
}

fn fixture_stream() -> Vec<u8> {
    let mut bytes = Vec::new();
    for raw in BgpkitParser::new(RIB_FIXTURE)
        .expect("open fixture")
        .into_raw_record_iter()
    {
        bytes.extend_from_slice(&raw.raw_bytes());
    }
    bytes
}

/// A `BGP4MP` AS4 message record whose BGP message carries an unknown type, which the parser
/// reports as a parse error.
fn malformed_bgp4mp_record(peer_ip: [u8; 4]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&64512u32.to_be_bytes()); // peer ASN
    body.extend_from_slice(&64512u32.to_be_bytes()); // local ASN
    body.extend_from_slice(&0u16.to_be_bytes()); // interface index
    body.extend_from_slice(&1u16.to_be_bytes()); // AFI: IPv4
    body.extend_from_slice(&peer_ip);
    body.extend_from_slice(&[10, 0, 0, 1]); // local address
    body.extend_from_slice(&[0xff; 16]); // BGP marker
    body.extend_from_slice(&19u16.to_be_bytes()); // message length
    body.push(99); // unknown message type

    let mut record = Vec::new();
    record.extend_from_slice(&1_760_000_000u32.to_be_bytes());
    record.extend_from_slice(&16u16.to_be_bytes()); // BGP4MP
    record.extend_from_slice(&4u16.to_be_bytes()); // MESSAGE_AS4
    record.extend_from_slice(&(body.len() as u32).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

fn elems(bytes: Vec<u8>, filters: &[Filter]) -> Vec<String> {
    BgpkitParser::from_reader(Cursor::new(bytes))
        .add_filters(filters)
        .into_elem_iter()
        .map(|elem| elem.to_string())
        .collect()
}

fn malformed_record_was_reported() -> bool {
    lines()
        .lock()
        .expect("log buffer")
        .iter()
        .any(|line| line.contains("Unknown BGP Message Type"))
}

#[test]
fn a_skipped_record_is_never_parsed() {
    install_logger();
    let mut mixed = malformed_bgp4mp_record([192, 0, 2, 99]);
    mixed.extend(fixture_stream());

    let unfiltered = elems(mixed.clone(), &[]);
    assert!(
        malformed_record_was_reported(),
        "an unfiltered run should parse the malformed record and report it"
    );
    assert!(!unfiltered.is_empty(), "the dump behind it is still read");

    // A peer filter that excludes the malformed record decides it from the record header, so the
    // record is dropped without parsing: no error is reported for it, and the dump is unaffected.
    install_logger();
    let reference_peer = BgpkitParser::new(RIB_FIXTURE)
        .expect("open fixture")
        .into_elem_iter()
        .next()
        .expect("fixture has elements")
        .peer_ip;
    let filters = vec![Filter::PeerIp(reference_peer)];
    let after_skip = elems(mixed, &filters);

    assert!(
        !malformed_record_was_reported(),
        "a skipped record must not be parsed, so it must not report an error"
    );
    let expected = elems(fixture_stream(), &filters);
    assert!(!expected.is_empty(), "the filter should keep some elements");
    assert_eq!(after_skip, expected);
}
