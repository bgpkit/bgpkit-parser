use bgpkit_parser::BgpkitParser;
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::io::Cursor;
use std::sync::Mutex;

const SUPPRESSION_NOTICE: &str =
    "further parse errors for this parser will be logged at debug level";

static LOGGED: Mutex<Vec<(Level, String)>> = Mutex::new(Vec::new());
static TEST_LOGGER: TestLogger = TestLogger;

struct TestLogger;

impl Log for TestLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) && record.args().to_string().contains("parser error") {
            LOGGED
                .lock()
                .unwrap()
                .push((record.level(), record.args().to_string()));
        }
    }

    fn flush(&self) {}
}

/// A common header with an undefined entry type: a `ParseError` that consumes only the header.
fn invalid_entry_type_header() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(0u32.to_be_bytes()); // timestamp
    bytes.extend(15u16.to_be_bytes()); // invalid entry type
    bytes.extend(0u16.to_be_bytes()); // subtype
    bytes.extend(0u32.to_be_bytes()); // length
    bytes
}

fn take_logged() -> Vec<(Level, String)> {
    std::mem::take(&mut *LOGGED.lock().unwrap())
}

// One test function: the logger is process-global and the scenarios must not interleave.
#[test]
fn parse_errors_are_logged_at_error_level_once_per_parser() {
    log::set_logger(&TEST_LOGGER).unwrap();
    log::set_max_level(LevelFilter::Debug);

    let corrupted = [invalid_entry_type_header(), invalid_entry_type_header()].concat();

    // every parse error is skipped; only the first one is logged at error level
    for _ in 0..2 {
        let records = BgpkitParser::from_reader(Cursor::new(corrupted.clone()))
            .into_record_iter()
            .count();
        assert_eq!(records, 0);

        let logged = take_logged();
        assert_eq!(logged.len(), 2, "{logged:?}");
        assert_eq!(logged[0].0, Level::Error);
        assert!(logged[0].1.contains(SUPPRESSION_NOTICE), "{logged:?}");
        assert_eq!(logged[1].0, Level::Debug);
        assert!(!logged[1].1.contains(SUPPRESSION_NOTICE), "{logged:?}");
    }

    // with core dumps enabled the iterator stops at the first error, so the message must not
    // promise further errors
    let mut iter = BgpkitParser::from_reader(Cursor::new(corrupted))
        .enable_core_dump()
        .into_raw_record_iter();
    assert!(iter.next().is_none());

    let logged = take_logged();
    assert_eq!(logged.len(), 1, "{logged:?}");
    assert_eq!(logged[0].0, Level::Error);
    assert!(!logged[0].1.contains(SUPPRESSION_NOTICE), "{logged:?}");
}
