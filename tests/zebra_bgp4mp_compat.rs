use bgpkit_parser::models::{Bgp4MpEnum, BgpMessage, BgpState, MrtMessage};
use bgpkit_parser::BgpkitParser;
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

const FIXTURE: &str = "tests/fixtures/ripe/rrc01/2000.11/updates.20001104.0124.gz";
const ZEBRA_COMPAT_WARNING: &str = "recovered shortened Zebra BGP4MP records";

static WARNINGS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static TEST_LOGGER: TestLogger = TestLogger;

struct TestLogger;

impl Log for TestLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Warn
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            WARNINGS.lock().unwrap().push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

#[test]
fn parses_shortened_zebra_bgp4mp_records_with_one_warning_per_parser() {
    log::set_logger(&TEST_LOGGER).unwrap();
    log::set_max_level(LevelFilter::Warn);

    let source = format!("{}/{FIXTURE}", env!("CARGO_MANIFEST_DIR"));
    let zero = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let mut records = 0usize;
    let mut recovered_state_changes = 0usize;
    let mut recovered_open_messages = 0usize;

    for result in BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_record_iter()
    {
        records += 1;
        match result.unwrap().message {
            MrtMessage::Bgp4Mp(Bgp4MpEnum::StateChange(state_change))
                if state_change.peer_asn.to_u32() == 0
                    && state_change.local_asn.to_u32() == 0
                    && state_change.interface_index == 0
                    && state_change.peer_ip == zero
                    && state_change.local_addr == zero =>
            {
                assert!(matches!(
                    (state_change.old_state, state_change.new_state),
                    (BgpState::Active, BgpState::OpenSent) | (BgpState::OpenSent, BgpState::Idle)
                ));
                recovered_state_changes += 1;
            }
            MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(message))
                if message.peer_asn.to_u32() == 0
                    && message.local_asn.to_u32() == 0
                    && message.interface_index == 0
                    && message.peer_ip == zero
                    && message.local_ip == zero
                    && matches!(message.bgp_message, BgpMessage::Open(_)) =>
            {
                let BgpMessage::Open(open) = message.bgp_message else {
                    unreachable!()
                };
                assert_eq!(open.asn.to_u32(), 12_390);
                assert_eq!(open.hold_time, 180);
                assert_eq!(open.bgp_identifier, Ipv4Addr::new(212, 50, 161, 199));
                recovered_open_messages += 1;
            }
            _ => {}
        }
    }

    assert_eq!(records, 1_286);
    assert_eq!(recovered_state_changes, 42);
    assert_eq!(recovered_open_messages, 21);

    assert_eq!(
        WARNINGS
            .lock()
            .unwrap()
            .iter()
            .filter(|warning| warning.contains(ZEBRA_COMPAT_WARNING))
            .count(),
        1
    );

    let second_parser_records = BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_record_iter()
        .map(Result::unwrap)
        .count();
    assert_eq!(second_parser_records, 1_286);
    assert_eq!(
        WARNINGS
            .lock()
            .unwrap()
            .iter()
            .filter(|warning| warning.contains(ZEBRA_COMPAT_WARNING))
            .count(),
        2
    );
}
