use bgpkit_parser::models::{BgpMessage, LegacyBgp, MrtMessage};
use bgpkit_parser::{BgpkitParser, MrtUpdate};

const FIXTURE_DIR: &str = "tests/fixtures/ripe/rrc00/2000.01";

fn fixture(name: &str) -> String {
    format!("{}/{FIXTURE_DIR}/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn parses_legacy_mrt_type_5_updates_fixture() {
    let source = fixture("updates.20000102.2014.gz");
    let mut records = 0usize;
    let mut update_records = 0usize;
    let mut keepalives = 0usize;
    let mut state_changes = 0usize;

    for result in BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_record_iter()
    {
        records += 1;
        match result.unwrap().message {
            MrtMessage::LegacyBgp(LegacyBgp::Message(message)) => {
                if matches!(message.bgp_message, BgpMessage::Update(_)) {
                    update_records += 1;
                } else if matches!(message.bgp_message, BgpMessage::KeepAlive) {
                    keepalives += 1;
                }
            }
            MrtMessage::LegacyBgp(LegacyBgp::StateChange(_)) => state_changes += 1,
            message => panic!("unexpected message in legacy update fixture: {message:?}"),
        }
    }

    assert_eq!(records, 3_957);
    assert_eq!(update_records, 3_818);
    assert_eq!(keepalives, 123);
    assert_eq!(state_changes, 16);

    let elements = BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_elem_iter()
        .map(Result::unwrap)
        .count();
    assert_eq!(elements, 6_343);

    let updates = BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_update_iter()
        .map(Result::unwrap)
        .map(|update| assert!(matches!(update, MrtUpdate::LegacyBgpUpdate(_))))
        .count();
    assert_eq!(updates, 3_818);

    let routes = BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_route_iter()
        .map(Result::unwrap)
        .count();
    assert_eq!(routes, 6_343);
}

#[test]
fn parses_historical_batched_table_dump_fixture() {
    let source = fixture("bview.20000111.0032.gz");
    let mut records = 0usize;
    let mut entries = 0usize;

    for result in BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_record_iter()
    {
        records += 1;
        match result.unwrap().message {
            MrtMessage::TableDumpMessageBatch(messages) => entries += messages.len(),
            message => panic!("unexpected message in historical bview fixture: {message:?}"),
        }
    }
    assert_eq!(records, 2_490);
    assert_eq!(entries, 452_018);

    let elements = BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_elem_iter()
        .map(Result::unwrap)
        .count();
    assert_eq!(elements, 452_018);

    let updates = BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_update_iter()
        .map(Result::unwrap)
        .map(|update| assert!(matches!(update, MrtUpdate::TableDumpMessage(_))))
        .count();
    assert_eq!(updates, 452_018);

    let routes = BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_route_iter()
        .map(Result::unwrap)
        .count();
    assert_eq!(routes, 452_018);
}
