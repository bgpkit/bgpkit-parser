use bgpkit_parser::models::{BgpError, BgpMessage, LegacyBgp, MrtMessage};
use bgpkit_parser::{BgpkitParser, MrtUpdate};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

const FIXTURE_DIR: &str = "tests/fixtures/ripe/rrc00/2000.01";
const EARLIEST_UPDATE: &str = "tests/fixtures/ripe/rrc00/1999.09/updates.19990903.1041.gz";
const OPEN_NOTIFY_UPDATE: &str = "tests/fixtures/ripe/rrc00/1999.12/updates.19991214.1621.gz";

fn fixture(name: &str) -> String {
    format!("{}/{FIXTURE_DIR}/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn repo_fixture(path: &str) -> String {
    format!("{}/{path}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn prints_earliest_ris_update_statistics() {
    let source = repo_fixture(EARLIEST_UPDATE);
    let mut raw_records = 0usize;
    let mut subtypes = BTreeMap::<u16, usize>::new();

    for raw_record in BgpkitParser::new(&source).unwrap().into_raw_record_iter() {
        raw_records += 1;
        *subtypes
            .entry(raw_record.common_header.entry_subtype)
            .or_default() += 1;
    }

    let mut parsed_records = 0usize;
    let parse_errors = 0usize;
    let mut update_records = 0usize;
    let mut opens = 0usize;
    let mut notifications = 0usize;
    let mut keepalives = 0usize;
    let mut state_changes = 0usize;

    for result in BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_record_iter()
    {
        match result {
            Ok(record) => {
                parsed_records += 1;
                match record.message {
                    MrtMessage::LegacyBgp(LegacyBgp::Message(message)) => {
                        match message.bgp_message {
                            BgpMessage::Update(_) => update_records += 1,
                            BgpMessage::Open(_) => opens += 1,
                            BgpMessage::Notification(_) => notifications += 1,
                            BgpMessage::KeepAlive => keepalives += 1,
                            BgpMessage::RouteRefresh(_) => {
                                panic!("unexpected ROUTE-REFRESH in legacy fixture")
                            }
                        }
                    }
                    MrtMessage::LegacyBgp(LegacyBgp::StateChange(_)) => state_changes += 1,
                    message => panic!("unexpected MRT message: {message:?}"),
                }
            }
            Err(error) => panic!("unexpected MRT parse error: {error}"),
        }
    }

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

    println!(
        "earliest RIS update statistics ({EARLIEST_UPDATE}):\n\
         raw MRT records: {raw_records}\n\
         raw subtypes: {subtypes:?}\n\
         parsed records: {parsed_records}\n\
         parse errors: {parse_errors}\n\
         update records: {update_records}\n\
         opens: {opens}\n\
         notifications: {notifications}\n\
         keepalives: {keepalives}\n\
         state changes: {state_changes}\n\
         BGP elements: {elements} (errors: {element_errors})\n\
         MRT updates: {updates} (errors: {update_errors})\n\
         route elements: {routes} (errors: {route_errors})"
    );

    assert_eq!(raw_records, 24_242);
    assert_eq!(
        subtypes,
        BTreeMap::from([(1, 24_216), (3, 4), (5, 1), (7, 21)])
    );
    assert_eq!(parsed_records, 24_242);
    assert_eq!(parse_errors, 0);
    assert_eq!(update_records, 24_216);
    assert_eq!(opens, 1);
    assert_eq!(notifications, 0);
    assert_eq!(keepalives, 21);
    assert_eq!(state_changes, 4);
    assert_eq!(elements, 65_311);
    assert_eq!(element_errors, 0);
    assert_eq!(updates, update_records);
    assert_eq!(update_errors, 0);
    assert_eq!(routes, elements);
    assert_eq!(route_errors, 0);
    assert_eq!(
        parsed_records,
        update_records + opens + notifications + keepalives + state_changes
    );
}

#[test]
fn parses_legacy_open_and_notify_fixture() {
    let source = repo_fixture(OPEN_NOTIFY_UPDATE);
    let mut raw_records = 0usize;
    let mut subtypes = BTreeMap::<u16, usize>::new();

    for raw_record in BgpkitParser::new(&source).unwrap().into_raw_record_iter() {
        raw_records += 1;
        *subtypes
            .entry(raw_record.common_header.entry_subtype)
            .or_default() += 1;
    }

    let mut records = 0usize;
    let mut updates = 0usize;
    let mut opens = 0usize;
    let mut notifications = 0usize;
    let mut keepalives = 0usize;
    let mut state_changes = 0usize;

    for result in BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_record_iter()
    {
        records += 1;
        match result.unwrap().message {
            MrtMessage::LegacyBgp(LegacyBgp::Message(message)) => match message.bgp_message {
                BgpMessage::Update(_) => updates += 1,
                BgpMessage::Open(open) => {
                    opens += 1;
                    assert_eq!(u32::from(message.peer_asn), 3549);
                    assert_eq!(
                        message.peer_ip,
                        IpAddr::V4(Ipv4Addr::new(204, 152, 166, 29))
                    );
                    assert_eq!(u32::from(message.local_asn), 12654);
                    assert_eq!(message.local_ip, IpAddr::V4(Ipv4Addr::new(193, 0, 0, 1)));
                    assert_eq!(open.version, 4);
                    assert_eq!(u32::from(open.asn), 3549);
                    assert_eq!(open.hold_time, 180);
                    assert_eq!(open.bgp_identifier, Ipv4Addr::new(204, 152, 166, 29));
                    assert_eq!(open.opt_params.len(), 2);
                }
                BgpMessage::Notification(notification) => {
                    notifications += 1;
                    assert_eq!(u32::from(message.peer_asn), 3549);
                    assert_eq!(message.peer_ip, IpAddr::V4(Ipv4Addr::new(206, 251, 0, 85)));
                    assert_eq!(u32::from(message.local_asn), 12654);
                    assert_eq!(message.local_ip, IpAddr::V4(Ipv4Addr::new(193, 0, 0, 1)));
                    assert_eq!(notification.error, BgpError::HoldTimerExpired(0));
                    assert!(notification.data.is_empty());
                }
                BgpMessage::KeepAlive => keepalives += 1,
                BgpMessage::RouteRefresh(_) => {
                    panic!("unexpected ROUTE-REFRESH in legacy fixture")
                }
            },
            MrtMessage::LegacyBgp(LegacyBgp::StateChange(_)) => state_changes += 1,
            message => panic!("unexpected MRT message: {message:?}"),
        }
    }

    assert_eq!(raw_records, 18_203);
    assert_eq!(
        subtypes,
        BTreeMap::from([(1, 18_054), (3, 27), (5, 1), (6, 1), (7, 120)])
    );
    assert_eq!(records, raw_records);
    assert_eq!(updates, 18_054);
    assert_eq!(opens, 1);
    assert_eq!(notifications, 1);
    assert_eq!(keepalives, 120);
    assert_eq!(state_changes, 27);

    let elements = BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_elem_iter()
        .map(Result::unwrap)
        .count();
    assert_eq!(elements, 55_489);

    let mrt_updates = BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_update_iter()
        .map(Result::unwrap)
        .inspect(|update| assert!(matches!(update, MrtUpdate::LegacyBgpUpdate(_))))
        .count();
    assert_eq!(mrt_updates, updates);

    let routes = BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_route_iter()
        .map(Result::unwrap)
        .count();
    assert_eq!(routes, elements);
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
        .inspect(|update| assert!(matches!(update, MrtUpdate::LegacyBgpUpdate(_))))
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
        .inspect(|update| assert!(matches!(update, MrtUpdate::TableDumpMessage(_))))
        .count();
    assert_eq!(updates, 452_018);

    let routes = BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_route_iter()
        .map(Result::unwrap)
        .count();
    assert_eq!(routes, 452_018);
}
