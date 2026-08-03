use bgpkit_parser::models::{Bgp4MpEnum, BgpState, MrtMessage};
use bgpkit_parser::BgpkitParser;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

const RRC03_CLEARING: &str =
    "tests/fixtures/ripe/rrc03/2010.02/updates.20100227.1600.first-796-records.gz";
const RRC15_DELETED_1600: &str = "tests/fixtures/ripe/rrc15/2010.02/updates.20100227.1600.gz";
const RRC15_DELETED_1610: &str = "tests/fixtures/ripe/rrc15/2010.02/updates.20100227.1610.gz";

#[derive(Debug, PartialEq, Eq)]
struct ExtendedStateChange {
    timestamp: u32,
    peer_ip: IpAddr,
    peer_asn: u32,
    old_state: BgpState,
    new_state: BgpState,
}

fn parse_extended_state_changes(path: &str) -> (usize, Vec<ExtendedStateChange>) {
    let source = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path);
    let mut records = 0usize;
    let mut state_changes = Vec::new();

    for result in BgpkitParser::new(&source)
        .unwrap()
        .into_fallible_record_iter()
    {
        let record = result.unwrap();
        records += 1;
        let timestamp = record.common_header.timestamp;

        if let MrtMessage::Bgp4Mp(Bgp4MpEnum::StateChange(state_change)) = record.message {
            let uses_extended_state = matches!(
                state_change.old_state,
                BgpState::Clearing | BgpState::Deleted
            ) || matches!(
                state_change.new_state,
                BgpState::Clearing | BgpState::Deleted
            );
            if uses_extended_state {
                state_changes.push(ExtendedStateChange {
                    timestamp,
                    peer_ip: state_change.peer_ip,
                    peer_asn: state_change.peer_asn.to_u32(),
                    old_state: state_change.old_state,
                    new_state: state_change.new_state,
                });
            }
        }
    }

    (records, state_changes)
}

#[test]
fn parses_quagga_clearing_states_from_rrc03() {
    let (records, state_changes) = parse_extended_state_changes(RRC03_CLEARING);

    assert_eq!(records, 796);
    assert_eq!(
        state_changes,
        vec![
            ExtendedStateChange {
                timestamp: 1_267_286_426,
                peer_ip: IpAddr::V4(Ipv4Addr::new(195, 69, 144, 87)),
                peer_asn: 6_774,
                old_state: BgpState::Clearing,
                new_state: BgpState::Idle,
            },
            ExtendedStateChange {
                timestamp: 1_267_286_426,
                peer_ip: IpAddr::V4(Ipv4Addr::new(193, 239, 116, 94)),
                peer_asn: 25_182,
                old_state: BgpState::Clearing,
                new_state: BgpState::Idle,
            },
            ExtendedStateChange {
                timestamp: 1_267_286_426,
                peer_ip: IpAddr::V4(Ipv4Addr::new(195, 69, 145, 56)),
                peer_asn: 29_686,
                old_state: BgpState::Established,
                new_state: BgpState::Clearing,
            },
            ExtendedStateChange {
                timestamp: 1_267_286_433,
                peer_ip: IpAddr::V4(Ipv4Addr::new(195, 69, 145, 56)),
                peer_asn: 29_686,
                old_state: BgpState::Clearing,
                new_state: BgpState::Idle,
            },
        ]
    );
}

#[test]
fn parses_quagga_deleted_states_from_rrc15() {
    let peer_ip = IpAddr::from_str("2001:12ff:1:1::2").unwrap();
    let fixtures = [
        (RRC15_DELETED_1600, 6_615, 1_267_286_526),
        (RRC15_DELETED_1610, 1_953, 1_267_287_002),
    ];

    for (path, expected_records, timestamp) in fixtures {
        let (records, state_changes) = parse_extended_state_changes(path);

        assert_eq!(
            records, expected_records,
            "unexpected record count for {path}"
        );
        assert_eq!(
            state_changes,
            vec![ExtendedStateChange {
                timestamp,
                peer_ip,
                peer_asn: 0,
                old_state: BgpState::OpenSent,
                new_state: BgpState::Deleted,
            }],
            "unexpected extended state changes for {path}"
        );
    }
}
