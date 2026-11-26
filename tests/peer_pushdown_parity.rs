//! A record skipped by a peer filter must yield exactly the elements the unfiltered parse would
//! yield for that peer.

use bgpkit_parser::{BgpkitParser, Filter};

const UPDATES_FIXTURE: &str = "tests/fixtures/ripe/rrc15/2010.02/updates.20100227.1600.gz";

fn filtered(filters: &[Filter]) -> Vec<String> {
    BgpkitParser::new(UPDATES_FIXTURE)
        .expect("open fixture")
        .add_filters(filters)
        .into_elem_iter()
        .map(|elem| elem.to_string())
        .collect()
}

fn unfiltered() -> Vec<(String, String)> {
    BgpkitParser::new(UPDATES_FIXTURE)
        .expect("open fixture")
        .into_elem_iter()
        .map(|elem| (elem.peer_ip.to_string(), elem.to_string()))
        .collect()
}

#[test]
fn peer_ip_filter_matches_unfiltered_selection() {
    let all = unfiltered();
    assert!(!all.is_empty(), "fixture has no elements");
    let (peer, _) = all[0].clone();

    let filters = vec![Filter::PeerIp(peer.parse().expect("valid peer address"))];
    let expected: Vec<String> = all
        .iter()
        .filter(|(candidate, _)| *candidate == peer)
        .map(|(_, line)| line.clone())
        .collect();

    assert!(!expected.is_empty());
    assert_eq!(filtered(&filters), expected);
}

#[test]
fn unrelated_peer_yields_nothing() {
    let filters = vec![Filter::PeerIp(
        "203.0.113.1".parse().expect("valid peer address"),
    )];
    assert!(filtered(&filters).is_empty());
}

#[test]
fn negated_peer_keeps_the_rest() {
    let all = unfiltered();
    let (peer, _) = all[0].clone();
    let filters = vec![Filter::Negated(Box::new(Filter::PeerIp(
        peer.parse().expect("valid peer address"),
    )))];
    let expected: Vec<String> = all
        .iter()
        .filter(|(candidate, _)| *candidate != peer)
        .map(|(_, line)| line.clone())
        .collect();

    assert_eq!(filtered(&filters), expected);
}

#[test]
fn timestamp_filter_matches_unfiltered_selection() {
    let all: Vec<(f64, String)> = BgpkitParser::new(UPDATES_FIXTURE)
        .expect("open fixture")
        .into_elem_iter()
        .map(|elem| (elem.timestamp, elem.to_string()))
        .collect();
    assert!(!all.is_empty());
    let mut stamps: Vec<f64> = all.iter().map(|(ts, _)| *ts).collect();
    stamps.sort_by(|a, b| a.partial_cmp(b).expect("finite timestamps"));
    let cut = stamps[stamps.len() / 2];

    let filters = vec![Filter::TsEnd(cut)];
    let expected: Vec<String> = all
        .iter()
        .filter(|(ts, _)| *ts <= cut)
        .map(|(_, line)| line.clone())
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(filtered(&filters), expected);

    let filters = vec![Filter::TsStart(cut)];
    let expected: Vec<String> = all
        .iter()
        .filter(|(ts, _)| *ts >= cut)
        .map(|(_, line)| line.clone())
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(filtered(&filters), expected);
}
