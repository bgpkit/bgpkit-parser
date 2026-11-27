//! `BgpElem::to_psv` must render exactly the PSV template, over every element of a real dump and
//! a real updates file, not just over hand-built samples.

use bgpkit_parser::{BgpElem, BgpkitParser};
use std::fmt::Display;

const RIB_FIXTURE: &str = "tests/fixtures/routeviews/bview.slice.gz";
const UPDATES_FIXTURE: &str = "tests/fixtures/ripe/rrc15/2010.02/updates.20100227.1600.gz";

fn opt<T: Display>(value: &Option<T>) -> String {
    value.as_ref().map(|v| v.to_string()).unwrap_or_default()
}

/// The template, with every field rendered through its own `Display`.
fn reference(elem: &BgpElem) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        match elem.elem_type {
            bgpkit_parser::models::ElemType::ANNOUNCE => "A",
            bgpkit_parser::models::ElemType::WITHDRAW => "W",
        },
        elem.timestamp,
        elem.peer_ip,
        elem.peer_asn,
        elem.prefix,
        opt(&elem.as_path),
        elem.origin_asns
            .as_ref()
            .map(|asns| asns
                .iter()
                .map(|asn| asn.to_string())
                .collect::<Vec<_>>()
                .join(" "))
            .unwrap_or_default(),
        opt(&elem.origin),
        opt(&elem.next_hop),
        opt(&elem.local_pref),
        opt(&elem.med),
        elem.communities
            .as_ref()
            .map(|communities| communities
                .iter()
                .map(|community| community.to_string())
                .collect::<Vec<_>>()
                .join(" "))
            .unwrap_or_default(),
        elem.atomic,
        opt(&elem.aggr_asn),
        opt(&elem.aggr_ip),
        opt(&elem.only_to_customer),
    )
}

fn check(path: &str) {
    let mut checked = 0usize;
    for elem in BgpkitParser::new(path)
        .unwrap_or_else(|_| panic!("open {path}"))
        .into_elem_iter()
    {
        assert_eq!(elem.to_psv(), reference(&elem), "{path}: elem {checked}");
        checked += 1;
    }
    assert!(checked > 0, "{path} produced no elements");
}

#[test]
fn psv_matches_the_template_over_a_rib_dump() {
    check(RIB_FIXTURE);
}

#[test]
fn psv_matches_the_template_over_an_updates_file() {
    check(UPDATES_FIXTURE);
}
