//! A record skipped by a prefix filter must yield exactly the elements the unfiltered parse
//! would yield for that prefix.

use bgpkit_parser::{BgpkitParser, Filter, PrefixMatchType};

/// A real TABLE_DUMP_V2 slice: one PEER_INDEX_TABLE followed by 399 RIB records.
const RIB_FIXTURE: &str = "tests/fixtures/routeviews/bview.slice.gz";

fn filtered(filters: &[Filter]) -> Vec<String> {
    BgpkitParser::new(RIB_FIXTURE)
        .expect("open fixture")
        .add_filters(filters)
        .into_elem_iter()
        .map(|elem| elem.to_string())
        .collect()
}

fn unfiltered() -> Vec<(String, String)> {
    BgpkitParser::new(RIB_FIXTURE)
        .expect("open fixture")
        .into_elem_iter()
        .map(|elem| (elem.prefix.to_string(), elem.to_string()))
        .collect()
}

#[test]
fn prefix_filter_matches_unfiltered_selection() {
    let all = unfiltered();
    assert!(!all.is_empty(), "fixture has no elements");
    let (prefix, _) = all[0].clone();

    let filters = vec![Filter::Prefix(
        prefix.parse().expect("valid prefix"),
        PrefixMatchType::Exact,
    )];
    let expected: Vec<String> = all
        .iter()
        .filter(|(candidate, _)| *candidate == prefix)
        .map(|(_, line)| line.clone())
        .collect();

    assert_eq!(filtered(&filters), expected);
}

#[test]
fn unrelated_prefix_yields_nothing() {
    let filters = vec![Filter::Prefix(
        "203.0.113.0/24".parse().expect("valid prefix"),
        PrefixMatchType::Exact,
    )];
    assert!(filtered(&filters).is_empty());
}

#[test]
fn negated_prefix_keeps_the_rest() {
    let all = unfiltered();
    let (prefix, _) = all[0].clone();
    let filters = vec![Filter::Negated(Box::new(Filter::Prefix(
        prefix.parse().expect("valid prefix"),
        PrefixMatchType::Exact,
    )))];
    let expected: Vec<String> = all
        .iter()
        .filter(|(candidate, _)| *candidate != prefix)
        .map(|(_, line)| line.clone())
        .collect();

    assert!(!expected.is_empty());
    assert_eq!(filtered(&filters), expected);
}
