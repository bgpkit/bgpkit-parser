//! A filtered elem iteration must return exactly the elems of the unfiltered
//! iteration that match, in the same order.
//!
//! The elem iterators test every elem they build against the parser's filters.
//! The record iterator they wrap used to run the same test once per record by
//! cloning the record and converting all of its elems, then throwing that
//! conversion away and converting the record again for the elem iterator. Both
//! paths must keep producing one identical stream; the record-level pass is now
//! skipped for the elem iterators, and this test is what holds the two apart if
//! that wiring ever changes.

use bgpkit_parser::models::BgpElem;
use bgpkit_parser::BgpkitParser;

const RIB: &str = "tests/fixtures/ripe/rrc00/2000.01/bview.20000111.0032.gz";
const UPDATES: &str = "tests/fixtures/ripe/rrc00/2000.03/updates.20000325.0345.gz";

fn elems(path: &str) -> Vec<BgpElem> {
    BgpkitParser::new(path)
        .expect("fixture opens")
        .into_elem_iter()
        .collect()
}

/// The prefix that appears most often, so the filtered run has a real
/// population to compare against instead of one or two elems.
fn busiest_prefix(elems: &[BgpElem]) -> Option<String> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for elem in elems {
        *counts.entry(elem.prefix.to_string()).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(prefix, _)| prefix)
}

fn psv(elems: &[BgpElem]) -> Vec<String> {
    elems.iter().map(|elem| elem.to_string()).collect()
}

fn assert_parity(path: &str) {
    let all = elems(path);
    assert!(!all.is_empty(), "{path} produced no elems");

    let prefix = busiest_prefix(&all).expect("at least one prefix");
    let expected = psv(&all
        .iter()
        .filter(|elem| elem.prefix.to_string() == prefix)
        .cloned()
        .collect::<Vec<_>>());
    assert!(!expected.is_empty(), "{path} lost every elem of {prefix}");

    let filtered = BgpkitParser::new(path)
        .expect("fixture opens")
        .add_filter("prefix", &prefix)
        .expect("prefix filter is valid")
        .into_elem_iter()
        .collect::<Vec<_>>();
    assert_eq!(
        expected,
        psv(&filtered),
        "{path}: filtered elem iteration of {prefix} diverged from the unfiltered stream"
    );

    let filtered_fallible = BgpkitParser::new(path)
        .expect("fixture opens")
        .add_filter("prefix", &prefix)
        .expect("prefix filter is valid")
        .into_fallible_elem_iter()
        .map_while(|elem| elem.ok().map(|elem| elem.to_string()))
        .collect::<Vec<_>>();
    assert_eq!(
        expected, filtered_fallible,
        "{path}: filtered fallible elem iteration of {prefix} diverged from the unfiltered stream"
    );
}

#[test]
fn filtered_elem_iteration_matches_the_unfiltered_stream_on_a_rib() {
    assert_parity(RIB);
}

#[test]
fn filtered_elem_iteration_matches_the_unfiltered_stream_on_updates() {
    assert_parity(UPDATES);
}
