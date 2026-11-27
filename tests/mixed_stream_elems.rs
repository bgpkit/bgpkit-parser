//! A stream that carries both dump and update records must produce the same elements as parsing
//! the two parts separately: the borrowed element path serves the dump records, then hands the
//! rest of the stream to the owned path.

use bgpkit_parser::{BgpkitParser, Filter, PrefixMatchType};
use std::io::Cursor;

const RIB_FIXTURE: &str = "tests/fixtures/routeviews/bview.slice.gz";
const UPDATES_FIXTURE: &str = "tests/fixtures/ripe/rrc15/2010.02/updates.20100227.1600.gz";

fn raw_stream(path: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for raw in BgpkitParser::new(path)
        .expect("open fixture")
        .into_raw_record_iter()
    {
        bytes.extend_from_slice(&raw.raw_bytes());
    }
    bytes
}

fn elems_of(bytes: Vec<u8>, filters: &[Filter]) -> Vec<String> {
    BgpkitParser::from_reader(Cursor::new(bytes))
        .add_filters(filters)
        .into_elem_iter()
        .map(|elem| elem.to_string())
        .collect()
}

#[test]
fn mixed_stream_matches_each_part() {
    let mut mixed = raw_stream(RIB_FIXTURE);
    mixed.extend(raw_stream(UPDATES_FIXTURE));

    let mut expected = elems_of(raw_stream(RIB_FIXTURE), &[]);
    expected.extend(elems_of(raw_stream(UPDATES_FIXTURE), &[]));
    assert!(!expected.is_empty());

    assert_eq!(elems_of(mixed.clone(), &[]), expected);
}

#[test]
fn mixed_stream_honours_a_prefix_filter_across_the_switch() {
    let mut mixed = raw_stream(RIB_FIXTURE);
    mixed.extend(raw_stream(UPDATES_FIXTURE));

    // A dump-only prefix constraint must not drop update records, which decide it per element.
    let filters = vec![Filter::Prefix(
        "8.8.8.0/24".parse().expect("valid prefix"),
        PrefixMatchType::Exact,
    )];
    let mut expected = elems_of(raw_stream(RIB_FIXTURE), &filters);
    expected.extend(elems_of(raw_stream(UPDATES_FIXTURE), &filters));

    assert_eq!(elems_of(mixed, &filters), expected);
}

/// The element iterator must agree with expanding every record of the same stream, unfiltered.
#[test]
fn elem_stream_matches_record_expansion() {
    for path in [RIB_FIXTURE, UPDATES_FIXTURE] {
        let by_record: Vec<String> = {
            let mut elementor = bgpkit_parser::Elementor::new();
            BgpkitParser::new(path)
                .expect("open fixture")
                .into_record_iter()
                .flat_map(|record| elementor.record_to_elems(record))
                .map(|elem| elem.to_string())
                .collect()
        };
        let by_elem: Vec<String> = BgpkitParser::new(path)
            .expect("open fixture")
            .into_elem_iter()
            .map(|elem| elem.to_string())
            .collect();

        assert!(!by_record.is_empty(), "{path} produced no elements");
        assert_eq!(by_elem, by_record, "{path}");
    }
}
