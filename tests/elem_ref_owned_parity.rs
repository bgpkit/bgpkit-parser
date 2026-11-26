//! Field-level parity between owned elems and elems materialised from borrowed views.

use bgpkit_parser::BgpkitParser;

/// A real TABLE_DUMP_V2 slice: one PEER_INDEX_TABLE followed by 399 RIB records.
const RIB_FIXTURE: &str = "tests/fixtures/routeviews/bview.slice.gz";

#[test]
fn borrowed_elems_match_owned_elems() {
    let owned: Vec<_> = BgpkitParser::new(RIB_FIXTURE)
        .expect("open fixture")
        .into_elem_iter()
        .collect();
    assert!(!owned.is_empty(), "fixture produced no elems");

    let mut parser = BgpkitParser::new(RIB_FIXTURE).expect("open fixture");
    let mut borrowed = Vec::new();
    while let Some(mut record) = parser.next_record_elems() {
        for elem in record.iter() {
            borrowed.push(elem.to_bgp_elem());
        }
    }

    assert_eq!(owned.len(), borrowed.len(), "element count differs");
    for (index, (owned_elem, borrowed_elem)) in owned.iter().zip(borrowed.iter()).enumerate() {
        assert_eq!(owned_elem, borrowed_elem, "elem {index} differs");
    }
}
