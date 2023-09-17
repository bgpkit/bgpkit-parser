//! This integration test simply checks that no errors are encountered when attempting to parse a
//! update dump and a RIB dump.
use bgpkit_parser::BgpkitParser;

#[test]
fn parse_updates() {
    check_file("https://spaces.bgpkit.org/parser/update-example.gz");
}

#[test]
fn parse_rib_dump() {
    check_file("https://spaces.bgpkit.org/parser/rib-example-small.bz2");
}

fn check_file(url: &str) {
    let parser = BgpkitParser::new(url).unwrap();

    for record in parser.into_record_iter() {
        assert!(record.is_ok(), "{}", record.unwrap_err());
    }
}
