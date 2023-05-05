#[cfg(test)]
mod tests {
    use super::*;
    use bgpkit_parser::{parse_mrt_record, BgpkitParser, Elementor};
    use std::io::Cursor;

    #[test]
    fn test_encode_small() {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";
        let parser = BgpkitParser::new(url).unwrap();
        for record in parser.into_record_iter() {
            let bytes = record.encode();
            let parsed_record = parse_mrt_record(&mut Cursor::new(bytes)).unwrap();
            assert_eq!(record, parsed_record);
        }
    }

    #[test]
    fn test_encode_large() {
        let url = "http://archive.routeviews.org/route-views.amsix/bgpdata/2023.05/UPDATES/updates.20230505.0330.bz2";
        let parser = BgpkitParser::new(url).unwrap();
        let mut elementor = Elementor::new();
        let mut count = 0;
        for record in parser.into_record_iter() {
            count += 1;
            let bytes = record.encode();
            let parsed_record = parse_mrt_record(&mut Cursor::new(bytes)).unwrap();
            assert_eq!(record, parsed_record);
        }
    }
}
