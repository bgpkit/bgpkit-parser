#[cfg(test)]
mod tests {
    use bgpkit_parser::models::MrtRecord;
    use bgpkit_parser::{parse_mrt_record, BgpkitParser};
    use std::io::{Cursor, Write};

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
        for record in parser.into_record_iter() {
            let bytes = record.encode();
            let parsed_record = parse_mrt_record(&mut Cursor::new(bytes)).unwrap();
            assert_eq!(record, parsed_record);
        }
    }

    #[test]
    fn test_encode_table_dump_v1() {
        let url = "http://archive.routeviews.org/bgpdata/2002.01/RIBS/rib.20020101.0027.bz2";
        let input_records: Vec<MrtRecord> =
            BgpkitParser::new(url).unwrap().into_record_iter().collect();

        let dir = tempdir::TempDir::new("test_encode_table_dump_v1").unwrap();
        let tempfile = dir
            .path()
            .join("test_encode_table_dump_v1.mrt")
            .to_str()
            .unwrap()
            .to_string();
        let mut writer = oneio::get_writer(tempfile.as_str()).unwrap();

        for record in input_records.iter() {
            let bytes = record.encode();
            writer.write_all(&bytes).unwrap();
            let parsed_record = parse_mrt_record(&mut Cursor::new(bytes)).unwrap();
            assert_eq!(*record, parsed_record);
        }
        drop(writer);

        let encoded_records: Vec<MrtRecord> = BgpkitParser::new(tempfile.as_str())
            .unwrap()
            .into_record_iter()
            .collect();

        assert_eq!(input_records, encoded_records);
    }
}