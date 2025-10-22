#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use bgpkit_parser::parser::mrt::mrt_record::parse_mrt_record;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = parse_mrt_record(&mut cursor);
});
