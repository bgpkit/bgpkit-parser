#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use bgpkit_parser::parser::mrt::mrt_header::parse_common_header;

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    let _ = parse_common_header(&mut cur);
});
