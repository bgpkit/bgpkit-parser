#![no_main]
use libfuzzer_sys::fuzz_target;
use bgpkit_parser::parser::rislive::parse_ris_live_message;
use std::str;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = str::from_utf8(data) {
        let _ = parse_ris_live_message(s);
    }
});
