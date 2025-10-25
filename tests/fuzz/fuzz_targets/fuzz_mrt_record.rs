#![no_main]
use libfuzzer_sys::fuzz_target;
use bytes::Bytes;
use bgpkit_parser::parser::mrt::mrt_record::parse_mrt_body;
use bgpkit_parser::models::EntryType;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    // Interpret first 2 bytes as entry_type, next 2 as subtype, rest as body
    let entry_type = u16::from_be_bytes([data[0], data[1]]);
    let entry_subtype = u16::from_be_bytes([data[2], data[3]]);
    // Quickly discard values mapping to completely unsupported types to reduce noise
    if EntryType::try_from(entry_type).is_err() {
        return;
    }
    let body = Bytes::copy_from_slice(&data[4..]);
    let _ = parse_mrt_body(entry_type, entry_subtype, body);
});
