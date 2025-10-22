#![no_main]
use libfuzzer_sys::fuzz_target;
use bytes::Bytes;
use bgpkit_parser::parser::bgp::messages::parse_bgp_message;
use bgpkit_parser::models::AsnLength;

fuzz_target!(|data: &[u8]| {
    let mut bytes = Bytes::copy_from_slice(data);
    // Try both 2-byte and 4-byte ASN lengths
    let _ = parse_bgp_message(&mut bytes.clone(), false, &AsnLength::Bits16);
    let _ = parse_bgp_message(&mut bytes, false, &AsnLength::Bits32);
});
