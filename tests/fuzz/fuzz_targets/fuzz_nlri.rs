#![no_main]
use libfuzzer_sys::fuzz_target;
use bytes::Bytes;
use bgpkit_parser::parser::utils::parse_nlri_list;
use bgpkit_parser::models::Afi;

fuzz_target!(|data: &[u8]| {
    let bytes = Bytes::copy_from_slice(data);
    let _ = parse_nlri_list(bytes.clone(), false, &Afi::Ipv4);
    let _ = parse_nlri_list(bytes, true, &Afi::Ipv6);
});
