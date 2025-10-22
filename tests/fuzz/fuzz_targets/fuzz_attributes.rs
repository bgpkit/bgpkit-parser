#![no_main]
use libfuzzer_sys::fuzz_target;
use bytes::Bytes;
use bgpkit_parser::parser::bgp::attributes::parse_attributes;
use bgpkit_parser::models::{AsnLength, Afi, Safi};

fuzz_target!(|data: &[u8]| {
    let mut bytes = Bytes::copy_from_slice(data);
    // Try without AFI/SAFI context
    let _ = parse_attributes(bytes.clone(), &AsnLength::Bits16, false, None, None, None);
    // Try with AFI/SAFI contexts
    let _ = parse_attributes(bytes.clone(), &AsnLength::Bits32, true, Some(&Afi::Ipv4), Some(&Safi::Unicast), None);
    let _ = parse_attributes(bytes, &AsnLength::Bits32, true, Some(&Afi::Ipv6), Some(&Safi::Unicast), None);
});
