#![no_main]
use bgpkit_parser::models::{Afi, AsnLength, Safi};
use bgpkit_parser::parser::bgp::attributes::parse_attributes;
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let bytes = Bytes::copy_from_slice(data);
    // Try without AFI/SAFI context
    let _ = parse_attributes(bytes.clone(), &AsnLength::Bits16, false, None, None, None);
    // Try with AFI/SAFI contexts
    let _ = parse_attributes(
        bytes.clone(),
        &AsnLength::Bits32,
        true,
        Some(Afi::Ipv4),
        Some(Safi::Unicast),
        None,
    );
    let _ = parse_attributes(
        bytes,
        &AsnLength::Bits32,
        true,
        Some(Afi::Ipv6),
        Some(Safi::Unicast),
        None,
    );
});
