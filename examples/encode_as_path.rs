//! Encode announcements with the `AsPath`/`As4Path` variant split (RFC 6793).
//!
//! Since the `is_as4` flag was split into distinct attribute variants:
//! - `AttributeValue::AsPath` is AS_PATH (type 2). Pass `AsnLength::Bits32`
//!   to `encode_to` and its segments encode as 4-octet automatically — this
//!   is how you build announcements for a 4-octet session.
//! - `AttributeValue::As4Path` is AS4_PATH (type 17), the RFC 6793 §4.2
//!   fallback for 2-octet sessions; its values always encode with 4-octet AS
//!   numbers regardless of session width.
//!
//! Encoding is fallible: an AS number above 65535 in a 2-octet segment
//! returns `EncodingError::ValueTooLarge` instead of silently truncating.
//! Substitute `Asn::TRANSITION` (AS_TRANS, 23456) in the 2-octet AS_PATH and
//! carry the full number in AS4_PATH, which is exactly what a 2-octet
//! session speaker does during 4-octet migration.

use bgpkit_parser::encoder::MrtUpdatesEncoder;
use bgpkit_parser::models::{
    AsPath, AsPathSegment, Asn, AsnLength, AttributeValue, Attributes, BgpElem, ElemType,
    NetworkPrefix, Origin,
};
use std::net::Ipv4Addr;
use std::str::FromStr;

fn announcement(path: AsPath) -> BgpElem {
    BgpElem {
        elem_type: ElemType::ANNOUNCE,
        prefix: NetworkPrefix::new(ipnet::IpNet::from_str("192.0.2.0/24").unwrap(), None),
        next_hop: Some(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        origin: Some(Origin::IGP),
        as_path: Some(path),
        peer_ip: std::net::IpAddr::V4(Ipv4Addr::new(193, 0, 0, 1)),
        peer_asn: Asn::new_32bit(12654),
        timestamp: 0.0,
        ..Default::default()
    }
}

fn main() {
    // A 4-octet AS path: no AS_TRANS needed, encode with Bits32.
    let path = AsPath::from_segments(vec![AsPathSegment::sequence([64512u32, 4200000000])]);
    let attributes = Attributes::from_iter(vec![AttributeValue::AsPath(path.clone())]);

    let bytes = attributes
        .encode(AsnLength::Bits32)
        .expect("4-octet encode");
    println!("AS_PATH type 2, Bits32: {:02x?}", bytes);
    // 0x40 0x02 (flags, type 2), 0x0A (value length 10 = 1 segment header +
    // two 4-octet AS numbers), then the segment.
    assert_eq!(&bytes[..3], &[0x40, 0x02, 0x0A]);
    assert_eq!(bytes[3], 0x02);

    // Same attribute on a 2-octet session: 4200000000 does not fit, and the
    // encoder says so instead of writing the low 16 bits (400644 -> 7428).
    let error = attributes
        .encode(AsnLength::Bits16)
        .expect_err("must not truncate");
    println!("Bits16 encode of AS 4200000000: {error}");

    // The RFC 6793 migration shape: AS_TRANS in the 2-octet AS_PATH...
    let short_path = AsPath::from_segments(vec![AsPathSegment::sequence([
        Asn::TRANSITION.to_u32(),
        174,
    ])]);
    let migrated = Attributes::from_iter(vec![
        AttributeValue::AsPath(short_path),
        // ...and the real 4-octet path in AS4_PATH (type 17).
        AttributeValue::As4Path(path),
    ]);
    let bytes = migrated
        .encode(AsnLength::Bits16)
        .expect("migration encode");
    println!("AS_PATH+AS4_PATH on a 2-octet session: {:02x?}", bytes);
    // 0x40 0x02 .. type-2 segment with two 2-octet ASNs (7 bytes total),
    // 0xC0 0x11 .. optional-transitive type-17 segment with 4-octet ASNs.
    assert_eq!(bytes[1], 0x02);
    assert_eq!(&bytes[9..11], &[0xC0, 0x11]);

    // Feed the announcement through the MRT updates encoder and read it back.
    let mut encoder = MrtUpdatesEncoder::new();
    encoder.process_elem(&announcement(AsPath::from_segments(vec![
        AsPathSegment::sequence([64512u32, 4200000000]),
    ])));
    let mrt_bytes = encoder.export_bytes().expect("export MRT");
    println!("MRT updates archive: {} bytes", mrt_bytes.len());
}
