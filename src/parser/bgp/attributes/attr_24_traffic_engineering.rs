//! BGP Traffic Engineering attribute parsing and encoding - RFC 5543
//!
//! RFC 5543: <https://datatracker.ietf.org/doc/html/rfc5543>

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{EncodingError, ParserError};
use crate::models::*;
use crate::parser::ReadUtils;

/// Parse the BGP Traffic Engineering attribute (type 24).
///
/// Parses the 36-octet fixed portion defined by RFC 5543 and retains any
/// remaining switching-capability-specific information as raw bytes.
pub fn parse_traffic_engineering(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    // RFC 5543 fixed portion:
    // 1 octet switching capability, 1 octet encoding, 2 octets reserved,
    // and eight 4-octet maximum LSP bandwidth values.
    const FIXED_LENGTH: usize = 36;

    if input.remaining() < FIXED_LENGTH {
        return Err(ParserError::TruncatedMsg(format!(
            "truncated Traffic Engineering attribute: need at least {FIXED_LENGTH} bytes, have {}",
            input.remaining()
        )));
    }

    let switching_capability = input.read_u8()?;
    let encoding = input.read_u8()?;
    let reserved = input.read_u16()?;

    let mut max_lsp_bandwidth = [0.0_f32; 8];
    for bandwidth in &mut max_lsp_bandwidth {
        *bandwidth = f32::from_bits(input.read_u32()?);
    }

    let switching_capability_specific = input;

    Ok(AttributeValue::TrafficEngineering(TrafficEngineering {
        switching_capability,
        encoding,
        reserved,
        max_lsp_bandwidth,
        switching_capability_specific,
    }))
}

/// Encode a BGP Traffic Engineering attribute.
///
/// Bandwidth values are written as their IEEE-754 single-precision bit
/// representations, and switching-capability-specific information is
/// appended unchanged.
pub fn encode_traffic_engineering(
    attr: &TrafficEngineering,
    output: &mut BytesMut,
) -> Result<(), EncodingError> {
    output.put_u8(attr.switching_capability);
    output.put_u8(attr.encoding);
    output.put_u16(attr.reserved);

    for bandwidth in &attr.max_lsp_bandwidth {
        output.put_u32(bandwidth.to_bits());
    }

    output.put_slice(&attr.switching_capability_specific);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_parse_traffic_engineering_psc1() {
        let mut input = BytesMut::new();

        input.put_u8(1); // PSC-1
        input.put_u8(1); // Encoding value
        input.put_u16(0x1234); // Reserved field

        for bandwidth in [
            1000.0_f32, 2000.0, 3000.0, 4000.0, 5000.0, 6000.0, 7000.0, 8000.0,
        ] {
            input.put_f32(bandwidth);
        }

        let mut capability_specific = BytesMut::new();
        capability_specific.put_f32(500.0); // Minimum LSP bandwidth
        capability_specific.put_u16(1500); // Interface MTU
        input.extend_from_slice(&capability_specific);

        let value = parse_traffic_engineering(input.freeze()).unwrap();

        let attr = match value {
            AttributeValue::TrafficEngineering(attr) => attr,
            other => panic!("expected TrafficEngineering, got {other:?}"),
        };

        assert_eq!(attr.switching_capability, 1);
        assert_eq!(attr.encoding, 1);
        assert_eq!(attr.reserved, 0x1234);

        let expected_bandwidths = [
            1000.0_f32, 2000.0, 3000.0, 4000.0, 5000.0, 6000.0, 7000.0, 8000.0,
        ];

        for (actual, expected) in attr
            .max_lsp_bandwidth
            .iter()
            .zip(expected_bandwidths.iter())
        {
            assert_eq!(actual.to_bits(), expected.to_bits());
        }

        assert_eq!(
            attr.switching_capability_specific,
            capability_specific.freeze()
        );
    }

    #[test]
    fn test_parse_traffic_engineering_unknown_capability() {
        let mut input = BytesMut::new();

        input.put_u8(0xFE); // Unknown switching capability
        input.put_u8(0xFD); // Unknown encoding
        input.put_u16(0); // Reserved

        for bandwidth in [1.0_f32, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0] {
            input.put_f32(bandwidth);
        }

        let capability_specific = Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]);
        input.extend_from_slice(&capability_specific);

        let value = parse_traffic_engineering(input.freeze()).unwrap();

        let attr = match value {
            AttributeValue::TrafficEngineering(attr) => attr,
            other => panic!("expected TrafficEngineering, got {other:?}"),
        };

        assert_eq!(attr.switching_capability, 0xFE);
        assert_eq!(attr.encoding, 0xFD);
        assert_eq!(attr.switching_capability_specific, capability_specific);
    }

    #[test]
    fn test_parse_traffic_engineering_rejects_truncated_fixed_part() {
        let input = Bytes::from(vec![0_u8; 35]);

        let error = parse_traffic_engineering(input).unwrap_err();

        assert!(matches!(error, ParserError::TruncatedMsg(_)));
    }

    #[test]
    fn test_encode_traffic_engineering_psc1() {
        let attr = TrafficEngineering {
            switching_capability: 1,
            encoding: 1,
            reserved: 0x1234,
            max_lsp_bandwidth: [
                1000.0_f32, 2000.0, 3000.0, 4000.0, 5000.0, 6000.0, 7000.0, 8000.0,
            ],
            switching_capability_specific: Bytes::from_static(&[
                0x43, 0xFA, 0x00, 0x00, // Minimum LSP bandwidth: 500.0
                0x05, 0xDC, // Interface MTU: 1500
            ]),
        };

        let mut output = BytesMut::new();
        encode_traffic_engineering(&attr, &mut output).unwrap();

        assert_eq!(
            output.freeze(),
            Bytes::from_static(&[
                0x01, // PSC-1
                0x01, // Encoding
                0x12, 0x34, // Reserved
                0x44, 0x7A, 0x00, 0x00, // 1000.0
                0x44, 0xFA, 0x00, 0x00, // 2000.0
                0x45, 0x3B, 0x80, 0x00, // 3000.0
                0x45, 0x7A, 0x00, 0x00, // 4000.0
                0x45, 0x9C, 0x40, 0x00, // 5000.0
                0x45, 0xBB, 0x80, 0x00, // 6000.0
                0x45, 0xDA, 0xC0, 0x00, // 7000.0
                0x45, 0xFA, 0x00, 0x00, // 8000.0
                0x43, 0xFA, 0x00, 0x00, // Minimum LSP bandwidth: 500.0
                0x05, 0xDC, // Interface MTU: 1500
            ])
        );
    }

    #[test]
    fn test_traffic_engineering_unknown_capability_round_trip() {
        let mut input = BytesMut::new();

        input.put_u8(0xFE); // Unknown switching capability
        input.put_u8(0xFD); // Unknown encoding
        input.put_u16(0x1234); // Reserved

        for bandwidth in [1.0_f32, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0] {
            input.put_f32(bandwidth);
        }

        input.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let original = input.freeze();

        let value = parse_traffic_engineering(original.clone()).unwrap();

        let attr = match value {
            AttributeValue::TrafficEngineering(attr) => attr,
            other => panic!("expected TrafficEngineering, got {other:?}"),
        };

        let mut encoded = BytesMut::new();
        encode_traffic_engineering(&attr, &mut encoded).unwrap();

        assert_eq!(encoded.freeze(), original);
    }
}
