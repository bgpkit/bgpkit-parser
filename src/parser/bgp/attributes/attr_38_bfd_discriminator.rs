use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub fn parse_bfd_discriminator(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    if input.remaining() < 5 {
        return Err(ParserError::TruncatedMsg(
            "truncated BFD Discriminator attribute".to_string(),
        ));
    }

    let mode = input.read_u8()?;
    let discriminator = input.read_u32()?;
    let mut tlvs = Vec::new();

    while input.remaining() > 0 {
        if input.remaining() < 2 {
            return Err(ParserError::TruncatedMsg(
                "truncated BFD Discriminator optional TLV header".to_string(),
            ));
        }
        let tlv_type = input.read_u8()?;
        let length = input.read_u8()? as usize;
        if input.remaining() < length {
            return Err(ParserError::TruncatedMsg(format!(
                "truncated BFD Discriminator optional TLV value for type {tlv_type}: need {length}, have {}",
                input.remaining()
            )));
        }
        let value = input.split_to(length);
        tlvs.push(RawTlv8 { tlv_type, value });
    }

    Ok(AttributeValue::BfdDiscriminator(
        BfdDiscriminatorAttribute {
            mode,
            discriminator,
            tlvs,
        },
    ))
}

pub fn encode_bfd_discriminator(attr: &BfdDiscriminatorAttribute) -> Bytes {
    let mut buf = BytesMut::new();
    buf.put_u8(attr.mode);
    buf.put_u32(attr.discriminator);
    for tlv in &attr.tlvs {
        buf.put_u8(tlv.tlv_type);
        buf.put_u8(tlv.value.len() as u8);
        buf.extend_from_slice(&tlv.value);
    }
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bfd_discriminator_with_source_ipv4_tlv() {
        let input = Bytes::from_static(&[
            0x01, 0x01, 0x02, 0x03, 0x04, // mode + discriminator
            0x01, 0x04, 192, 0, 2, 1, // source IP TLV
        ]);
        let value = parse_bfd_discriminator(input.clone()).unwrap();
        match value {
            AttributeValue::BfdDiscriminator(attr) => {
                assert_eq!(attr.mode, 1);
                assert_eq!(attr.discriminator, 0x01020304);
                assert_eq!(attr.tlvs.len(), 1);
                assert_eq!(attr.tlvs[0].tlv_type, 1);
                assert_eq!(attr.tlvs[0].value, Bytes::from_static(&[192, 0, 2, 1]));
                assert_eq!(encode_bfd_discriminator(&attr), input);
            }
            value => panic!("expected BFD Discriminator, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_bfd_discriminator_without_optional_tlvs_round_trip() {
        let input = Bytes::from_static(&[0x01, 0x01, 0x02, 0x03, 0x04]);
        let value = parse_bfd_discriminator(input.clone()).unwrap();
        match value {
            AttributeValue::BfdDiscriminator(attr) => {
                assert_eq!(attr.mode, 1);
                assert_eq!(attr.discriminator, 0x01020304);
                assert!(attr.tlvs.is_empty());
                assert_eq!(encode_bfd_discriminator(&attr), input);
            }
            value => panic!("expected BFD Discriminator, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_bfd_discriminator_rejects_short_value() {
        assert!(parse_bfd_discriminator(Bytes::from_static(&[0x01, 0x02])).is_err());
        assert!(parse_bfd_discriminator(Bytes::from_static(&[
            0x01, 0x01, 0x02, 0x03, 0x04, 0x01, 0x04, 192
        ]))
        .is_err());
    }

    #[test]
    fn test_parse_bfd_discriminator_rejects_truncated_optional_tlv_header() {
        // Valid BFD (5 bytes) + only 1 byte for optional TLV header (need 2)
        let input = Bytes::from_static(&[0x01, 0x01, 0x02, 0x03, 0x04, 0x01]);
        assert!(parse_bfd_discriminator(input).is_err());
    }
}
