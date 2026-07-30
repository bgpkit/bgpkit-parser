use crate::encoder::sink::put_u16_len_slice;
use crate::error::EncodingError;
use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub fn parse_sfp(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    let mut tlvs = Vec::new();

    while input.remaining() > 0 {
        if input.remaining() < 3 {
            return Err(ParserError::TruncatedMsg(
                "truncated SFP TLV header".to_string(),
            ));
        }
        let tlv_type = input.read_u8()?;
        let length = input.read_u16()? as usize;
        if input.remaining() < length {
            return Err(ParserError::TruncatedMsg(format!(
                "truncated SFP TLV value for type {tlv_type}: need {length}, have {}",
                input.remaining()
            )));
        }
        let value = input.split_to(length);
        tlvs.push(RawTlv8Ext { tlv_type, value });
    }

    Ok(AttributeValue::Sfp(SfpAttribute { tlvs }))
}

pub fn encode_sfp(attr: &SfpAttribute, buf: &mut BytesMut) -> Result<(), EncodingError> {
    for tlv in &attr.tlvs {
        buf.put_u8(tlv.tlv_type);
        put_u16_len_slice(buf, "SFP TLV value length", &tlv.value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sfp_association_tlv_round_trip() {
        let input = Bytes::from_static(&[0x01, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd]);
        let value = parse_sfp(input.clone()).unwrap();
        match value {
            AttributeValue::Sfp(attr) => {
                assert_eq!(attr.tlvs.len(), 1);
                assert_eq!(attr.tlvs[0].tlv_type, 1);
                assert_eq!(
                    attr.tlvs[0].value,
                    Bytes::from_static(&[0xaa, 0xbb, 0xcc, 0xdd])
                );
                let mut buf = BytesMut::new();
                encode_sfp(&attr, &mut buf).unwrap();
                assert_eq!(buf.freeze(), input);
            }
            value => panic!("expected SFP, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_sfp_unknown_tlv_round_trip() {
        let input = Bytes::from_static(&[0x7f, 0x00, 0x02, 0xde, 0xad]);
        let value = parse_sfp(input.clone()).unwrap();
        match value {
            AttributeValue::Sfp(attr) => {
                assert_eq!(attr.tlvs[0].tlv_type, 0x7f);
                assert_eq!(attr.tlvs[0].value, Bytes::from_static(&[0xde, 0xad]));
                let mut buf = BytesMut::new();
                encode_sfp(&attr, &mut buf).unwrap();
                assert_eq!(buf.freeze(), input);
            }
            value => panic!("expected SFP, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_sfp_empty_attribute_round_trip() {
        let value = parse_sfp(Bytes::new()).unwrap();
        match value {
            AttributeValue::Sfp(attr) => {
                assert!(attr.tlvs.is_empty());
                let mut buf = BytesMut::new();
                encode_sfp(&attr, &mut buf).unwrap();
                assert!(buf.is_empty());
            }
            value => panic!("expected SFP, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_sfp_rejects_truncated_tlv() {
        assert!(parse_sfp(Bytes::from_static(&[0x01, 0x00])).is_err());
        assert!(parse_sfp(Bytes::from_static(&[0x01, 0x00, 0x02, 0xaa])).is_err());
    }
}
