use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub fn parse_bier(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    let mut tlvs = Vec::new();

    while input.remaining() > 0 {
        if input.remaining() < 4 {
            return Err(ParserError::TruncatedMsg(
                "truncated BIER TLV header".to_string(),
            ));
        }
        let tlv_type = input.read_u16()?;
        let length = input.read_u16()? as usize;
        if input.remaining() < length {
            return Err(ParserError::TruncatedMsg(format!(
                "truncated BIER TLV value for type {tlv_type}: need {length}, have {}",
                input.remaining()
            )));
        }
        let value = input.split_to(length);
        tlvs.push(RawTlv16 { tlv_type, value });
    }

    Ok(AttributeValue::Bier(BierAttribute { tlvs }))
}

pub fn encode_bier(attr: &BierAttribute) -> Bytes {
    let mut buf = BytesMut::new();
    for tlv in &attr.tlvs {
        buf.put_u16(tlv.tlv_type);
        buf.put_u16(tlv.value.len() as u16);
        buf.extend_from_slice(&tlv.value);
    }
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bier_tlv_round_trip() {
        let input = Bytes::from_static(&[
            0x00, 0x01, // BIER TLV type 1
            0x00, 0x03, // value length
            0xaa, 0xbb, 0xcc,
        ]);
        let value = parse_bier(input.clone()).unwrap();
        match value {
            AttributeValue::Bier(attr) => {
                assert_eq!(attr.tlvs.len(), 1);
                assert_eq!(attr.tlvs[0].tlv_type, 1);
                assert_eq!(attr.tlvs[0].value, Bytes::from_static(&[0xaa, 0xbb, 0xcc]));
                assert_eq!(encode_bier(&attr), input);
            }
            value => panic!("expected BIER, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_bier_unknown_tlv_round_trip() {
        let input = Bytes::from_static(&[0x12, 0x34, 0x00, 0x02, 0xde, 0xad]);
        let value = parse_bier(input.clone()).unwrap();
        match value {
            AttributeValue::Bier(attr) => {
                assert_eq!(attr.tlvs[0].tlv_type, 0x1234);
                assert_eq!(attr.tlvs[0].value, Bytes::from_static(&[0xde, 0xad]));
                assert_eq!(encode_bier(&attr), input);
            }
            value => panic!("expected BIER, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_bier_empty_attribute_round_trip() {
        let value = parse_bier(Bytes::new()).unwrap();
        match value {
            AttributeValue::Bier(attr) => {
                assert!(attr.tlvs.is_empty());
                assert_eq!(encode_bier(&attr), Bytes::new());
            }
            value => panic!("expected BIER, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_bier_rejects_truncated_tlv() {
        assert!(parse_bier(Bytes::from_static(&[0x00, 0x01, 0x00])).is_err());
        assert!(parse_bier(Bytes::from_static(&[0x00, 0x01, 0x00, 0x02, 0xaa])).is_err());
    }
}
