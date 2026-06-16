use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub fn parse_bgp_prefix_sid(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    let mut tlvs = Vec::new();

    while input.remaining() > 0 {
        if input.remaining() < 3 {
            return Err(ParserError::TruncatedMsg(
                "truncated BGP Prefix-SID TLV header".to_string(),
            ));
        }
        let tlv_type = input.read_u8()?;
        let length = input.read_u16()? as usize;
        if input.remaining() < length {
            return Err(ParserError::TruncatedMsg(format!(
                "truncated BGP Prefix-SID TLV value for type {tlv_type}: need {length}, have {}",
                input.remaining()
            )));
        }
        let value = input.split_to(length);
        tlvs.push(RawTlv8Ext { tlv_type, value });
    }

    Ok(AttributeValue::BgpPrefixSid(BgpPrefixSidAttribute { tlvs }))
}

pub fn encode_bgp_prefix_sid(attr: &BgpPrefixSidAttribute) -> Bytes {
    let mut buf = BytesMut::new();
    for tlv in &attr.tlvs {
        buf.put_u8(tlv.tlv_type);
        buf.put_u16(tlv.value.len() as u16);
        buf.extend_from_slice(&tlv.value);
    }
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_prefix_sid_label_index_tlv_round_trip() {
        let input = Bytes::from_static(&[
            0x01, 0x00, 0x07, // Label-Index TLV type + value length
            0x00, // reserved
            0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x2a, // label index
        ]);
        let value = parse_bgp_prefix_sid(input.clone()).unwrap();
        match value {
            AttributeValue::BgpPrefixSid(attr) => {
                assert_eq!(attr.tlvs.len(), 1);
                assert_eq!(attr.tlvs[0].tlv_type, 1);
                assert_eq!(attr.tlvs[0].value.len(), 7);
                assert_eq!(encode_bgp_prefix_sid(&attr), input);
            }
            value => panic!("expected Prefix-SID, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_prefix_sid_unknown_tlv_round_trip() {
        let input = Bytes::from_static(&[0x7f, 0x00, 0x02, 0xaa, 0xbb]);
        let value = parse_bgp_prefix_sid(input.clone()).unwrap();
        match value {
            AttributeValue::BgpPrefixSid(attr) => {
                assert_eq!(attr.tlvs[0].tlv_type, 0x7f);
                assert_eq!(attr.tlvs[0].value, Bytes::from_static(&[0xaa, 0xbb]));
                assert_eq!(encode_bgp_prefix_sid(&attr), input);
            }
            value => panic!("expected Prefix-SID, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_prefix_sid_empty_attribute_round_trip() {
        let value = parse_bgp_prefix_sid(Bytes::new()).unwrap();
        match value {
            AttributeValue::BgpPrefixSid(attr) => {
                assert!(attr.tlvs.is_empty());
                assert_eq!(encode_bgp_prefix_sid(&attr), Bytes::new());
            }
            value => panic!("expected Prefix-SID, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_prefix_sid_rejects_truncated_tlv() {
        assert!(parse_bgp_prefix_sid(Bytes::from_static(&[0x01, 0x00])).is_err());
        assert!(parse_bgp_prefix_sid(Bytes::from_static(&[0x01, 0x00, 0x02, 0xaa])).is_err());
    }
}
