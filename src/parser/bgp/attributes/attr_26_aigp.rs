use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Parse AIGP attribute TLVs (RFC 7311).
pub fn parse_aigp(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    let mut tlvs = Vec::new();

    while input.remaining() > 0 {
        if input.remaining() < 3 {
            return Err(ParserError::TruncatedMsg(
                "truncated AIGP TLV header".to_string(),
            ));
        }

        let tlv_type = input.read_u8()?;
        let length = input.read_u16()?;
        if length < 3 {
            return Err(ParserError::ParseError(format!(
                "invalid AIGP TLV length {length} for type {tlv_type}"
            )));
        }

        let value_len = (length - 3) as usize;
        if input.remaining() < value_len {
            return Err(ParserError::TruncatedMsg(format!(
                "truncated AIGP TLV value for type {tlv_type}: need {value_len}, have {}",
                input.remaining()
            )));
        }

        let value = input.split_to(value_len);
        tlvs.push(AigpTlv {
            tlv_type,
            length,
            value,
        });
    }

    Ok(AttributeValue::Aigp(Aigp { tlvs }))
}

pub fn encode_aigp(aigp: &Aigp) -> Bytes {
    let mut buf = BytesMut::new();
    for tlv in &aigp.tlvs {
        let length = if tlv.length as usize == tlv.value.len() + 3 {
            tlv.length
        } else {
            (tlv.value.len() + 3) as u16
        };
        buf.put_u8(tlv.tlv_type);
        buf.put_u16(length);
        buf.extend_from_slice(&tlv.value);
    }
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_aigp_metric_tlv() {
        let input = Bytes::from_static(&[
            0x01, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a,
        ]);
        let value = parse_aigp(input).unwrap();
        match value {
            AttributeValue::Aigp(aigp) => {
                assert_eq!(aigp.tlvs.len(), 1);
                assert_eq!(aigp.tlvs[0].tlv_type, 1);
                assert_eq!(aigp.tlvs[0].length, 11);
                assert_eq!(aigp.accumulated_metric(), Some(42));
            }
            value => panic!("expected AIGP, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_aigp_unknown_tlv_and_round_trip() {
        let input = Bytes::from_static(&[0x7f, 0x00, 0x05, 0xaa, 0xbb]);
        let value = parse_aigp(input.clone()).unwrap();
        match value {
            AttributeValue::Aigp(aigp) => {
                assert_eq!(aigp.tlvs.len(), 1);
                assert_eq!(aigp.tlvs[0].tlv_type, 0x7f);
                assert_eq!(aigp.tlvs[0].value, Bytes::from_static(&[0xaa, 0xbb]));
                assert_eq!(encode_aigp(&aigp), input);
            }
            value => panic!("expected AIGP, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_aigp_rejects_short_tlv() {
        assert!(parse_aigp(Bytes::from_static(&[0x01, 0x00])).is_err());
    }

    #[test]
    fn test_parse_aigp_rejects_invalid_length() {
        // TLV with length < 3 (type=1, length=2)
        let input = Bytes::from_static(&[0x01, 0x00, 0x02, 0x00]);
        assert!(parse_aigp(input).is_err());
    }

    #[test]
    fn test_parse_aigp_rejects_truncated_value() {
        // TLV header claims 8 bytes total (value_len=5), but only 3 bytes after header
        let input = Bytes::from_static(&[0x01, 0x00, 0x08, 0x00, 0x00, 0x00]);
        assert!(parse_aigp(input).is_err());
    }

    #[test]
    fn test_encode_aigp_corrects_mismatched_length() {
        // stored length (3) does not match actual value len (0) + 3
        let aigp = Aigp {
            tlvs: vec![AigpTlv {
                tlv_type: 1,
                length: 3,
                value: Bytes::new(),
            }],
        };
        let encoded = encode_aigp(&aigp);
        // corrected length: 0 value bytes + 3 header = 3
        assert_eq!(encoded, Bytes::from_static(&[0x01, 0x00, 0x03]));
    }
}
