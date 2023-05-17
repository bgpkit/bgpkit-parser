use crate::models::{CommonHeader, EntryType};
use crate::ParserError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_traits::FromPrimitive;
use std::io::Read;

/// MRT common header [RFC6396][header].
/// [header]: https://tools.ietf.org/html/rfc6396#section-4.1
pub fn parse_common_header<T: Read>(input: &mut T) -> Result<CommonHeader, ParserError> {
    let mut raw_bytes = [0u8; 12];
    input.read_exact(&mut raw_bytes)?;
    let mut data = BytesMut::from(&raw_bytes[..]);

    let timestamp = data.get_u32();
    let entry_type_raw = data.get_u16();
    let entry_type = EntryType::from_u16(entry_type_raw).ok_or_else(|| {
        ParserError::ParseError(format!("Failed to parse entry type: {}", entry_type_raw))
    })?;
    let entry_subtype = data.get_u16();
    // the length field does not include the length of the common header
    let mut length = data.get_u32();

    let microsecond_timestamp = match &entry_type {
        EntryType::BGP4MP_ET => {
            length -= 4;
            let mut raw_bytes: [u8; 4] = [0; 4];
            input.read_exact(&mut raw_bytes)?;
            Some(BytesMut::from(&raw_bytes[..]).get_u32())
        }
        _ => None,
    };

    Ok(CommonHeader {
        timestamp,
        microsecond_timestamp,
        entry_type,
        entry_subtype,
        length,
    })
}

impl CommonHeader {
    pub fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&self.timestamp.to_be_bytes());
        bytes.put_u16(self.entry_type as u16);
        bytes.put_u16(self.entry_subtype);

        match self.microsecond_timestamp {
            None => bytes.put_u32(self.length),
            Some(microseconds) => {
                // When the microsecond timestamp is present, the length must be adjusted to account
                // for the stace used by the extra timestamp data.
                bytes.put_u32(self.length + 4);
                bytes.put_u32(microseconds);
            }
        };
        bytes.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EntryType;
    use bytes::Buf;

    /// Test that the length is not adjusted when the microsecond timestamp is not present.
    #[test]
    fn test_encode_common_header() {
        let header = CommonHeader {
            timestamp: 1,
            microsecond_timestamp: None,
            entry_type: EntryType::BGP4MP,
            entry_subtype: 4,
            length: 5,
        };

        let expected = Bytes::from_static(&[
            0, 0, 0, 1, // timestamp
            0, 16, // entry type
            0, 4, // entry subtype
            0, 0, 0, 5, // length
        ]);

        let encoded = header.encode();
        assert_eq!(encoded, expected);

        let mut reader = expected.reader();
        let parsed = parse_common_header(&mut reader).unwrap();
        assert_eq!(parsed, header);
    }

    /// Test that the length is adjusted when the microsecond timestamp is present.
    #[test]
    fn test_encode_common_header_et() {
        let header = CommonHeader {
            timestamp: 1,
            microsecond_timestamp: Some(230_000),
            entry_type: EntryType::BGP4MP_ET,
            entry_subtype: 4,
            length: 5,
        };

        let expected = Bytes::from_static(&[
            0, 0, 0, 1, // timestamp
            0, 17, // entry type
            0, 4, // entry subtype
            0, 0, 0, 9, // length
            0, 3, 130, 112, // microsecond timestamp
        ]);

        let encoded = header.encode();
        assert_eq!(encoded, expected);

        let mut reader = expected.reader();
        let parsed = parse_common_header(&mut reader).unwrap();
        assert_eq!(parsed, header);
    }
}
