use crate::models::{CommonHeader, EntryType};
use crate::ParserError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Read;

/// MRT common header [RFC6396][header].
///
/// [header]: https://tools.ietf.org/html/rfc6396#section-4.1
///
/// A MRT record is constructed as the following:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Type              |            Subtype            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Length                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Message... (variable)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ```
///
/// Or with extended timestamp:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Type              |            Subtype            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Length                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Microsecond Timestamp                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Message... (variable)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn parse_common_header<T: Read>(input: &mut T) -> Result<CommonHeader, ParserError> {
    let mut raw_bytes = [0u8; 12];
    input.read_exact(&mut raw_bytes)?;
    let mut data = &raw_bytes[..];

    let timestamp = data.get_u32();
    let entry_type_raw = data.get_u16();
    let entry_type = EntryType::try_from(entry_type_raw)?;
    let entry_subtype = data.get_u16();
    // the length field does not include the length of the common header
    let mut length = data.get_u32();

    let microsecond_timestamp = match &entry_type {
        EntryType::BGP4MP_ET => {
            // For ET records, the on-wire length includes the extra 4-byte microsecond timestamp
            // that lives in the header. Internally we store `length` as the message length only,
            // so subtract 4 after validating to avoid underflow.
            if length < 4 {
                return Err(ParserError::ParseError(
                    "invalid MRT header length for ET record: length < 4".into(),
                ));
            }
            length -= 4;
            let mut raw_bytes: [u8; 4] = [0; 4];
            input.read_exact(&mut raw_bytes)?;
            Some((&raw_bytes[..]).get_u32())
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

    /// Ensure ET header with invalid on-wire length (< 4) returns error instead of panicking.
    #[test]
    fn test_parse_common_header_et_invalid_length() {
        // Construct a header with length=3 for ET (which is invalid since it must include 4 bytes of microsecond field)
        let bytes = Bytes::from_static(&[
            0, 0, 0, 0, // timestamp
            0, 17, // entry type = BGP4MP_ET
            0, 0, // subtype
            0, 0, 0, 3, // length (invalid for ET)
        ]);
        let mut reader = bytes.reader();
        let res = parse_common_header(&mut reader);
        assert!(res.is_err());
    }
}
