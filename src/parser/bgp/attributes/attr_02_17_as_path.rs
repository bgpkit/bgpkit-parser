use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

const AS_PATH_AS_SET: u8 = 1;
const AS_PATH_AS_SEQUENCE: u8 = 2;
// https://datatracker.ietf.org/doc/html/rfc5065
const AS_PATH_CONFED_SEQUENCE: u8 = 3;
const AS_PATH_CONFED_SET: u8 = 4;

pub fn parse_as_path(mut input: Bytes, asn_len: &AsnLength) -> Result<AsPath, ParserError> {
    let mut output = AsPath {
        segments: Vec::with_capacity(5),
    };
    while input.remaining() > 0 {
        let segment = parse_as_path_segment(&mut input, asn_len)?;
        output.append_segment(segment);
    }

    Ok(output)
}

fn parse_as_path_segment(
    input: &mut Bytes,
    asn_len: &AsnLength,
) -> Result<AsPathSegment, ParserError> {
    let segment_type = input.read_u8()?;
    let count = input.read_u8()? as usize;

    // Validate AS_PATH segment count against remaining buffer size
    // to prevent reading beyond buffer bounds
    let required_bytes = count
        .checked_mul(asn_len.bytes())
        .ok_or_else(|| ParserError::ParseError("AS path segment too large".to_string()))?;
    if input.remaining() < required_bytes {
        return Err(ParserError::TruncatedMsg(format!(
            "AS_PATH segment requires {} bytes, only {} remaining",
            required_bytes,
            input.remaining()
        )));
    }

    let path = input.read_asns(asn_len, count)?;
    match segment_type {
        AS_PATH_AS_SET => Ok(AsPathSegment::AsSet(path)),
        AS_PATH_AS_SEQUENCE => Ok(AsPathSegment::AsSequence(path)),
        AS_PATH_CONFED_SEQUENCE => Ok(AsPathSegment::ConfedSequence(path)),
        AS_PATH_CONFED_SET => Ok(AsPathSegment::ConfedSet(path)),
        _ => Err(ParserError::ParseError(format!(
            "Invalid AS path segment type: {segment_type}"
        ))),
    }
}

pub fn encode_as_path(path: &AsPath, asn_len: AsnLength) -> Bytes {
    let mut output = BytesMut::with_capacity(1024);
    for segment in path.segments.iter() {
        match segment {
            AsPathSegment::AsSet(asns) => {
                output.put_u8(AS_PATH_AS_SET);
                output.put_u8(asns.len() as u8);
                write_asns(asns, asn_len, &mut output);
            }
            AsPathSegment::AsSequence(asns) => {
                output.put_u8(AS_PATH_AS_SEQUENCE);
                output.put_u8(asns.len() as u8);
                write_asns(asns, asn_len, &mut output);
            }
            AsPathSegment::ConfedSequence(asns) => {
                output.put_u8(AS_PATH_CONFED_SEQUENCE);
                output.put_u8(asns.len() as u8);
                write_asns(asns, asn_len, &mut output);
            }
            AsPathSegment::ConfedSet(asns) => {
                output.put_u8(AS_PATH_CONFED_SET);
                output.put_u8(asns.len() as u8);
                write_asns(asns, asn_len, &mut output);
            }
        }
    }
    output.freeze()
}

fn write_asns(asns: &[Asn], asn_len: AsnLength, output: &mut BytesMut) {
    match asn_len {
        AsnLength::Bits16 => {
            for asn in asns.iter() {
                output.put_u16(asn.into());
            }
        }
        AsnLength::Bits32 => {
            for asn in asns.iter() {
                output.put_u32(asn.into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ///
    /// ```text
    /// AS_PATH is a well-known mandatory attribute that is composed
    /// of a sequence of AS path segments.  Each AS path segment is
    /// represented by a triple <path segment type, path segment
    /// length, path segment value>.
    ///
    /// The path segment type is a 1-octet length field with the
    /// following values defined:
    ///
    /// Value      Segment Type
    ///
    /// 1         AS_SET: unordered set of ASes a route in the
    /// UPDATE message has traversed
    ///
    /// 2         AS_SEQUENCE: ordered set of ASes a route in
    /// the UPDATE message has traversed
    ///
    /// The path segment length is a 1-octet length field,
    /// containing the number of ASes (not the number of octets) in
    /// the path segment value field.
    ///
    /// The path segment value field contains one or more AS
    /// numbers, each encoded as a 2-octet length field.
    ///
    /// Usage of this attribute is defined in 5.1.2.
    /// ```
    #[test]
    fn test_parse_as_path() {
        let data = Bytes::from(vec![
            2, // sequence
            3, // 3 ASes in path
            0, 1, // AS1
            0, 2, // AS2
            0, 3, // AS3
        ]);
        let path = parse_as_path(data.clone(), &AsnLength::Bits16).unwrap();
        assert_eq!(vec![1, 2, 3], path.to_u32_vec_opt(false).unwrap());

        let path = parse_as_path(data, &AsnLength::Bits16).unwrap();
        assert_eq!(
            path.to_u32_vec_opt(false),
            AsPath::from_sequence([1, 2, 3]).to_u32_vec_opt(false)
        );
    }

    #[test]
    fn test_parse_as_path_segment() {
        //////////////////////
        // 16 bits sequence //
        //////////////////////
        let mut data = Bytes::from(vec![
            2, // sequence
            3, // 3 ASes in path
            0, 1, // AS1
            0, 2, // AS2
            0, 3, // AS3
        ]);
        let res = parse_as_path_segment(&mut data, &AsnLength::Bits16).unwrap();
        assert_eq!(res, AsPathSegment::sequence([1, 2, 3]));

        //////////////////////
        // 32 bits sequence //
        //////////////////////
        let mut data = Bytes::from(vec![
            2, // sequence
            3, // 3 ASes in path
            0, 0, 0, 1, // AS1
            0, 0, 0, 2, // AS2
            0, 0, 0, 3, // AS3
        ]);
        let res = parse_as_path_segment(&mut data, &AsnLength::Bits32).unwrap();
        assert_eq!(res, AsPathSegment::sequence([1, 2, 3]));

        /////////////////
        // other types //
        /////////////////
        let mut data = Bytes::from(vec![
            1, // AS Set
            1, // 1 AS in path
            0, 1,
        ]);
        let res = parse_as_path_segment(&mut data, &AsnLength::Bits16).unwrap();
        assert_eq!(res, AsPathSegment::set([1]));

        let mut data = Bytes::from(vec![
            3, // Confed Sequence
            1, // 1 AS in path
            0, 1,
        ]);
        let res = parse_as_path_segment(&mut data, &AsnLength::Bits16).unwrap();
        assert!(matches!(res, AsPathSegment::ConfedSequence(_)));

        let mut data = Bytes::from(vec![
            4, // Confed Set
            1, // 1 AS in path
            0, 1,
        ]);
        let res = parse_as_path_segment(&mut data, &AsnLength::Bits16).unwrap();
        assert!(matches!(res, AsPathSegment::ConfedSet(_)));

        let mut data = Bytes::from(vec![
            5, // ERROR
            1, // 1 AS in path
            0, 1,
        ]);
        let res = parse_as_path_segment(&mut data, &AsnLength::Bits16).unwrap_err();
        assert!(matches!(res, ParserError::ParseError(_)));
    }

    #[test]
    fn test_encode_as_path() {
        let data = Bytes::from(vec![
            2, // sequence
            3, // 3 ASes in path
            0, 1, // AS1
            0, 2, // AS2
            0, 3, // AS3
        ]);
        let path = parse_as_path(data.clone(), &AsnLength::Bits16).unwrap();
        let encoded_bytes = encode_as_path(&path, AsnLength::Bits16);
        assert_eq!(data, encoded_bytes);

        let data = Bytes::from(vec![
            2, // sequence
            3, // 3 ASes in path
            0, 0, 0, 1, // AS1
            0, 0, 0, 2, // AS2
            0, 0, 0, 3, // AS3
        ]);
        let path = parse_as_path(data.clone(), &AsnLength::Bits32).unwrap();
        let encoded_bytes = encode_as_path(&path, AsnLength::Bits32);
        assert_eq!(data, encoded_bytes);
    }

    #[test]
    fn test_encode_confed() {
        let data = Bytes::from(vec![
            3, // Confed Sequence
            1, // 1 AS in path
            0, 1,
        ]);
        let path = parse_as_path(data.clone(), &AsnLength::Bits16).unwrap();
        let encoded_bytes = encode_as_path(&path, AsnLength::Bits16);
        assert_eq!(data, encoded_bytes);

        let data = Bytes::from(vec![
            4, // Confed Set
            1, // 1 AS in path
            0, 1,
        ]);
        let path = parse_as_path(data.clone(), &AsnLength::Bits16).unwrap();
        let encoded_bytes = encode_as_path(&path, AsnLength::Bits16);
        assert_eq!(data, encoded_bytes);
    }

    #[test]
    fn test_as_path_count_validation() {
        // Test that excessive count value is rejected (16-bit ASN)
        // count=100, but buffer only has 2 bytes
        let data = Bytes::from(vec![
            2,   // sequence
            100, // 100 ASes claimed, but buffer is too small
            0, 1, // Only 2 bytes available (1 ASN, not 100)
        ]);
        let result = parse_as_path(data, &AsnLength::Bits16);
        assert!(result.is_err());
        assert!(matches!(result, Err(ParserError::TruncatedMsg(_))));

        // Test that excessive count value is rejected (32-bit ASN)
        // count=50, but buffer only has 4 bytes
        let data = Bytes::from(vec![
            2,  // sequence
            50, // 50 ASes claimed (need 200 bytes), but buffer is too small
            0, 0, 0, 1, // Only 4 bytes available (1 ASN, not 50)
        ]);
        let result = parse_as_path(data, &AsnLength::Bits32);
        assert!(result.is_err());
        assert!(matches!(result, Err(ParserError::TruncatedMsg(_))));

        // Test valid count passes
        let data = Bytes::from(vec![
            2, // sequence
            2, // 2 ASes
            0, 1, 0, 2, // 2 ASNs (4 bytes for 16-bit)
        ]);
        let result = parse_as_path(data, &AsnLength::Bits16);
        assert!(result.is_ok());
    }
}
