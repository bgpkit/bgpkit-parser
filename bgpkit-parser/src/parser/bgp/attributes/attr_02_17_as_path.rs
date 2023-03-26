use crate::parser::ReadUtils;
use crate::ParserError;
use bgp_models::prelude::*;
use std::io::Cursor;

const AS_PATH_AS_SET: u8 = 1;
const AS_PATH_AS_SEQUENCE: u8 = 2;
// https://datatracker.ietf.org/doc/html/rfc5065
const AS_PATH_CONFED_SEQUENCE: u8 = 3;
const AS_PATH_CONFED_SET: u8 = 4;

pub fn parse_as_path(
    input: &mut Cursor<&[u8]>,
    asn_len: &AsnLength,
    total_bytes: usize,
) -> Result<AttributeValue, ParserError> {
    let mut output = AsPath {
        segments: Vec::with_capacity(5),
    };
    let pos_end = input.position() + total_bytes as u64;
    while input.position() < pos_end {
        let segment = parse_as_path_segment(input, asn_len)?;
        output.add_segment(segment);
    }
    Ok(AttributeValue::AsPath(output))
}

fn parse_as_path_segment(
    input: &mut Cursor<&[u8]>,
    asn_len: &AsnLength,
) -> Result<AsPathSegment, ParserError> {
    let segment_type = input.read_8b()?;
    let count = input.read_8b()?;
    let path = input.read_asns(asn_len, count as usize)?;
    match segment_type {
        AS_PATH_AS_SET => Ok(AsPathSegment::AsSet(path)),
        AS_PATH_AS_SEQUENCE => Ok(AsPathSegment::AsSequence(path)),
        AS_PATH_CONFED_SEQUENCE => Ok(AsPathSegment::ConfedSequence(path)),
        AS_PATH_CONFED_SET => Ok(AsPathSegment::ConfedSet(path)),
        _ => Err(ParserError::ParseError(format!(
            "Invalid AS path segment type: {}",
            segment_type
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_models::prelude::AttributeValue::AsPath;

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
        let data: [u8; 8] = [
            2, // sequence
            3, // 3 ASes in path
            0, 1, // AS1
            0, 2, // AS2
            0, 3, // AS3
        ];
        let res = parse_as_path(&mut Cursor::new(&data), &AsnLength::Bits16, 8).unwrap();

        assert!(matches!(res, AsPath(_)));
        if let AsPath(path) = res {
            assert_eq!(vec![1, 2, 3], path.to_u32_vec().unwrap())
        } else {
            panic!("cannot parse the path")
        }
    }

    #[test]
    fn test_parse_as_path_segment() {
        //////////////////////
        // 16 bits sequence //
        //////////////////////
        let data: [u8; 8] = [
            2, // sequence
            3, // 3 ASes in path
            0, 1, // AS1
            0, 2, // AS2
            0, 3, // AS3
        ];
        let res = parse_as_path_segment(&mut Cursor::new(&data), &AsnLength::Bits16).unwrap();

        assert!(matches!(res, AsPathSegment::AsSequence(_)));
        if let AsPathSegment::AsSequence(p) = res {
            let asns: Vec<u32> = p.into_iter().map(|a| a.asn).collect();
            assert_eq!(asns, vec![1, 2, 3]);
        } else {
            panic!("not a as sequence")
        }

        //////////////////////
        // 16 bits sequence //
        //////////////////////
        let data: [u8; 14] = [
            2, // sequence
            3, // 3 ASes in path
            0, 0, 0, 1, // AS1
            0, 0, 0, 2, // AS2
            0, 0, 0, 3, // AS3
        ];
        let res = parse_as_path_segment(&mut Cursor::new(&data), &AsnLength::Bits32).unwrap();
        assert!(matches!(res, AsPathSegment::AsSequence(_)));
        if let AsPathSegment::AsSequence(p) = res {
            let asns: Vec<u32> = p.into_iter().map(|a| a.asn).collect();
            assert_eq!(asns, vec![1, 2, 3]);
        } else {
            panic!("not a as sequence")
        }

        /////////////////
        // other types //
        /////////////////
        let data: [u8; 4] = [
            1, // AS Set
            1, // 1 AS in path
            0, 1,
        ];
        let res = parse_as_path_segment(&mut Cursor::new(&data), &AsnLength::Bits16).unwrap();
        assert!(matches!(res, AsPathSegment::AsSet(_)));

        let data: [u8; 4] = [
            3, // Confed Sequence
            1, // 1 AS in path
            0, 1,
        ];
        let res = parse_as_path_segment(&mut Cursor::new(&data), &AsnLength::Bits16).unwrap();
        assert!(matches!(res, AsPathSegment::ConfedSequence(_)));

        let data: [u8; 4] = [
            4, // Confed Set
            1, // 1 AS in path
            0, 1,
        ];
        let res = parse_as_path_segment(&mut Cursor::new(&data), &AsnLength::Bits16).unwrap();
        assert!(matches!(res, AsPathSegment::ConfedSet(_)));

        let data: [u8; 4] = [
            5, // ERROR
            1, // 1 AS in path
            0, 1,
        ];
        let res = parse_as_path_segment(&mut Cursor::new(&data), &AsnLength::Bits16).unwrap_err();
        assert!(matches!(res, ParserError::ParseError(_)));
    }
}
