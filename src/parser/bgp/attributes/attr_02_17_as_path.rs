use crate::models::*;
// use crate::parser::ReadUtils;
use crate::ParserError;
use num_enum::TryFromPrimitive;
// use std::borrow::Cow;

#[allow(non_camel_case_types)]
#[derive(Debug, TryFromPrimitive)]
#[repr(u8)]
enum AsSegmentType {
    AS_PATH_AS_SET = 1,
    AS_PATH_AS_SEQUENCE = 2,
    // https://datatracker.ietf.org/doc/html/rfc5065
    AS_PATH_CONFED_SEQUENCE = 3,
    AS_PATH_CONFED_SET = 4,
}

pub fn parse_as_path(mut input: &[u8], asn_len: &AsnLength) -> Result<AsPath, ParserError> {
    // let mut output = AsPath {
    //     segments: Vec::with_capacity(5),
    // };
    // while !input.is_empty() {
    //     let segment = parse_as_path_segment(&mut input, asn_len)?;
    //     output.append_segment(segment);
    // }
    //
    // Ok(output)
    todo!()
}

fn parse_as_path_segment(
    input: &mut &[u8],
    asn_len: &AsnLength,
) -> Result<AsPathSegment<'static>, ParserError> {
    // let segment_type = AsSegmentType::try_from(input.read_u8()?)?;
    // let count = input.read_u8()? as usize;
    // let path = Cow::Owned(input.read_asns(asn_len, count)?);
    // match segment_type {
    //     AsSegmentType::AS_PATH_AS_SET => Ok(AsPathSegment::AsSet(path)),
    //     AsSegmentType::AS_PATH_AS_SEQUENCE => Ok(AsPathSegment::AsSequence(path)),
    //     AsSegmentType::AS_PATH_CONFED_SEQUENCE => Ok(AsPathSegment::ConfedSequence(path)),
    //     AsSegmentType::AS_PATH_CONFED_SET => Ok(AsPathSegment::ConfedSet(path)),
    // }
    todo!()
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
        let data = &[
            2, // sequence
            3, // 3 ASes in path
            0, 1, // AS1
            0, 2, // AS2
            0, 3, // AS3
        ];
        let path = parse_as_path(data, &AsnLength::Bits16).unwrap();
        assert_eq!(path, AsPath::from_sequence([1, 2, 3]));
    }

    #[test]
    fn test_parse_as_path_segment() {
        //////////////////////
        // 16 bits sequence //
        //////////////////////
        let mut data: &[u8] = &[
            2, // sequence
            3, // 3 ASes in path
            0, 1, // AS1
            0, 2, // AS2
            0, 3, // AS3
        ];
        let res = parse_as_path_segment(&mut data, &AsnLength::Bits16).unwrap();
        assert_eq!(res, AsPathSegment::sequence([1, 2, 3]));

        //////////////////////
        // 16 bits sequence //
        //////////////////////
        let mut data: &[u8] = &[
            2, // sequence
            3, // 3 ASes in path
            0, 0, 0, 1, // AS1
            0, 0, 0, 2, // AS2
            0, 0, 0, 3, // AS3
        ];
        let res = parse_as_path_segment(&mut data, &AsnLength::Bits32).unwrap();
        assert_eq!(res, AsPathSegment::sequence([1, 2, 3]));

        /////////////////
        // other types //
        /////////////////
        let mut data: &[u8] = &[
            1, // AS Set
            1, // 1 AS in path
            0, 1,
        ];
        let res = parse_as_path_segment(&mut data, &AsnLength::Bits16).unwrap();
        assert_eq!(res, AsPathSegment::set([1]));

        let mut data: &[u8] = &[
            3, // Confed Sequence
            1, // 1 AS in path
            0, 1,
        ];
        let res = parse_as_path_segment(&mut data, &AsnLength::Bits16).unwrap();
        assert!(matches!(res, AsPathSegment::ConfedSequence(_)));

        let mut data: &[u8] = &[
            4, // Confed Set
            1, // 1 AS in path
            0, 1,
        ];
        let res = parse_as_path_segment(&mut data, &AsnLength::Bits16).unwrap();
        assert!(matches!(res, AsPathSegment::ConfedSet(_)));

        let mut data: &[u8] = &[
            5, // ERROR
            1, // 1 AS in path
            0, 1,
        ];
        let res = parse_as_path_segment(&mut data, &AsnLength::Bits16).unwrap_err();
        assert!(matches!(res, ParserError::UnrecognizedEnumVariant { .. }));
    }
}
