use crate::models::builder::AsPathBuilder;
use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use num_enum::TryFromPrimitive;

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

pub fn parse_as_path(input: &[u8], asn_len: AsnLength) -> Result<AsPath, ParserError> {
    match asn_len {
        AsnLength::Bits16 => read_as_path_16bit(input),
        AsnLength::Bits32 => read_as_path_32bit(input),
    }
}

fn read_as_path_16bit(mut input: &[u8]) -> Result<AsPath, ParserError> {
    let mut builder = AsPathBuilder::default();

    while !input.is_empty() {
        let segment_type = AsSegmentType::try_from(input.read_u8()?)?;
        let count = input.read_u8()? as usize;
        input.require_n_remaining(count * 2, "AS_PATH")?;

        let mut segment_builder = match segment_type {
            AsSegmentType::AS_PATH_AS_SEQUENCE => builder.begin_as_sequence(count),
            AsSegmentType::AS_PATH_AS_SET => builder.begin_as_set(count),
            AsSegmentType::AS_PATH_CONFED_SEQUENCE => builder.begin_confed_sequence(count),
            AsSegmentType::AS_PATH_CONFED_SET => builder.begin_confed_set(count),
        };

        for _ in 0..count {
            segment_builder.push(Asn::new_16bit(input.read_u16()?));
        }
    }

    Ok(builder.build())
}

fn read_as_path_32bit(mut input: &[u8]) -> Result<AsPath, ParserError> {
    let mut builder = AsPathBuilder::default();

    while !input.is_empty() {
        let segment_type = AsSegmentType::try_from(input.read_u8()?)?;
        let count = input.read_u8()? as usize;
        input.require_n_remaining(count * 4, "AS4_PATH")?;

        let mut segment_builder = match segment_type {
            AsSegmentType::AS_PATH_AS_SEQUENCE => builder.begin_as_sequence(count),
            AsSegmentType::AS_PATH_AS_SET => builder.begin_as_set(count),
            AsSegmentType::AS_PATH_CONFED_SEQUENCE => builder.begin_confed_sequence(count),
            AsSegmentType::AS_PATH_CONFED_SET => builder.begin_confed_set(count),
        };

        for _ in 0..count {
            segment_builder.push(Asn::new_32bit(input.read_u32()?));
        }
    }

    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_as_path_segment(
        input: &mut &[u8],
        asn_len: AsnLength,
    ) -> Result<AsPathSegment<'static>, ParserError> {
        let path = match asn_len {
            AsnLength::Bits16 => read_as_path_16bit(input),
            AsnLength::Bits32 => read_as_path_32bit(input),
        }?;

        Ok(path.into_segments_iter().next().unwrap())
    }

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
        let path = parse_as_path(data, AsnLength::Bits16).unwrap();
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
        let res = parse_as_path_segment(&mut data, AsnLength::Bits16).unwrap();
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
        let res = parse_as_path_segment(&mut data, AsnLength::Bits32).unwrap();
        assert_eq!(res, AsPathSegment::sequence([1, 2, 3]));

        /////////////////
        // other types //
        /////////////////
        let mut data: &[u8] = &[
            1, // AS Set
            1, // 1 AS in path
            0, 1,
        ];
        let res = parse_as_path_segment(&mut data, AsnLength::Bits16).unwrap();
        assert_eq!(res, AsPathSegment::set([1]));

        let mut data: &[u8] = &[
            3, // Confed Sequence
            1, // 1 AS in path
            0, 1,
        ];
        let res = parse_as_path_segment(&mut data, AsnLength::Bits16).unwrap();
        assert!(matches!(res, AsPathSegment::ConfedSequence(_)));

        let mut data: &[u8] = &[
            4, // Confed Set
            1, // 1 AS in path
            0, 1,
        ];
        let res = parse_as_path_segment(&mut data, AsnLength::Bits16).unwrap();
        assert!(matches!(res, AsPathSegment::ConfedSet(_)));

        let mut data: &[u8] = &[
            5, // ERROR
            1, // 1 AS in path
            0, 1,
        ];
        let res = parse_as_path_segment(&mut data, AsnLength::Bits16).unwrap_err();
        assert!(matches!(res, ParserError::UnrecognizedEnumVariant { .. }));
    }
}
