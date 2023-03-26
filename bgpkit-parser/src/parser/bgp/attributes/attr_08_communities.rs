use crate::parser::ReadUtils;
use crate::ParserError;
use bgp_models::prelude::*;
use log::debug;
use std::io::Cursor;

pub fn parse_regular_communities(
    input: &mut Cursor<&[u8]>,
    total_bytes: usize,
) -> Result<AttributeValue, ParserError> {
    const COMMUNITY_NO_EXPORT: u32 = 0xFFFFFF01;
    const COMMUNITY_NO_ADVERTISE: u32 = 0xFFFFFF02;
    const COMMUNITY_NO_EXPORT_SUBCONFED: u32 = 0xFFFFFF03;

    debug!(
        "reading communities. cursor_pos: {}/{}; total to read: {}",
        input.position(),
        input.get_ref().len(),
        total_bytes
    );

    let mut communities = vec![];
    let mut read = 0;

    while read < total_bytes {
        let community_val = input.read_32b()?;
        communities.push(match community_val {
            COMMUNITY_NO_EXPORT => Community::NoExport,
            COMMUNITY_NO_ADVERTISE => Community::NoAdvertise,
            COMMUNITY_NO_EXPORT_SUBCONFED => Community::NoExportSubConfed,
            value => {
                let asn = Asn {
                    asn: ((value >> 16) & 0xffff),
                    len: AsnLength::Bits16,
                };
                let value = (value & 0xffff) as u16;
                Community::Custom(asn, value)
            }
        });
        read += 4;
    }

    debug!(
        "finished reading communities. cursor_pos: {}/{}; {:?}",
        input.position(),
        input.get_ref().len(),
        &communities
    );
    Ok(AttributeValue::Communities(communities))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test parsing of communities values, as defined in RFC1997.
    #[test]
    fn test_parse_communities() {
        if let Ok(AttributeValue::Communities(communities)) = parse_regular_communities(
            &mut Cursor::new(&[
                0xFF, 0xFF, 0xFF, 0x01, // NoExport
                0xFF, 0xFF, 0xFF, 0x02, // NoAdvertise
                0xFF, 0xFF, 0xFF, 0x03, // NoExportSubConfed
                0x00, 0x7B, 0x01, 0xC8, // Custom(123, 456)
            ]),
            16,
        ) {
            assert_eq!(communities.len(), 4);
            assert_eq!(communities[0], Community::NoExport);
            assert_eq!(communities[1], Community::NoAdvertise);
            assert_eq!(communities[2], Community::NoExportSubConfed);
            assert_eq!(communities[3], Community::Custom(Asn::from(123), 456));
        } else {
            panic!("parsing error");
        }
    }
}
