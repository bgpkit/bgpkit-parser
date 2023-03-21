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
