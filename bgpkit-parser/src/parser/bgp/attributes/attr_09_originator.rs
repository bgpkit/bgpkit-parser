use crate::parser::ReadUtils;
use crate::ParserError;
use bgp_models::prelude::*;
use std::io::Cursor;

pub fn parse_originator_id(
    input: &mut Cursor<&[u8]>,
    afi: &Option<Afi>,
) -> Result<AttributeValue, ParserError> {
    let afi = match afi {
        None => &Afi::Ipv4,
        Some(a) => a,
    };
    let addr = input.read_address(afi)?;
    Ok(AttributeValue::OriginatorId(addr))
}
