use crate::parser::ReadUtils;
use crate::ParserError;
use bgp_models::prelude::*;
use std::io::Cursor;

pub fn parse_next_hop(
    input: &mut Cursor<&[u8]>,
    afi: &Option<Afi>,
) -> Result<AttributeValue, ParserError> {
    if let Some(afi) = afi {
        Ok(input.read_address(afi).map(AttributeValue::NextHop)?)
    } else {
        Ok(input
            .read_address(&Afi::Ipv4)
            .map(AttributeValue::NextHop)?)
    }
}
