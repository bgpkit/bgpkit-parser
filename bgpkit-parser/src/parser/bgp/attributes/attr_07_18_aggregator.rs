use crate::parser::ReadUtils;
use crate::ParserError;
use bgp_models::prelude::*;
use std::io::Cursor;

pub fn parse_aggregator(
    input: &mut Cursor<&[u8]>,
    asn_len: &AsnLength,
    afi: &Option<Afi>,
) -> Result<AttributeValue, ParserError> {
    let asn = input.read_asn(asn_len)?;
    let afi = match afi {
        None => &Afi::Ipv4,
        Some(a) => a,
    };
    let addr = input.read_address(afi)?;
    Ok(AttributeValue::Aggregator(asn, addr))
}
