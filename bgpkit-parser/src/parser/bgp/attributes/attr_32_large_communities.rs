use crate::parser::ReadUtils;
use crate::ParserError;
use bgp_models::prelude::*;
use std::io::Cursor;

pub fn parse_large_communities(
    input: &mut Cursor<&[u8]>,
    total_bytes: usize,
) -> Result<AttributeValue, ParserError> {
    let mut communities = Vec::new();
    let pos_end = input.position() + total_bytes as u64;
    while input.position() < pos_end {
        let global_administrator = input.read_32b()?;
        let local_data = [input.read_32b()?, input.read_32b()?];
        communities.push(LargeCommunity::new(global_administrator, local_data));
    }
    Ok(AttributeValue::LargeCommunities(communities))
}
