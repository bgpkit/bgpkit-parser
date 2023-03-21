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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_large_communities() {
        let data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x01, // global administrator
            0x00, 0x00, 0x00, 0x02, // local data
            0x00, 0x00, 0x00, 0x03, // local data
            0x00, 0x00, 0x00, 0x04, // global administrator
            0x00, 0x00, 0x00, 0x05, // local data
            0x00, 0x00, 0x00, 0x06, // local data
        ];

        if let Ok(AttributeValue::LargeCommunities(communities)) =
            parse_large_communities(&mut Cursor::new(&data), data.len())
        {
            assert_eq!(communities.len(), 2);
            assert_eq!(communities[0].global_administrator, 1);
            assert_eq!(communities[0].local_data[0], 2);
            assert_eq!(communities[0].local_data[1], 3);
            assert_eq!(communities[1].global_administrator, 4);
            assert_eq!(communities[1].local_data[0], 5);
            assert_eq!(communities[1].local_data[1], 6);
        } else {
            panic!()
        }
    }
}
