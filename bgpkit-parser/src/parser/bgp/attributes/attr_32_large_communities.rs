use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, Bytes};

pub fn parse_large_communities(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    let mut communities = Vec::new();
    while input.remaining() > 0 {
        input.has_n_remaining(12)?; // 12 bytes for large community (3x 32 bits integers)
        let global_administrator = input.get_u32();
        let local_data = [input.get_u32(), input.get_u32()];
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
            parse_large_communities(Bytes::from(data))
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
