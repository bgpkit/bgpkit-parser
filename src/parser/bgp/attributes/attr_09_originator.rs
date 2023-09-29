use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::Bytes;

pub fn parse_originator_id(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    input.expect_remaining_eq(4, "ORIGINATOR_ID")?;
    Ok(AttributeValue::OriginatorId(input.read_ipv4_address()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_parse_originator_id() {
        let ipv4 = Ipv4Addr::from_str("10.0.0.1").unwrap();
        if let Ok(AttributeValue::OriginatorId(n)) =
            parse_originator_id(Bytes::from(ipv4.octets().to_vec()))
        {
            assert_eq!(n, ipv4);
        } else {
            panic!()
        }
    }
}
