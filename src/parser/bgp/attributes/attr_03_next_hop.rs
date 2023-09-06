use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::Bytes;

pub fn parse_next_hop(mut input: Bytes, afi: &Option<Afi>) -> Result<AttributeValue, ParserError> {
    if let Some(afi) = afi {
        Ok(input.read_address(afi).map(AttributeValue::NextHop)?)
    } else {
        Ok(input
            .read_address(&Afi::Ipv4)
            .map(AttributeValue::NextHop)?)
    }
}

pub fn parse_mp_next_hop(mut input: Bytes) -> Result<Option<NextHopAddress>, ParserError> {
    let output = match input.len() {
        0 => None,
        4 => Some(input.read_ipv4_address().map(NextHopAddress::Ipv4)?),
        16 => Some(input.read_ipv6_address().map(NextHopAddress::Ipv6)?),
        32 => Some(NextHopAddress::Ipv6LinkLocal(
            input.read_ipv6_address()?,
            input.read_ipv6_address()?,
        )),
        v => {
            return Err(ParserError::ParseError(format!(
                "Invalid next hop length found: {}",
                v
            )));
        }
    };
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_parse_next_hop() {
        let ipv4 = Ipv4Addr::from_str("10.0.0.1").unwrap();
        let ipv6 = Ipv6Addr::from_str("FC00::1").unwrap();
        let ipv4_bytes = Bytes::from(ipv4.octets().to_vec());
        let ipv6_bytes = Bytes::from(ipv6.octets().to_vec());

        let res = parse_next_hop(ipv4_bytes, &None).unwrap();
        if let AttributeValue::NextHop(n) = res {
            assert_eq!(n.to_string(), "10.0.0.1".to_string())
        } else {
            panic!();
        }

        let res = parse_next_hop(ipv6_bytes, &Some(Afi::Ipv6)).unwrap();
        if let AttributeValue::NextHop(n) = res {
            assert_eq!(n.to_string().to_ascii_uppercase(), "FC00::1".to_string())
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_np_next_hop() {
        let ipv4 = Bytes::from(Ipv4Addr::from_str("10.0.0.1").unwrap().octets().to_vec());
        let ipv6 = Bytes::from(Ipv6Addr::from_str("fc00::1").unwrap().octets().to_vec());
        let ipv6_2 = Bytes::from(Ipv6Addr::from_str("fc00::2").unwrap().octets().to_vec());

        if let Some(NextHopAddress::Ipv4(n)) = parse_mp_next_hop(ipv4).unwrap() {
            assert_eq!(n.to_string(), "10.0.0.1".to_string())
        } else {
            panic!();
        }

        if let Some(NextHopAddress::Ipv6(n)) = parse_mp_next_hop(ipv6.clone()).unwrap() {
            assert_eq!(n.to_string(), "fc00::1".to_string())
        } else {
            panic!();
        }

        let mut combined = BytesMut::from(ipv6.to_vec().as_slice());
        combined.extend_from_slice(&ipv6_2);

        if let Some(NextHopAddress::Ipv6LinkLocal(n, m)) =
            parse_mp_next_hop(combined.into()).unwrap()
        {
            assert_eq!(n.to_string(), "fc00::1".to_string());
            assert_eq!(m.to_string(), "fc00::2".to_string());
        } else {
            panic!();
        }
    }
}
