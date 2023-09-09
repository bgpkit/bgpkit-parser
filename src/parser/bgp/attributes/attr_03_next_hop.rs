use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use std::net::IpAddr;

pub fn parse_next_hop(mut input: &[u8], afi: &Option<Afi>) -> Result<AttributeValue, ParserError> {
    match afi.unwrap_or(Afi::Ipv4) {
        Afi::Ipv4 => {
            input.expect_remaining_eq(4, "NEXT_HOP")?;
            Ok(input
                .read_ipv4_address()
                .map(IpAddr::V4)
                .map(AttributeValue::NextHop)?)
        }
        Afi::Ipv6 => {
            input.expect_remaining_eq(16, "NEXT_HOP")?;
            Ok(input
                .read_ipv6_address()
                .map(IpAddr::V6)
                .map(AttributeValue::NextHop)?)
        }
    }
}

pub fn parse_mp_next_hop(mut input: &[u8]) -> Result<Option<NextHopAddress>, ParserError> {
    match input.len() {
        0 => Ok(None),
        4 => Ok(Some(input.read_ipv4_address().map(NextHopAddress::Ipv4)?)),
        16 => Ok(Some(input.read_ipv6_address().map(NextHopAddress::Ipv6)?)),
        32 => Ok(Some(NextHopAddress::Ipv6LinkLocal(
            input.read_ipv6_address()?,
            input.read_ipv6_address()?,
        ))),
        v => Err(ParserError::InvalidNextHopLength(v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_parse_next_hop() {
        let ipv4 = Ipv4Addr::from_str("10.0.0.1").unwrap();
        let ipv6 = Ipv6Addr::from_str("FC00::1").unwrap();
        let ipv4_bytes = &ipv4.octets();
        let ipv6_bytes = &ipv6.octets();

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
        let ipv4 = Ipv4Addr::from_str("10.0.0.1").unwrap().octets();
        let ipv6 = Ipv6Addr::from_str("fc00::1").unwrap().octets();
        let ipv6_2 = Ipv6Addr::from_str("fc00::2").unwrap().octets();

        if let Some(NextHopAddress::Ipv4(n)) = parse_mp_next_hop(&ipv4).unwrap() {
            assert_eq!(n.to_string(), "10.0.0.1".to_string())
        } else {
            panic!();
        }

        if let Some(NextHopAddress::Ipv6(n)) = parse_mp_next_hop(&ipv6).unwrap() {
            assert_eq!(n.to_string(), "fc00::1".to_string())
        } else {
            panic!();
        }

        let mut combined = ipv6.to_vec();
        combined.extend_from_slice(&ipv6_2);

        if let Some(NextHopAddress::Ipv6LinkLocal(n, m)) = parse_mp_next_hop(&combined).unwrap() {
            assert_eq!(n.to_string(), "fc00::1".to_string());
            assert_eq!(m.to_string(), "fc00::2".to_string());
        } else {
            panic!();
        }
    }
}
