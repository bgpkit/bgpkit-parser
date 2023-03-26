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

pub fn parse_mp_next_hop(
    next_hop_length: u8,
    input: &mut Cursor<&[u8]>,
) -> Result<Option<NextHopAddress>, ParserError> {
    let output = match next_hop_length {
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
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_parse_next_hop() {
        let ipv4 = Ipv4Addr::from_str("10.0.0.1").unwrap();
        let ipv6 = Ipv6Addr::from_str("FC00::1").unwrap();

        let res = parse_next_hop(&mut Cursor::new(&ipv4.octets()), &None).unwrap();
        if let AttributeValue::NextHop(n) = res {
            assert_eq!(n.to_string(), "10.0.0.1".to_string())
        } else {
            panic!();
        }

        let res = parse_next_hop(&mut Cursor::new(&ipv6.octets()), &Some(Afi::Ipv6)).unwrap();
        if let AttributeValue::NextHop(n) = res {
            assert_eq!(n.to_string().to_ascii_uppercase(), "FC00::1".to_string())
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_np_next_hop() {
        let ipv4 = Ipv4Addr::from_str("10.0.0.1").unwrap();
        let ipv6 = Ipv6Addr::from_str("fc00::1").unwrap();
        let ipv6_2 = Ipv6Addr::from_str("fc00::2").unwrap();

        assert_eq!(
            None,
            parse_mp_next_hop(0, &mut Cursor::new(&ipv4.octets())).unwrap()
        );

        if let Some(NextHopAddress::Ipv4(n)) =
            parse_mp_next_hop(4, &mut Cursor::new(&ipv4.octets())).unwrap()
        {
            assert_eq!(n.to_string(), "10.0.0.1".to_string())
        } else {
            panic!();
        }

        if let Some(NextHopAddress::Ipv6(n)) =
            parse_mp_next_hop(16, &mut Cursor::new(&ipv6.octets())).unwrap()
        {
            assert_eq!(n.to_string(), "fc00::1".to_string())
        } else {
            panic!();
        }

        let mut bytes = vec![];
        bytes.extend(ipv6.octets());
        bytes.extend(ipv6_2.octets());

        if let Some(NextHopAddress::Ipv6LinkLocal(n, m)) =
            parse_mp_next_hop(32, &mut Cursor::new(&bytes)).unwrap()
        {
            assert_eq!(n.to_string(), "fc00::1".to_string());
            assert_eq!(m.to_string(), "fc00::2".to_string());
        } else {
            panic!();
        }
    }
}
