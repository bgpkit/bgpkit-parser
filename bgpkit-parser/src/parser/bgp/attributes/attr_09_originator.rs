use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::Bytes;
use std::net::IpAddr;

pub fn parse_originator_id(
    mut input: Bytes,
    afi: &Option<Afi>,
) -> Result<AttributeValue, ParserError> {
    let afi = match afi {
        None => &Afi::Ipv4,
        Some(a) => a,
    };
    let addr = input.read_address(afi)?;
    Ok(AttributeValue::OriginatorId(addr))
}

pub fn encode_originator_id(addr: &IpAddr) -> Bytes {
    match addr {
        IpAddr::V4(ip) => Bytes::from(ip.octets().to_vec()),
        IpAddr::V6(ip) => Bytes::from(ip.octets().to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_parse_originator_id() {
        let ipv4 = Ipv4Addr::from_str("10.0.0.1").unwrap();
        if let Ok(AttributeValue::OriginatorId(n)) =
            parse_originator_id(Bytes::from(ipv4.octets().to_vec()), &None)
        {
            assert_eq!(n, ipv4);
        } else {
            panic!()
        }

        let ipv6 = Ipv6Addr::from_str("fc::1").unwrap();
        if let Ok(AttributeValue::OriginatorId(n)) =
            parse_originator_id(Bytes::from(ipv6.octets().to_vec()), &Some(Afi::Ipv6))
        {
            assert_eq!(n, ipv6);
        } else {
            panic!()
        }
    }

    #[test]
    fn test_encode_originator() {
        let ipv4 = Ipv4Addr::from_str("10.0.0.1").unwrap();
        assert_eq!(
            encode_originator_id(&IpAddr::V4(ipv4)),
            Bytes::from(ipv4.octets().to_vec())
        );
    }
}
