use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::Bytes;

pub fn parse_aggregator(
    mut input: Bytes,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_parse_aggregator() {
        let ipv4 = Ipv4Addr::from_str("10.0.0.1").unwrap();
        let mut data = vec![];
        data.extend([1u8, 2]);
        data.extend(ipv4.octets());
        let bytes = Bytes::from(data);

        if let Ok(AttributeValue::Aggregator(asn, n)) =
            parse_aggregator(bytes.clone(), &AsnLength::Bits16, &None)
        {
            assert_eq!(n, ipv4);
            assert_eq!(
                asn,
                Asn {
                    asn: 258,
                    len: AsnLength::Bits16
                }
            )
        } else {
            panic!()
        }

        if let Ok(AttributeValue::Aggregator(asn, n)) =
            parse_aggregator(bytes.clone(), &AsnLength::Bits16, &Some(Afi::Ipv4))
        {
            assert_eq!(n, ipv4);
            assert_eq!(
                asn,
                Asn {
                    asn: 258,
                    len: AsnLength::Bits16
                }
            )
        } else {
            panic!()
        }

        let ipv6 = Ipv6Addr::from_str("fc00::1").unwrap();
        let mut data = vec![];
        data.extend([0u8, 0, 1, 2]);
        data.extend(ipv6.octets());
        let bytes = Bytes::from(data);

        if let Ok(AttributeValue::Aggregator(asn, n)) =
            parse_aggregator(bytes, &AsnLength::Bits32, &Some(Afi::Ipv6))
        {
            assert_eq!(n, ipv6);
            assert_eq!(
                asn,
                Asn {
                    asn: 258,
                    len: AsnLength::Bits32
                }
            )
        } else {
            panic!()
        }
    }
}
