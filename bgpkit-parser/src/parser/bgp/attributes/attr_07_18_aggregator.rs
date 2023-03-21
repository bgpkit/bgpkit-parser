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

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_models::prelude::Asn;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_parse_aggregator() {
        let ipv4 = Ipv4Addr::from_str("10.0.0.1").unwrap();
        let mut bytes = vec![];
        bytes.extend([1u8, 2]);
        bytes.extend(ipv4.octets());

        if let Ok(AttributeValue::Aggregator(asn, n)) =
            parse_aggregator(&mut Cursor::new(&bytes), &AsnLength::Bits16, &None)
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

        if let Ok(AttributeValue::Aggregator(asn, n)) = parse_aggregator(
            &mut Cursor::new(&bytes),
            &AsnLength::Bits16,
            &Some(Afi::Ipv4),
        ) {
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
        let mut bytes = vec![];
        bytes.extend([0u8, 0, 1, 2]);
        bytes.extend(ipv6.octets());

        if let Ok(AttributeValue::Aggregator(asn, n)) = parse_aggregator(
            &mut Cursor::new(&bytes),
            &AsnLength::Bits32,
            &Some(Afi::Ipv6),
        ) {
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
