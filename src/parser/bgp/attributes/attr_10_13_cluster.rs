use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, Bytes};
use std::net::IpAddr;

pub fn parse_clusters(mut input: Bytes, afi: &Option<Afi>) -> Result<AttributeValue, ParserError> {
    // FIXME: in https://tools.ietf.org/html/rfc4456, the CLUSTER_LIST is a set of CLUSTER_ID each represented by a 4-byte number
    let mut clusters = Vec::new();
    while input.remaining() > 0 {
        let afi = match afi {
            None => &Afi::Ipv4,
            Some(a) => a,
        };
        let addr = input.read_address(afi)?;
        clusters.push(addr);
    }
    Ok(AttributeValue::Clusters(clusters))
}

pub fn encode_clusters(clusters: &Vec<IpAddr>) -> Bytes {
    let mut buf = Vec::new();
    for cluster in clusters {
        buf.extend(match cluster {
            IpAddr::V4(n) => Bytes::from(n.octets().to_vec()),
            IpAddr::V6(n) => Bytes::from(n.octets().to_vec()),
        });
    }
    Bytes::from(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_parse_clusters() {
        if let Ok(AttributeValue::Clusters(n)) = parse_clusters(
            Bytes::from(vec![
                0xC0, 0x00, 0x02, 0x01, // 192.0.2.1
                0xC0, 0x00, 0x02, 0x02, // 192.0.2.2
            ]),
            &None,
        ) {
            assert_eq!(n.len(), 2);
            assert_eq!(n[0], Ipv4Addr::from_str("192.0.2.1").unwrap());
            assert_eq!(n[1], Ipv4Addr::from_str("192.0.2.2").unwrap());
        } else {
            panic!()
        }
    }

    #[test]
    fn test_encode_clusters() {
        let clusters = vec![
            IpAddr::V4(Ipv4Addr::from_str("192.0.2.1").unwrap()),
            IpAddr::V4(Ipv4Addr::from_str("192.0.2.2").unwrap()),
        ];
        assert_eq!(
            encode_clusters(&clusters),
            Bytes::from(vec![
                0xC0, 0x00, 0x02, 0x01, //
                0xC0, 0x00, 0x02, 0x02, //
            ])
        );
    }
}
