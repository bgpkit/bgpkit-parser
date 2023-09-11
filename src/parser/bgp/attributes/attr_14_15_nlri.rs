use crate::models::*;
use crate::parser::bgp::attributes::attr_03_next_hop::parse_mp_next_hop;
use crate::parser::{parse_nlri_list, ReadUtils};
use crate::ParserError;
use log::warn;
use smallvec::smallvec;

/// <https://datatracker.ietf.org/doc/html/rfc4760#section-3>
/// The attribute is encoded as shown below:
/// +---------------------------------------------------------+
/// | Address Family Identifier (2 octets)                    |
/// +---------------------------------------------------------+
/// | Subsequent Address Family Identifier (1 octet)          |
/// +---------------------------------------------------------+
/// | Length of Next Hop Network Address (1 octet)            |
/// +---------------------------------------------------------+
/// | Network Address of Next Hop (variable)                  |
/// +---------------------------------------------------------+
/// | Reserved (1 octet)                                      |
/// +---------------------------------------------------------+
/// | Network Layer Reachability Information (variable)       |
/// +---------------------------------------------------------+
pub fn parse_reach_nlri(
    mut input: &[u8],
    afi: Option<Afi>,
    safi: Option<Safi>,
    prefixes: Option<&NetworkPrefix>,
    additional_paths: bool, // whether the NLRI is part of an additional paths message
) -> Result<AttributeValue, ParserError> {
    let first_byte_zero = input[0] == 0;

    // read address family
    let afi = match afi {
        Some(afi) if !first_byte_zero => afi,
        _ => Afi::try_from(input.read_u16()?)?,
    };
    let safi = match safi {
        Some(safi) if !first_byte_zero => safi,
        _ => Safi::try_from(input.read_u8()?)?,
    };

    let next_hop_length = input.read_u8()? as usize;
    input.require_n_remaining(next_hop_length, "mp next hop")?;
    let next_hop_bytes = input.split_to(next_hop_length)?;
    let next_hop = parse_mp_next_hop(next_hop_bytes)?;

    let prefixes = match prefixes {
        // skip parsing prefixes: https://datatracker.ietf.org/doc/html/rfc6396#section-4.3.4
        Some(prefix) if !first_byte_zero => smallvec![*prefix],
        _ => {
            // skip reserved byte for reachable NRLI
            if input.read_u8()? != 0 {
                warn!("NRLI reserved byte not 0");
            }

            parse_nlri_list(input, additional_paths, afi)?
        }
    };

    Ok(AttributeValue::MpReachNlri(ReachableNlri::new(
        afi, safi, next_hop, prefixes,
    )))
}

pub fn parse_unreach_nlri(
    mut input: &[u8],
    afi: Option<Afi>,
    safi: Option<Safi>,
    prefixes: Option<&NetworkPrefix>,
    additional_paths: bool, // whether the NLRI is part of an additional paths message
) -> Result<AttributeValue, ParserError> {
    let first_byte_zero = input[0] == 0;

    // read address family
    let afi = match afi {
        Some(afi) if !first_byte_zero => afi,
        _ => input.read_afi()?,
    };
    let safi = match safi {
        Some(safi) if !first_byte_zero => safi,
        _ => input.read_safi()?,
    };

    let prefixes = match prefixes {
        // skip parsing prefixes: https://datatracker.ietf.org/doc/html/rfc6396#section-4.3.4
        Some(prefix) if !first_byte_zero => smallvec![*prefix],
        _ => parse_nlri_list(input, additional_paths, afi)?,
    };

    Ok(AttributeValue::MpUnreachNlri(UnreachableNlri::new(
        afi, safi, prefixes,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_parsing_nlri_simple() {
        let test_bytes = &[
            0x00, 0x01, // address family: IPv4
            0x01, // safi: unicast
            0x04, // next hop length: 4
            0xC0, 0x00, 0x02, 0x01, // next hop: 192.0.2.1
            0x00, // reserved
            // NLRI
            0x18, // 24 bits prefix length
            0xC0, 0x00, 0x02, // 192.0.2
        ];
        let res = parse_reach_nlri(test_bytes, None, None, None, false);

        if let Ok(AttributeValue::MpReachNlri(nlri)) = res {
            assert_eq!(nlri.address_family(), Afi::Ipv4);
            assert_eq!(nlri.safi(), Safi::Unicast);
            assert_eq!(
                nlri.next_hop(),
                NextHopAddress::Ipv4(Ipv4Addr::from_str("192.0.2.1").unwrap())
            );
            assert_eq!(
                nlri.prefixes,
                PrefixList::from([NetworkPrefix::from_str("192.0.2.0/24").unwrap()])
            );
        } else {
            panic!("Unexpected result: {:?}", res);
        }
    }

    #[test]
    fn test_parsing_nlri_add_path() {
        let test_bytes = &[
            0x00, 0x01, // address family: IPv4
            0x01, // safi: unicast
            0x04, // next hop length: 4
            0xC0, 0x00, 0x02, 0x01, // next hop: 192.0.2.1
            0x00, // reserved
            // NLRI
            0x00, 0x00, 0x00, 0x7B, // path_id: 123
            0x18, // 24 bits prefix length
            0xC0, 0x00, 0x02, // 192.0.2
        ];
        let res = parse_reach_nlri(test_bytes, None, None, None, true);

        if let Ok(AttributeValue::MpReachNlri(nlri)) = res {
            assert_eq!(nlri.address_family(), Afi::Ipv4);
            assert_eq!(nlri.safi(), Safi::Unicast);
            assert_eq!(
                nlri.next_hop(),
                NextHopAddress::Ipv4(Ipv4Addr::from_str("192.0.2.1").unwrap())
            );
            let prefix = NetworkPrefix::new(IpNet::from_str("192.0.2.0/24").unwrap(), 123);
            assert_eq!(nlri.prefixes[0], prefix);
            assert_eq!(nlri.prefixes[0].path_id, prefix.path_id);
        } else {
            panic!("Unexpected result: {:?}", res);
        }
    }
}
