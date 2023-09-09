//! BGP Extended Communities Attribute
//!
//! RFC4360: <https://datatracker.ietf.org/doc/html/rfc4360#section-4.5>
//! IANA Codes: <https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml>

use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;

use std::net::Ipv4Addr;

pub fn parse_extended_community(mut input: &[u8]) -> Result<AttributeValue, ParserError> {
    let mut communities = Vec::new();

    while input.remaining() > 0 {
        let ec_type_u8 = input.read_u8()?;
        let ec: ExtendedCommunity = match ExtendedCommunityType::from(ec_type_u8) {
            ExtendedCommunityType::TransitiveTwoOctetAs => {
                let sub_type = input.read_u8()?;
                let global = input.read_u16()?;
                let mut local: [u8; 4] = [0; 4];
                input.read_exact(&mut local[..])?;
                ExtendedCommunity::TransitiveTwoOctetAs(TwoOctetAsExtCommunity {
                    subtype: sub_type,
                    global_admin: Asn::new_16bit(global),
                    local_admin: local,
                })
            }
            ExtendedCommunityType::NonTransitiveTwoOctetAs => {
                let sub_type = input.read_u8()?;
                let global = input.read_u16()?;
                let mut local: [u8; 4] = [0; 4];
                input.read_exact(&mut local)?;
                ExtendedCommunity::NonTransitiveTwoOctetAs(TwoOctetAsExtCommunity {
                    subtype: sub_type,
                    global_admin: Asn::new_16bit(global),
                    local_admin: local,
                })
            }

            ExtendedCommunityType::TransitiveIpv4Addr => {
                let sub_type = input.read_u8()?;
                let global = Ipv4Addr::from(input.read_u32()?);
                let mut local: [u8; 2] = [0; 2];
                input.read_exact(&mut local)?;
                ExtendedCommunity::TransitiveIpv4Addr(Ipv4AddrExtCommunity {
                    subtype: sub_type,
                    global_admin: global,
                    local_admin: local,
                })
            }
            ExtendedCommunityType::NonTransitiveIpv4Addr => {
                let sub_type = input.read_u8()?;
                let global = Ipv4Addr::from(input.read_u32()?);
                let mut local: [u8; 2] = [0; 2];
                input.read_exact(&mut local)?;
                ExtendedCommunity::NonTransitiveIpv4Addr(Ipv4AddrExtCommunity {
                    subtype: sub_type,
                    global_admin: global,
                    local_admin: local,
                })
            }
            ExtendedCommunityType::TransitiveFourOctetAs => {
                let sub_type = input.read_u8()?;
                let global = input.read_u32()?;
                let mut local: [u8; 2] = [0; 2];
                input.read_exact(&mut local)?;
                ExtendedCommunity::TransitiveFourOctetAs(FourOctetAsExtCommunity {
                    subtype: sub_type,
                    global_admin: Asn::new_32bit(global),
                    local_admin: local,
                })
            }
            ExtendedCommunityType::NonTransitiveFourOctetAs => {
                let sub_type = input.read_u8()?;
                let global = input.read_u32()?;
                let mut local: [u8; 2] = [0; 2];
                input.read_exact(&mut local)?;
                ExtendedCommunity::NonTransitiveFourOctetAs(FourOctetAsExtCommunity {
                    subtype: sub_type,
                    global_admin: Asn::new_32bit(global),
                    local_admin: local,
                })
            }
            ExtendedCommunityType::TransitiveOpaque => {
                let sub_type = input.read_u8()?;
                let mut value: [u8; 6] = [0; 6];
                input.read_exact(&mut value)?;
                ExtendedCommunity::TransitiveOpaque(OpaqueExtCommunity {
                    subtype: sub_type,
                    value,
                })
            }
            ExtendedCommunityType::NonTransitiveOpaque => {
                let sub_type = input.read_u8()?;
                let mut value: [u8; 6] = [0; 6];
                input.read_exact(&mut value)?;
                ExtendedCommunity::NonTransitiveOpaque(OpaqueExtCommunity {
                    subtype: sub_type,
                    value,
                })
            }
            ExtendedCommunityType::Unknown(_) => {
                let mut buffer: [u8; 8] = [0; 8];
                buffer[0] = ec_type_u8;
                input.read_exact(&mut buffer[1..])?;

                ExtendedCommunity::Raw(buffer)
            }
        };

        communities.push(ec);
    }
    Ok(AttributeValue::ExtendedCommunities(communities))
}

pub fn parse_ipv6_extended_community(mut input: &[u8]) -> Result<AttributeValue, ParserError> {
    let mut communities = Vec::new();
    while input.remaining() > 0 {
        let ec_type_u8 = input.read_u8()?;
        let sub_type = input.read_u8()?;
        let global = input.read_ipv6_address()?;
        let mut local: [u8; 2] = [0; 2];
        local[0] = input.read_u8()?;
        local[1] = input.read_u8()?;
        let ec = ExtendedCommunity::Ipv6Addr(Ipv6AddrExtCommunity {
            community_type: ExtendedCommunityType::from(ec_type_u8),
            subtype: sub_type,
            global_admin: global,
            local_admin: local,
        });
        communities.push(ec);
    }
    Ok(AttributeValue::ExtendedCommunities(communities))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    // TransitiveTwoOctetAsSpecific = 0x00,
    // TransitiveIpv4AddressSpecific = 0x01,
    // TransitiveFourOctetAsSpecific = 0x02,
    // TransitiveOpaque = 0x03,

    #[test]
    fn test_parse_extended_communities_two_octet_as() {
        let data = [
            0x00, // Transitive Two Octet AS Specific
            0x02, // Route Target
            0x00, 0x01, // AS 1
            0x00, 0x00, 0x00, 0x01, // Local Admin 1
        ];

        if let AttributeValue::ExtendedCommunities(communities) =
            parse_extended_community(&data).unwrap()
        {
            assert_eq!(communities.len(), 1);
            if let ExtendedCommunity::TransitiveTwoOctetAs(community) = &communities[0] {
                assert_eq!(community.subtype, 0x02);
                assert_eq!(community.global_admin, Asn::new_16bit(1));
                assert_eq!(community.local_admin, [0x00, 0x00, 0x00, 0x01]);
            } else {
                panic!("Unexpected community type");
            }
        } else {
            panic!("Unexpected attribute type");
        }
    }

    #[test]
    fn test_parse_extended_communities_ipv4() {
        let data = [
            0x01, // Transitive IPv4 Address Specific
            0x02, // Route Target
            0xC0, 0x00, 0x02, 0x01, // ipv4: 192.0.2.1
            0x00, 0x01, // Local Admin 1
        ];

        if let AttributeValue::ExtendedCommunities(communities) =
            parse_extended_community(&data).unwrap()
        {
            assert_eq!(communities.len(), 1);
            if let ExtendedCommunity::TransitiveIpv4Addr(community) = &communities[0] {
                assert_eq!(community.subtype, 0x02);
                assert_eq!(community.global_admin, Ipv4Addr::new(192, 0, 2, 1));
                assert_eq!(community.local_admin, [0x00, 0x01]);
            } else {
                panic!("Unexpected community type");
            }
        } else {
            panic!("Unexpected attribute type");
        }
    }

    #[test]
    fn test_parse_extended_communities_four_octet_as() {
        let data = [
            0x02, // Transitive Four Octet AS Specific
            0x02, // Route Target
            0x00, 0x00, 0x00, 0x01, // AS 1
            0x00, 0x01, // Local Admin 1
        ];

        if let AttributeValue::ExtendedCommunities(communities) =
            parse_extended_community(&data).unwrap()
        {
            assert_eq!(communities.len(), 1);
            if let ExtendedCommunity::TransitiveFourOctetAs(community) = &communities[0] {
                assert_eq!(community.subtype, 0x02);
                assert_eq!(community.global_admin, Asn::new_16bit(1));
                assert_eq!(community.local_admin, [0x00, 0x01]);
            } else {
                panic!("Unexpected community type");
            }
        } else {
            panic!("Unexpected attribute type");
        }
    }

    #[test]
    fn test_parse_extended_communities_opaque() {
        let data = [
            0x03, // Transitive Opaque
            0x02, // Route Target
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // Opaque
        ];

        if let AttributeValue::ExtendedCommunities(communities) =
            parse_extended_community(&data).unwrap()
        {
            assert_eq!(communities.len(), 1);
            if let ExtendedCommunity::TransitiveOpaque(community) = &communities[0] {
                assert_eq!(community.subtype, 0x02);
                assert_eq!(community.value, [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
            } else {
                panic!("Unexpected community type");
            }
        } else {
            panic!("Unexpected attribute type");
        }
    }

    #[test]
    fn test_parse_extended_communities_ipv6() {
        let data = [
            0x40, // Transitive IPv6 Address Specific
            0x02, // Route Target
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // ipv6: 2001:db8::1
            0x00, 0x01, // Local Admin 1
        ];

        if let AttributeValue::ExtendedCommunities(communities) =
            parse_ipv6_extended_community(&data).unwrap()
        {
            assert_eq!(communities.len(), 1);
            if let ExtendedCommunity::Ipv6Addr(community) = &communities[0] {
                assert_eq!(
                    community.community_type,
                    ExtendedCommunityType::NonTransitiveTwoOctetAs
                );
                assert_eq!(community.subtype, 0x02);
                assert_eq!(
                    community.global_admin,
                    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)
                );
                assert_eq!(community.local_admin, [0x00, 0x01]);
            } else {
                panic!("Unexpected community type");
            }
        } else {
            panic!("Unexpected attribute type");
        }
    }
}
