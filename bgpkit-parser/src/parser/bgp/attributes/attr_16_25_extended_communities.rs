//! BGP Extended Communities Attribute
//!
//! RFC4360: <https://datatracker.ietf.org/doc/html/rfc4360#section-4.5>
//! IANA Codes: <https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml>

use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use num_traits::FromPrimitive;

use bytes::{Buf, Bytes};
use std::net::Ipv4Addr;

pub fn parse_extended_community(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    let mut communities = Vec::new();

    while input.remaining() > 0 {
        let ec_type_u8 = input.read_u8()?;
        let ec_type: ExtendedCommunityType = match ExtendedCommunityType::from_u8(ec_type_u8) {
            Some(t) => t,
            None => {
                let mut buffer: [u8; 8] = [0; 8];
                let mut i = 0;
                buffer[i] = ec_type_u8;
                for _b in 0..7 {
                    i += 1;
                    buffer[i] = input.read_u8()?;
                }
                let ec = ExtendedCommunity::Raw(buffer);
                communities.push(ec);
                continue;
            }
        };
        let ec: ExtendedCommunity = match ec_type {
            ExtendedCommunityType::TransitiveTwoOctetAsSpecific => {
                let sub_type = input.read_u8()?;
                let global = input.read_u16()?;
                let mut local: [u8; 4] = [0; 4];
                for i in 0..4 {
                    local[i] = input.read_u8()?;
                }
                ExtendedCommunity::TransitiveTwoOctetAsSpecific(TwoOctetAsSpecific {
                    ec_type: ec_type_u8,
                    ec_subtype: sub_type,
                    global_administrator: Asn {
                        asn: global as u32,
                        len: AsnLength::Bits16,
                    },
                    local_administrator: local,
                })
            }
            ExtendedCommunityType::NonTransitiveTwoOctetAsSpecific => {
                let sub_type = input.read_u8()?;
                let global = input.read_u16()?;
                let mut local: [u8; 4] = [0; 4];
                for i in 0..4 {
                    local[i] = input.read_u8()?;
                }
                ExtendedCommunity::NonTransitiveTwoOctetAsSpecific(TwoOctetAsSpecific {
                    ec_type: ec_type_u8,
                    ec_subtype: sub_type,
                    global_administrator: Asn {
                        asn: global as u32,
                        len: AsnLength::Bits16,
                    },
                    local_administrator: local,
                })
            }

            ExtendedCommunityType::TransitiveIpv4AddressSpecific => {
                let sub_type = input.read_u8()?;
                let global = Ipv4Addr::from(input.read_u32()?);
                let mut local: [u8; 2] = [0; 2];
                local[0] = input.read_u8()?;
                local[1] = input.read_u8()?;
                ExtendedCommunity::TransitiveIpv4AddressSpecific(Ipv4AddressSpecific {
                    ec_type: ec_type_u8,
                    ec_subtype: sub_type,
                    global_administrator: global,
                    local_administrator: local,
                })
            }
            ExtendedCommunityType::NonTransitiveIpv4AddressSpecific => {
                let sub_type = input.read_u8()?;
                let global = Ipv4Addr::from(input.read_u32()?);
                let mut local: [u8; 2] = [0; 2];
                local[0] = input.read_u8()?;
                local[1] = input.read_u8()?;
                ExtendedCommunity::NonTransitiveIpv4AddressSpecific(Ipv4AddressSpecific {
                    ec_type: ec_type_u8,
                    ec_subtype: sub_type,
                    global_administrator: global,
                    local_administrator: local,
                })
            }
            ExtendedCommunityType::TransitiveFourOctetAsSpecific => {
                let sub_type = input.read_u8()?;
                let global = input.read_u32()?;
                let mut local: [u8; 2] = [0; 2];
                local[0] = input.read_u8()?;
                local[1] = input.read_u8()?;
                ExtendedCommunity::TransitiveFourOctetAsSpecific(FourOctetAsSpecific {
                    ec_type: ec_type_u8,
                    ec_subtype: sub_type,
                    global_administrator: Asn {
                        asn: global,
                        len: AsnLength::Bits32,
                    },
                    local_administrator: local,
                })
            }
            ExtendedCommunityType::NonTransitiveFourOctetAsSpecific => {
                let sub_type = input.read_u8()?;
                let global = input.read_u32()?;
                let mut local: [u8; 2] = [0; 2];
                local[0] = input.read_u8()?;
                local[1] = input.read_u8()?;
                ExtendedCommunity::NonTransitiveFourOctetAsSpecific(FourOctetAsSpecific {
                    ec_type: ec_type_u8,
                    ec_subtype: sub_type,
                    global_administrator: Asn {
                        asn: global,
                        len: AsnLength::Bits32,
                    },
                    local_administrator: local,
                })
            }
            ExtendedCommunityType::TransitiveOpaque => {
                let sub_type = input.read_u8()?;
                let mut value: [u8; 6] = [0; 6];
                for i in 0..6 {
                    value[i] = input.read_u8()?;
                }
                ExtendedCommunity::TransitiveOpaque(Opaque {
                    ec_type: ec_type_u8,
                    ec_subtype: sub_type,
                    value,
                })
            }
            ExtendedCommunityType::NonTransitiveOpaque => {
                let sub_type = input.read_u8()?;
                let mut value: [u8; 6] = [0; 6];
                for i in 0..6 {
                    value[i] = input.read_u8()?;
                }
                ExtendedCommunity::NonTransitiveOpaque(Opaque {
                    ec_type: ec_type_u8,
                    ec_subtype: sub_type,
                    value,
                })
            }
        };

        communities.push(ec);
    }
    Ok(AttributeValue::ExtendedCommunities(communities))
}

pub fn parse_ipv6_extended_community(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    let mut communities = Vec::new();
    while input.remaining() > 0 {
        let ec_type_u8 = input.read_u8()?;
        let sub_type = input.read_u8()?;
        let global = input.read_ipv6_address()?;
        let mut local: [u8; 2] = [0; 2];
        local[0] = input.read_u8()?;
        local[1] = input.read_u8()?;
        let ec = ExtendedCommunity::Ipv6AddressSpecific(Ipv6AddressSpecific {
            ec_type: ec_type_u8,
            ec_subtype: sub_type,
            global_administrator: global,
            local_administrator: local,
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
        let data: Vec<u8> = vec![
            0x00, // Transitive Two Octet AS Specific
            0x02, // Route Target
            0x00, 0x01, // AS 1
            0x00, 0x00, 0x00, 0x01, // Local Admin 1
        ];

        if let AttributeValue::ExtendedCommunities(communities) =
            parse_extended_community(Bytes::from(data)).unwrap()
        {
            assert_eq!(communities.len(), 1);
            if let ExtendedCommunity::TransitiveTwoOctetAsSpecific(community) = &communities[0] {
                assert_eq!(community.ec_type, 0x00);
                assert_eq!(community.ec_subtype, 0x02);
                assert_eq!(community.global_administrator.asn, 1);
                assert_eq!(community.local_administrator, [0x00, 0x00, 0x00, 0x01]);
            } else {
                panic!("Unexpected community type");
            }
        } else {
            panic!("Unexpected attribute type");
        }
    }

    #[test]
    fn test_parse_extended_communities_ipv4() {
        let data: Vec<u8> = vec![
            0x01, // Transitive IPv4 Address Specific
            0x02, // Route Target
            0xC0, 0x00, 0x02, 0x01, // ipv4: 192.0.2.1
            0x00, 0x01, // Local Admin 1
        ];

        if let AttributeValue::ExtendedCommunities(communities) =
            parse_extended_community(Bytes::from(data)).unwrap()
        {
            assert_eq!(communities.len(), 1);
            if let ExtendedCommunity::TransitiveIpv4AddressSpecific(community) = &communities[0] {
                assert_eq!(community.ec_type, 0x01);
                assert_eq!(community.ec_subtype, 0x02);
                assert_eq!(community.global_administrator, Ipv4Addr::new(192, 0, 2, 1));
                assert_eq!(community.local_administrator, [0x00, 0x01]);
            } else {
                panic!("Unexpected community type");
            }
        } else {
            panic!("Unexpected attribute type");
        }
    }

    #[test]
    fn test_parse_extended_communities_four_octet_as() {
        let data: Vec<u8> = vec![
            0x02, // Transitive Four Octet AS Specific
            0x02, // Route Target
            0x00, 0x00, 0x00, 0x01, // AS 1
            0x00, 0x01, // Local Admin 1
        ];

        if let AttributeValue::ExtendedCommunities(communities) =
            parse_extended_community(Bytes::from(data)).unwrap()
        {
            assert_eq!(communities.len(), 1);
            if let ExtendedCommunity::TransitiveFourOctetAsSpecific(community) = &communities[0] {
                assert_eq!(community.ec_type, 0x02);
                assert_eq!(community.ec_subtype, 0x02);
                assert_eq!(community.global_administrator.asn, 1);
                assert_eq!(community.local_administrator, [0x00, 0x01]);
            } else {
                panic!("Unexpected community type");
            }
        } else {
            panic!("Unexpected attribute type");
        }
    }

    #[test]
    fn test_parse_extended_communities_opaque() {
        let data: Vec<u8> = vec![
            0x03, // Transitive Opaque
            0x02, // Route Target
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // Opaque
        ];

        if let AttributeValue::ExtendedCommunities(communities) =
            parse_extended_community(Bytes::from(data)).unwrap()
        {
            assert_eq!(communities.len(), 1);
            if let ExtendedCommunity::TransitiveOpaque(community) = &communities[0] {
                assert_eq!(community.ec_type, 0x03);
                assert_eq!(community.ec_subtype, 0x02);
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
        let data: Vec<u8> = vec![
            0x40, // Transitive IPv6 Address Specific
            0x02, // Route Target
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // ipv6: 2001:db8::1
            0x00, 0x01, // Local Admin 1
        ];

        if let AttributeValue::ExtendedCommunities(communities) =
            parse_ipv6_extended_community(Bytes::from(data)).unwrap()
        {
            assert_eq!(communities.len(), 1);
            if let ExtendedCommunity::Ipv6AddressSpecific(community) = &communities[0] {
                assert_eq!(community.ec_type, 0x40);
                assert_eq!(community.ec_subtype, 0x02);
                assert_eq!(
                    community.global_administrator,
                    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)
                );
                assert_eq!(community.local_administrator, [0x00, 0x01]);
            } else {
                panic!("Unexpected community type");
            }
        } else {
            panic!("Unexpected attribute type");
        }
    }
}
