use crate::parser::ReadUtils;
use crate::ParserError;
use bgp_models::prelude::*;
use num_traits::FromPrimitive;
use std::io::Cursor;
use std::net::Ipv4Addr;

pub fn parse_extended_community(
    input: &mut Cursor<&[u8]>,
    total_bytes: usize,
) -> Result<AttributeValue, ParserError> {
    let mut communities = Vec::new();
    let pos_end = input.position() + total_bytes as u64;
    while input.position() < pos_end {
        let ec_type_u8 = input.read_8b()?;
        let ec_type: ExtendedCommunityType = match ExtendedCommunityType::from_u8(ec_type_u8) {
            Some(t) => t,
            None => {
                let mut buffer: [u8; 8] = [0; 8];
                let mut i = 0;
                buffer[i] = ec_type_u8;
                for _b in 0..7 {
                    i += 1;
                    buffer[i] = input.read_8b()?;
                }
                let ec = ExtendedCommunity::Raw(buffer);
                communities.push(ec);
                continue;
            }
        };
        let ec: ExtendedCommunity = match ec_type {
            ExtendedCommunityType::TransitiveTwoOctetAsSpecific => {
                let sub_type = input.read_8b()?;
                let global = input.read_16b()?;
                let mut local: [u8; 4] = [0; 4];
                for i in 0..4 {
                    local[i] = input.read_8b()?;
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
                let sub_type = input.read_8b()?;
                let global = input.read_16b()?;
                let mut local: [u8; 4] = [0; 4];
                for i in 0..4 {
                    local[i] = input.read_8b()?;
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
                let sub_type = input.read_8b()?;
                let global = Ipv4Addr::from(input.read_32b()?);
                let mut local: [u8; 2] = [0; 2];
                local[0] = input.read_8b()?;
                local[1] = input.read_8b()?;
                ExtendedCommunity::TransitiveIpv4AddressSpecific(Ipv4AddressSpecific {
                    ec_type: ec_type_u8,
                    ec_subtype: sub_type,
                    global_administrator: global,
                    local_administrator: local,
                })
            }
            ExtendedCommunityType::NonTransitiveIpv4AddressSpecific => {
                let sub_type = input.read_8b()?;
                let global = Ipv4Addr::from(input.read_32b()?);
                let mut local: [u8; 2] = [0; 2];
                local[0] = input.read_8b()?;
                local[1] = input.read_8b()?;
                ExtendedCommunity::NonTransitiveIpv4AddressSpecific(Ipv4AddressSpecific {
                    ec_type: ec_type_u8,
                    ec_subtype: sub_type,
                    global_administrator: global,
                    local_administrator: local,
                })
            }
            ExtendedCommunityType::TransitiveFourOctetAsSpecific => {
                let sub_type = input.read_8b()?;
                let global = input.read_32b()?;
                let mut local: [u8; 2] = [0; 2];
                local[0] = input.read_8b()?;
                local[1] = input.read_8b()?;
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
                let sub_type = input.read_8b()?;
                let global = input.read_32b()?;
                let mut local: [u8; 2] = [0; 2];
                local[0] = input.read_8b()?;
                local[1] = input.read_8b()?;
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
                let sub_type = input.read_8b()?;
                let mut value: [u8; 6] = [0; 6];
                for i in 0..6 {
                    value[i] = input.read_8b()?;
                }
                ExtendedCommunity::TransitiveOpaque(Opaque {
                    ec_type: ec_type_u8,
                    ec_subtype: sub_type,
                    value,
                })
            }
            ExtendedCommunityType::NonTransitiveOpaque => {
                let sub_type = input.read_8b()?;
                let mut value: [u8; 6] = [0; 6];
                for i in 0..6 {
                    value[i] = input.read_8b()?;
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

pub fn parse_ipv6_extended_community(
    input: &mut Cursor<&[u8]>,
    total_bytes: usize,
) -> Result<AttributeValue, ParserError> {
    let mut communities = Vec::new();
    let pos_end = input.position() + total_bytes as u64;
    while input.position() < pos_end {
        let ec_type_u8 = input.read_8b()?;
        let sub_type = input.read_8b()?;
        let global = input.read_ipv6_address()?;
        let mut local: [u8; 2] = [0; 2];
        local[0] = input.read_8b()?;
        local[1] = input.read_8b()?;
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
