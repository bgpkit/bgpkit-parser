use std::io::{Read, Take};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::convert::TryFrom;
use bgp_models::bgp::attributes::*;
use bgp_models::bgp::community::*;
use bgp_models::network::*;
use log::warn;

use byteorder::{BigEndian, ReadBytesExt};

use num_traits::FromPrimitive;

use crate::parser::ReadUtils;
use crate::error::ParserError;



pub struct AttributeParser {
    additional_paths: bool,
}

impl AttributeParser {
    const AS_PATH_AS_SET: u8 = 1;
    const AS_PATH_AS_SEQUENCE: u8 = 2;
    // https://datatracker.ietf.org/doc/html/rfc5065
    const AS_PATH_CONFED_SEQUENCE: u8 = 3;
    const AS_PATH_CONFED_SET: u8 = 4;

    pub fn new(has_add_path: bool) -> AttributeParser {
        AttributeParser {
            additional_paths: has_add_path,
        }
    }

    pub fn parse_attributes<T: std::io::Read>(
        &self,
        input: &mut Take<T>,
        asn_len: &AsnLength,
        afi: Option<Afi>,
        safi: Option<Safi>,
        prefixes: Option<Vec<NetworkPrefix>>,
    ) -> Result<Vec<Attribute>, ParserError> {
        let mut attributes: Vec<Attribute> = vec![];

        while input.limit() >= 3 {
            // has content to read
            let flag = input.read_u8()?;
            let attr_type = input.read_u8()?;
            let length = match flag & AttributeFlagsBit::ExtendedLengthBit as u8 {
                0 => input.read_8b()? as u64,
                _ => input.read_16b()? as u64,
            };

            if flag & AttributeFlagsBit::PartialBit as u8 != 0 {
                /*
                https://datatracker.ietf.org/doc/html/rfc4271#section-4.3

                > The third high-order bit (bit 2) of the Attribute Flags octet
                > is the Partial bit.  It defines whether the information
                > contained in the optional transitive attribute is partial (if
                > set to 1) or complete (if set to 0).  For well-known attributes
                > and for optional non-transitive attributes, the Partial bit
                > MUST be set to 0.

                */
                let mut buf=Vec::with_capacity(length as usize);
                input.read_to_end(&mut buf)?;
                continue;
            }

            let attr_type = match AttrType::from_u8(attr_type) {
                Some(t) => t,
                None => {
                    drop_n!(input, length);
                    return Err(crate::error::ParserError::UnknownAttr(format!("Failed to parse attribute type: {}", attr_type)))
                }
            };

            // if input.limit()==0{break}
            if input.limit()<length {
                warn!("not enough bytes: input bytes left - {}, want to read - {}; skipping", input.limit(), length);
                break
            }
            let mut attr_input = input.take(length);

            let attr = match attr_type {
                AttrType::ORIGIN => self.parse_origin(&mut attr_input),
                AttrType::AS_PATH => self.parse_as_path(&mut attr_input, asn_len),
                AttrType::NEXT_HOP => self.parse_next_hop(&mut attr_input, &afi),
                AttrType::MULTI_EXIT_DISCRIMINATOR => self.parse_med(&mut attr_input),
                AttrType::LOCAL_PREFERENCE => self.parse_local_pref(&mut attr_input),
                AttrType::ATOMIC_AGGREGATE => Ok(Attribute::AtomicAggregate(AtomicAggregate::AG)),
                AttrType::AGGREGATOR => self.parse_aggregator(&mut attr_input, asn_len, &afi),
                AttrType::ORIGINATOR_ID => self.parse_originator_id(&mut attr_input, &afi),
                AttrType::CLUSTER_LIST => self.parse_clusters(&mut attr_input, &afi),
                AttrType::MP_REACHABLE_NLRI => {
                        self.parse_nlri(&mut attr_input, &afi, &safi, &prefixes, true)
                }
                AttrType::MP_UNREACHABLE_NLRI => self.parse_nlri(&mut attr_input, &afi, &safi, &prefixes, false),
                AttrType::AS4_PATH => self.parse_as_path(&mut attr_input, &AsnLength::Bits32),
                AttrType::AS4_AGGREGATOR => self.parse_aggregator(&mut attr_input, &AsnLength::Bits32, &afi),

                // communities
                AttrType::COMMUNITIES => self.parse_regular_communities(&mut attr_input),
                AttrType::LARGE_COMMUNITIES => self.parse_large_communities(&mut attr_input),
                AttrType::EXTENDED_COMMUNITIES => self.parse_extended_community(&mut attr_input) ,
                AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES => self.parse_ipv6_extended_community(&mut attr_input),
                AttrType::DEVELOPMENT => {
                    let mut buf=Vec::with_capacity(length as usize);
                    attr_input.read_to_end(&mut buf)?;
                    Ok(Attribute::Development(buf))
                },
                _ => {
                    let mut buf=Vec::with_capacity(length as usize);
                    attr_input.read_to_end(&mut buf)?;
                    Err(crate::error::ParserError::Unsupported(format!("Unsupported attribute type: {:?}", attr_type)))
                    // dbg!(attr_type, length, flag);
                    // dbg!(length, buf);
                    // break
                }
            };
            let _attr = match attr{
                Ok(v) => {
                    attributes.push(v);
                }
                Err(_e) => {continue}
            };
        }
        while input.limit()>0 {
            input.read_8b()?;
        }
        Ok(attributes)
    }

    fn parse_origin<T: Read>(&self, input: &mut Take<T>) -> Result<Attribute, ParserError> {
        let origin = input.read_u8()?;
        match Origin::from_u8(origin) {
            Some(v) => Ok(Attribute::Origin(v)),
            None => {
                return Err(crate::error::ParserError::UnknownAttr(format!("Failed to parse attribute type: origin")))
            }
        }
    }

    fn parse_as_path<T: Read>(&self, input: &mut Take<T>, asn_len: &AsnLength) -> Result<Attribute, ParserError> {
        let mut output = AsPath::new();
        while input.limit() > 0 {
            let segment = self.parse_as_segment(input, asn_len)?;
            output.add_segment(segment);
        }
        Ok(Attribute::AsPath(output))
    }

    fn parse_as_segment<T: Read>(&self, input: &mut Take<T>, asn_len: &AsnLength) -> Result<AsPathSegment, ParserError> {
        let segment_type = input.read_u8()?;
        let count = input.read_u8()?;
        // Vec<u8> does not have reads
        let path = input.read_asns(asn_len, count as usize)?;
        match segment_type {
            AttributeParser::AS_PATH_AS_SET => Ok(AsPathSegment::AsSet(path)),
            AttributeParser::AS_PATH_AS_SEQUENCE => Ok(AsPathSegment::AsSequence(path)),
            AttributeParser::AS_PATH_CONFED_SEQUENCE => Ok(AsPathSegment::ConfedSequence(path)),
            AttributeParser::AS_PATH_CONFED_SET => Ok(AsPathSegment::ConfedSet(path)),
            _ => Err(ParserError::ParseError(
                format!("Invalid AS path segment type: {}", segment_type),
            )),
        }
    }

    fn parse_next_hop<T: Read>(&self, input: &mut Take<T>, afi: &Option<Afi>) -> Result<Attribute, ParserError> {
        if let Some(afi) = afi {
            if *afi==Afi::Ipv6{
                print!("break here");
            }
            Ok(input.read_address(afi).map(Attribute::NextHop)?)
        } else {
            Ok(input.read_address(&Afi::Ipv4).map(Attribute::NextHop)?)
        }
    }

    fn parse_med<T: Read>(&self, input: &mut Take<T>) -> Result<Attribute, ParserError> {
        Ok(input
            .read_u32::<BigEndian>()
            .map(Attribute::MultiExitDiscriminator)?)
    }

    fn parse_local_pref<T: Read>(&self, input: &mut Take<T>) -> Result<Attribute, ParserError> {
        Ok(input
            .read_u32::<BigEndian>()
            .map(Attribute::LocalPreference)?)
    }

    fn parse_aggregator<T: Read>(&self, input: &mut Take<T>, asn_len: &AsnLength, afi: &Option<Afi>) -> Result<Attribute, ParserError> {
        let asn = input.read_asn(asn_len)?;
        let afi = match afi {
            None => { &Afi::Ipv4 }
            Some(a) => {a}
        };
        let addr = input.read_address(afi)?;
        Ok(Attribute::Aggregator(asn, addr))
    }

    fn parse_regular_communities<T: Read>(&self, input: &mut Take<T>) -> Result<Attribute, ParserError> {
        const COMMUNITY_NO_EXPORT: u32 = 0xFFFFFF01;
        const COMMUNITY_NO_ADVERTISE: u32 = 0xFFFFFF02;
        const COMMUNITY_NO_EXPORT_SUBCONFED: u32 = 0xFFFFFF03;
        let mut communities = Vec::with_capacity((input.limit() / 4) as usize);
        while input.limit() > 0 {
            let community_val = input.read_u32::<BigEndian>()?;
            communities.push(
                match community_val {
                    COMMUNITY_NO_EXPORT => Community::NoExport,
                    COMMUNITY_NO_ADVERTISE => Community::NoAdvertise,
                    COMMUNITY_NO_EXPORT_SUBCONFED => Community::NoExportSubConfed,
                    value => {
                        let asn = (value >> 16) & 0xffff;
                        let value = (value & 0xffff) as u16;
                        Community::Custom(asn, value)
                    }
                }
            )
        }
        Ok(Attribute::Communities(communities))
    }

    fn parse_originator_id<T: Read>(&self, input: &mut Take<T>, afi: &Option<Afi>) -> Result<Attribute, ParserError> {
        let afi = match afi {
            None => { &Afi::Ipv4 }
            Some(a) => {a}
        };
        let addr = input.read_address(afi)?;
        Ok(Attribute::OriginatorId(addr))
    }

    #[allow(unused)]
    fn parse_cluster_id<T: Read>(&self, input: &mut Take<T>, afi: &Option<Afi>) -> Result<Attribute, ParserError> {
        let afi = match afi {
            None => { &Afi::Ipv4 }
            Some(a) => {a}
        };
        let addr = input.read_address(afi)?;
        Ok(Attribute::Clusters(vec![addr]))
    }

    fn parse_clusters<T: Read>(&self, input: &mut Take<T>, afi: &Option<Afi>) -> Result<Attribute, ParserError> {
        // FIXME: in https://tools.ietf.org/html/rfc4456, the CLUSTER_LIST is a set of CLUSTER_ID each represented by a 4-byte number
        let mut clusters = Vec::new();
        while input.limit() > 0 {
            let afi = match afi {
                None => { &Afi::Ipv4 }
                Some(a) => {a}
            };
            let addr = input.read_address(afi)?;
            clusters.push(addr);
        }
        Ok(Attribute::Clusters(clusters))
    }

    ///
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
    fn parse_nlri<T: Read>(&self, input: &mut Take<T>,
                                   afi: &Option<Afi>, safi: &Option<Safi>,
                                   prefixes: &Option<Vec<NetworkPrefix>>,
                                   reachable: bool,
    ) -> Result<Attribute, ParserError> {
        let mut buf=Vec::with_capacity(input.limit() as usize);
        input.read_to_end(&mut buf)?;
        let first_byte_zero = buf[0]==0;
        let mut buf_input = buf.as_slice().take(buf.len() as u64);

        // read address family
        let afi = match afi {
            Some(afi) => {
                if first_byte_zero {
                    buf_input.read_afi()?
                } else {
                    afi.to_owned()
                }
            },
            None => buf_input.read_afi()?
        };
        let safi = match safi {
            Some(safi) => {
                if first_byte_zero {
                    buf_input.read_safi()?
                } else {
                    safi.to_owned()
                }
            }
            None => buf_input.read_safi()?,
        };

        let mut next_hop = None;
        if reachable {
            let next_hop_length = buf_input.read_u8()?;
            next_hop = match self.parse_mp_next_hop(next_hop_length, &mut buf_input) {
                Ok(x) => x,
                Err(e) => {
                    dbg!(&e);
                    dbg!(&afi);
                    return Err(e)
                }
            };
        }

        let prefixes = match prefixes {
            Some(pfxs) => {
                // skip parsing prefixes: https://datatracker.ietf.org/doc/html/rfc6396#section-4.3.4
                if first_byte_zero {
                    if reachable {
                        // skip reserved byte for reachable NRLI
                        let _should_be_zero = buf_input.read_u8()?;
                    }
                    self.parse_mp_prefix_list(&mut buf_input, &afi)?
                } else {
                    pfxs.to_owned()
                }
            },
            None => {
                if reachable {
                    // skip reserved byte for reachable NRLI
                    buf_input.read_u8()?;
                }
                self.parse_mp_prefix_list(&mut buf_input, &afi)?
            }
        };

        // Reserved field, should ignore
        match reachable {
            true => Ok(Attribute::MpReachNlri(Nlri {afi,safi, next_hop, prefixes})),
            false => Ok(Attribute::MpUnreachNlri(Nlri {afi,safi, next_hop, prefixes}))
        }
    }

    fn parse_mp_next_hop<T: Read>(
        &self,
        next_hop_length: u8,
        input: &mut Take<T>,
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
                return Err(ParserError::ParseError(
                    format!("Invalid next hop length found: {}",v),
                ));
            }
        };
        Ok(output)
    }

    fn parse_mp_prefix_list<T: Read>(
        &self,
        input: &mut Take<T>,
        afi: &Afi,
    ) -> Result<Vec<NetworkPrefix>, ParserError> {
        let mut output = Vec::new();
        while input.limit() > 0 {
            let path_id = if self.additional_paths {
                input.read_u32::<BigEndian>()
            } else {
                Ok(0)
            }?;
            let prefix = input.read_nlri_prefix(afi, path_id)?;
            output.push(prefix);
        }
        Ok(output)
    }

    fn parse_large_communities<T: Read>(
        &self,
        input: &mut Take<T>,
    ) -> Result<Attribute, ParserError> {
        let mut communities = Vec::new();
        while input.limit() > 0 {
            let global_administrator = input.read_u32::<BigEndian>()?;
            let local_data = [
                input.read_u32::<BigEndian>()?,
                input.read_u32::<BigEndian>()?,
            ];
            communities.push(LargeCommunity::new(global_administrator, local_data));
        }
        Ok(Attribute::LargeCommunities(communities))
    }

    fn parse_extended_community<T: Read>(
        &self,
        input: &mut Take<T>,
    ) -> Result<Attribute, ParserError> {
        let mut communities = Vec::new();
        while input.limit() > 0 {
            let ec_type_u8 = input.read_8b()?;
            let ec_type: ExtendedCommunityType = match ExtendedCommunityType::from_u8(ec_type_u8){
                Some(t) => t,
                None => return Err(crate::error::ParserError::ParseError(format!("Failed to parse extended community type: {}", ec_type_u8)))
            };
            let ec: ExtendedCommunity = match ec_type {
                ExtendedCommunityType::TransitiveTwoOctetAsSpecific => {
                    let sub_type = input.read_8b()?;
                    let global = input.read_16b()?;
                    let local = input.read_n_bytes(4)?;
                    ExtendedCommunity::TransitiveTwoOctetAsSpecific( TwoOctetAsSpecific{
                        ec_type: ec_type_u8,
                        ec_subtype: sub_type,
                        global_administrator: global as u32,
                        local_administrator: <[u8; 4]>::try_from(local).unwrap()
                    } )
                }
                ExtendedCommunityType::NonTransitiveTwoOctetAsSpecific => {
                    let sub_type = input.read_8b()?;
                    let global = input.read_16b()?;
                    let local = input.read_n_bytes(4)?;
                    ExtendedCommunity::NonTransitiveTwoOctetAsSpecific( TwoOctetAsSpecific{
                        ec_type: ec_type_u8,
                        ec_subtype: sub_type,
                        global_administrator: global as u32,
                        local_administrator: <[u8; 4]>::try_from(local).unwrap()
                    } )
                }

                ExtendedCommunityType::TransitiveIpv4AddressSpecific => {
                    let sub_type = input.read_8b()?;
                    let global = Ipv4Addr::from(input.read_32b()?);
                    let local = input.read_n_bytes(2)?;
                    ExtendedCommunity::TransitiveIpv4AddressSpecific( Ipv4AddressSpecific{
                        ec_type: ec_type_u8,
                        ec_subtype: sub_type,
                        global_administrator: global,
                        local_administrator: <[u8; 2]>::try_from(local).unwrap()
                    } )
                }
                ExtendedCommunityType::NonTransitiveIpv4AddressSpecific => {
                    let sub_type = input.read_8b()?;
                    let global = Ipv4Addr::from(input.read_32b()?);
                    let local = input.read_n_bytes(2)?;
                    ExtendedCommunity::NonTransitiveIpv4AddressSpecific( Ipv4AddressSpecific{
                        ec_type: ec_type_u8,
                        ec_subtype: sub_type,
                        global_administrator: global,
                        local_administrator: <[u8; 2]>::try_from(local).unwrap()
                    } )
                }
                ExtendedCommunityType::TransitiveFourOctetAsSpecific => {
                    let sub_type = input.read_8b()?;
                    let global = input.read_32b()?;
                    let local = input.read_n_bytes(2)?;
                    ExtendedCommunity::TransitiveFourOctetAsSpecific( FourOctetAsSpecific{
                        ec_type: ec_type_u8,
                        ec_subtype: sub_type,
                        global_administrator: global,
                        local_administrator: <[u8; 2]>::try_from(local).unwrap()
                    } )
                }
                ExtendedCommunityType::NonTransitiveFourOctetAsSpecific => {
                    let sub_type = input.read_8b()?;
                    let global = input.read_32b()?;
                    let local = input.read_n_bytes(2)?;
                    ExtendedCommunity::NonTransitiveFourOctetAsSpecific( FourOctetAsSpecific{
                        ec_type: ec_type_u8,
                        ec_subtype: sub_type,
                        global_administrator: global,
                        local_administrator: <[u8; 2]>::try_from(local).unwrap()
                    } )
                }
                ExtendedCommunityType::TransitiveOpaque => {
                    let sub_type = input.read_8b()?;
                    let value = input.read_n_bytes(6)?;
                    ExtendedCommunity::TransitiveOpaque( Opaque{
                        ec_type: ec_type_u8,
                        ec_subtype: sub_type,
                        value: <[u8; 6]>::try_from(value).unwrap()
                    } )
                }
                ExtendedCommunityType::NonTransitiveOpaque => {
                    let sub_type = input.read_8b()?;
                    let value = input.read_n_bytes(6)?;
                    ExtendedCommunity::NonTransitiveOpaque( Opaque{
                        ec_type: ec_type_u8,
                        ec_subtype: sub_type,
                        value: <[u8; 6]>::try_from(value).unwrap()
                    } )
                }
            };

            communities.push(ec);
        }
        Ok(Attribute::ExtendedCommunities(communities))
    }

    fn parse_ipv6_extended_community<T: Read>(
        &self,
        input: &mut Take<T>,
    ) -> Result<Attribute, ParserError> {
        let mut communities = Vec::new();
        while input.limit() > 0 {
            let ec_type_u8 = input.read_8b()?;
            let sub_type = input.read_8b()?;
            let global = Ipv6Addr::from(input.read_u128::<BigEndian>()?);
            let local = input.read_n_bytes(2)?;
            let ec = ExtendedCommunity::Ipv6AddressSpecific(
                Ipv6AddressSpecific {
                    ec_type: ec_type_u8,
                    ec_subtype: sub_type,
                    global_administrator: global,
                    local_administrator: <[u8; 2]>::try_from(local).unwrap()
                }
            );
            communities.push(ec);
        }
        Ok(Attribute::ExtendedCommunities(communities))
    }
}

