use bgp_models::bgp::attributes::*;
use bgp_models::bgp::community::*;
use bgp_models::network::*;
use byteorder::{ReadBytesExt, BE};
use log::{debug, warn};
use std::io::{Cursor, Seek, SeekFrom};
use std::net::Ipv4Addr;

use num_traits::FromPrimitive;

use crate::error::ParserError;
use crate::parser::{parse_nlri_list, ReadUtils};

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

    /// Parse BGP attributes given a slice of u8 and some options.
    ///
    /// The `data: &[u8]` contains the entirety of the attributes bytes, therefore the size of
    /// the slice is the total byte length of the attributes section of the message.
    pub fn parse_attributes(
        &self,
        data: &[u8],
        asn_len: &AsnLength,
        afi: Option<Afi>,
        safi: Option<Safi>,
        prefixes: Option<&[NetworkPrefix]>,
    ) -> Result<Vec<Attribute>, ParserError> {
        let mut attributes: Vec<Attribute> = Vec::with_capacity(20);
        let total_slices_bytes = data.len() as u64;
        let mut input = Cursor::new(data);

        while input.position() + 3 <= total_slices_bytes {
            // each attribute is at least 3 bytes: flag(1) + type(1) + length(1)
            // thus the while loop condition is set to be at least 3 bytes to read.

            // has content to read
            let flag = input.read_8b()?;
            let attr_type = input.read_8b()?;
            let length = match flag & AttributeFlagsBit::ExtendedLengthBit as u8 {
                0 => input.read_8b()? as usize,
                _ => input.read_u16::<BE>()? as usize,
            };

            let mut partial = false;

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
                partial = true;
            }

            debug!(
                "reading attribute: type -- {:?}, length -- {}",
                &attr_type, length
            );
            let attr_type = match AttrType::from_u8(attr_type) {
                Some(t) => t,
                None => {
                    // input.read_and_drop_n_bytes(length)?;
                    input.seek(SeekFrom::Current(length as i64))?;
                    return match attr_type {
                        11 | 12 | 13 | 19 | 20 | 21 | 28 | 30 | 31 | 129 | 241..=243 => {
                            Err(ParserError::DeprecatedAttr(format!(
                                "deprecated attribute type: {}",
                                attr_type
                            )))
                        }
                        _ => Err(ParserError::UnknownAttr(format!(
                            "unknown attribute type: {}",
                            attr_type
                        ))),
                    };
                }
            };

            let bytes_left = total_slices_bytes - input.position();
            let attr_end_pos = input.position() + length as u64;

            if bytes_left < length as u64 {
                warn!(
                    "not enough bytes: input bytes left - {}, want to read - {}; skipping",
                    bytes_left, length
                );
                break;
            }

            let attr = match attr_type {
                AttrType::ORIGIN => self.parse_origin(&mut input),
                AttrType::AS_PATH => self.parse_as_path(&mut input, asn_len, length),
                AttrType::NEXT_HOP => self.parse_next_hop(&mut input, &afi),
                AttrType::MULTI_EXIT_DISCRIMINATOR => self.parse_med(&mut input),
                AttrType::LOCAL_PREFERENCE => self.parse_local_pref(&mut input),
                AttrType::ATOMIC_AGGREGATE => {
                    Ok(AttributeValue::AtomicAggregate(AtomicAggregate::AG))
                }
                AttrType::AGGREGATOR => self.parse_aggregator(&mut input, asn_len, &afi),
                AttrType::ORIGINATOR_ID => self.parse_originator_id(&mut input, &afi),
                AttrType::CLUSTER_LIST => self.parse_clusters(&mut input, &afi, length),
                AttrType::MP_REACHABLE_NLRI => {
                    self.parse_nlri(&mut input, &afi, &safi, &prefixes, true, length)
                }
                AttrType::MP_UNREACHABLE_NLRI => {
                    self.parse_nlri(&mut input, &afi, &safi, &prefixes, false, length)
                }
                AttrType::AS4_PATH => self.parse_as_path(&mut input, &AsnLength::Bits32, length),
                AttrType::AS4_AGGREGATOR => {
                    self.parse_aggregator(&mut input, &AsnLength::Bits32, &afi)
                }

                // communities
                AttrType::COMMUNITIES => self.parse_regular_communities(&mut input, length),
                AttrType::LARGE_COMMUNITIES => self.parse_large_communities(&mut input, length),
                AttrType::EXTENDED_COMMUNITIES => self.parse_extended_community(&mut input, length),
                AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES => {
                    self.parse_ipv6_extended_community(&mut input, length)
                }
                AttrType::DEVELOPMENT => {
                    let mut value = vec![];
                    for _i in 0..length {
                        value.push(input.read_8b()?);
                    }
                    Ok(AttributeValue::Development(value))
                }
                AttrType::ONLY_TO_CUSTOMER => self.parse_only_to_customer_attr(&mut input),
                _ => Err(crate::error::ParserError::Unsupported(format!(
                    "unsupported attribute type: {:?}",
                    attr_type
                ))),
            };

            debug!(
                "seeking position tp {}/{}",
                attr_end_pos,
                input.get_ref().len()
            );
            // always fast forward to the attribute end position.
            input.seek(SeekFrom::Start(attr_end_pos))?;

            match attr {
                Ok(value) => {
                    attributes.push(Attribute {
                        value,
                        flag,
                        attr_type,
                    });
                }
                Err(e) => {
                    if partial {
                        // it's ok to have errors when reading partial bytes
                        warn!("PARTIAL: {}", e.to_string());
                    } else {
                        warn!("{}", e.to_string());
                    }
                    continue;
                }
            };
        }

        Ok(attributes)
    }

    fn parse_origin(&self, input: &mut Cursor<&[u8]>) -> Result<AttributeValue, ParserError> {
        let origin = input.read_8b()?;
        match Origin::from_u8(origin) {
            Some(v) => Ok(AttributeValue::Origin(v)),
            None => Err(crate::error::ParserError::UnknownAttr(
                "Failed to parse attribute type: origin".to_string(),
            )),
        }
    }

    fn parse_as_path(
        &self,
        input: &mut Cursor<&[u8]>,
        asn_len: &AsnLength,
        total_bytes: usize,
    ) -> Result<AttributeValue, ParserError> {
        let mut output = AsPath {
            segments: Vec::with_capacity(5),
        };
        let pos_end = input.position() + total_bytes as u64;
        while input.position() < pos_end {
            let segment = self.parse_as_segment(input, asn_len)?;
            output.add_segment(segment);
        }
        Ok(AttributeValue::AsPath(output))
    }

    fn parse_as_segment(
        &self,
        input: &mut Cursor<&[u8]>,
        asn_len: &AsnLength,
    ) -> Result<AsPathSegment, ParserError> {
        let segment_type = input.read_8b()?;
        let count = input.read_8b()?;
        let path = input.read_asns(asn_len, count as usize)?;
        match segment_type {
            AttributeParser::AS_PATH_AS_SET => Ok(AsPathSegment::AsSet(path)),
            AttributeParser::AS_PATH_AS_SEQUENCE => Ok(AsPathSegment::AsSequence(path)),
            AttributeParser::AS_PATH_CONFED_SEQUENCE => Ok(AsPathSegment::ConfedSequence(path)),
            AttributeParser::AS_PATH_CONFED_SET => Ok(AsPathSegment::ConfedSet(path)),
            _ => Err(ParserError::ParseError(format!(
                "Invalid AS path segment type: {}",
                segment_type
            ))),
        }
    }

    fn parse_next_hop(
        &self,
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

    fn parse_med(&self, input: &mut Cursor<&[u8]>) -> Result<AttributeValue, ParserError> {
        match input.read_32b() {
            Ok(v) => Ok(AttributeValue::MultiExitDiscriminator(v)),
            Err(err) => Err(ParserError::from(err)),
        }
    }

    fn parse_local_pref(&self, input: &mut Cursor<&[u8]>) -> Result<AttributeValue, ParserError> {
        match input.read_32b() {
            Ok(v) => Ok(AttributeValue::LocalPreference(v)),
            Err(err) => Err(ParserError::from(err)),
        }
    }

    fn parse_aggregator(
        &self,
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

    fn parse_regular_communities(
        &self,
        input: &mut Cursor<&[u8]>,
        total_bytes: usize,
    ) -> Result<AttributeValue, ParserError> {
        const COMMUNITY_NO_EXPORT: u32 = 0xFFFFFF01;
        const COMMUNITY_NO_ADVERTISE: u32 = 0xFFFFFF02;
        const COMMUNITY_NO_EXPORT_SUBCONFED: u32 = 0xFFFFFF03;

        debug!(
            "reading communities. cursor_pos: {}/{}; total to read: {}",
            input.position(),
            input.get_ref().len(),
            total_bytes
        );

        let mut communities = vec![];
        let mut read = 0;

        while read < total_bytes {
            let community_val = input.read_32b()?;
            communities.push(match community_val {
                COMMUNITY_NO_EXPORT => Community::NoExport,
                COMMUNITY_NO_ADVERTISE => Community::NoAdvertise,
                COMMUNITY_NO_EXPORT_SUBCONFED => Community::NoExportSubConfed,
                value => {
                    let asn = Asn {
                        asn: ((value >> 16) & 0xffff),
                        len: AsnLength::Bits16,
                    };
                    let value = (value & 0xffff) as u16;
                    Community::Custom(asn, value)
                }
            });
            read += 4;
        }

        debug!(
            "finished reading communities. cursor_pos: {}/{}; {:?}",
            input.position(),
            input.get_ref().len(),
            &communities
        );
        Ok(AttributeValue::Communities(communities))
    }

    fn parse_originator_id(
        &self,
        input: &mut Cursor<&[u8]>,
        afi: &Option<Afi>,
    ) -> Result<AttributeValue, ParserError> {
        let afi = match afi {
            None => &Afi::Ipv4,
            Some(a) => a,
        };
        let addr = input.read_address(afi)?;
        Ok(AttributeValue::OriginatorId(addr))
    }

    #[allow(unused)]
    fn parse_cluster_id(
        &self,
        input: &mut Cursor<&[u8]>,
        afi: &Option<Afi>,
    ) -> Result<AttributeValue, ParserError> {
        let afi = match afi {
            None => &Afi::Ipv4,
            Some(a) => a,
        };
        let addr = input.read_address(afi)?;
        Ok(AttributeValue::Clusters(vec![addr]))
    }

    fn parse_clusters(
        &self,
        input: &mut Cursor<&[u8]>,
        afi: &Option<Afi>,
        total_bytes: usize,
    ) -> Result<AttributeValue, ParserError> {
        // FIXME: in https://tools.ietf.org/html/rfc4456, the CLUSTER_LIST is a set of CLUSTER_ID each represented by a 4-byte number
        let mut clusters = Vec::new();
        let initial_pos = input.position();
        while input.position() - initial_pos < total_bytes as u64 {
            let afi = match afi {
                None => &Afi::Ipv4,
                Some(a) => a,
            };

            let addr = input.read_address(afi)?;

            clusters.push(addr);
        }
        Ok(AttributeValue::Clusters(clusters))
    }

    ///
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
    fn parse_nlri(
        &self,
        input: &mut Cursor<&[u8]>,
        afi: &Option<Afi>,
        safi: &Option<Safi>,
        prefixes: &Option<&[NetworkPrefix]>,
        reachable: bool,
        total_bytes: usize,
    ) -> Result<AttributeValue, ParserError> {
        let first_byte_zero = input.get_ref()[input.position() as usize] == 0;
        let pos_end = input.position() + total_bytes as u64;

        // read address family
        let afi = match afi {
            Some(afi) => {
                if first_byte_zero {
                    input.read_afi()?
                } else {
                    afi.to_owned()
                }
            }
            None => input.read_afi()?,
        };
        let safi = match safi {
            Some(safi) => {
                if first_byte_zero {
                    input.read_safi()?
                } else {
                    safi.to_owned()
                }
            }
            None => input.read_safi()?,
        };

        let mut next_hop = None;
        if reachable {
            let next_hop_length = input.read_8b()?;
            next_hop = match self.parse_mp_next_hop(next_hop_length, input) {
                Ok(x) => x,
                Err(e) => return Err(e),
            };
        }

        let mut bytes_left = pos_end - input.position();

        let prefixes = match prefixes {
            Some(pfxs) => {
                // skip parsing prefixes: https://datatracker.ietf.org/doc/html/rfc6396#section-4.3.4
                if first_byte_zero {
                    if reachable {
                        // skip reserved byte for reachable NRLI
                        if input.read_8b()? != 0 {
                            warn!("NRLI reserved byte not 0");
                        }
                        bytes_left -= 1;
                    }
                    parse_nlri_list(input, self.additional_paths, &afi, bytes_left)?
                } else {
                    pfxs.to_vec()
                }
            }
            None => {
                if reachable {
                    // skip reserved byte for reachable NRLI
                    if input.read_8b()? != 0 {
                        warn!("NRLI reserved byte not 0");
                    }
                    bytes_left -= 1;
                }
                parse_nlri_list(input, self.additional_paths, &afi, bytes_left)?
            }
        };

        // Reserved field, should ignore
        match reachable {
            true => Ok(AttributeValue::MpReachNlri(Nlri {
                afi,
                safi,
                next_hop,
                prefixes,
            })),
            false => Ok(AttributeValue::MpUnreachNlri(Nlri {
                afi,
                safi,
                next_hop,
                prefixes,
            })),
        }
    }

    fn parse_mp_next_hop(
        &self,
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

    fn parse_large_communities(
        &self,
        input: &mut Cursor<&[u8]>,
        total_bytes: usize,
    ) -> Result<AttributeValue, ParserError> {
        let mut communities = Vec::new();
        let pos_end = input.position() + total_bytes as u64;
        while input.position() < pos_end {
            let global_administrator = input.read_32b()?;
            let local_data = [input.read_32b()?, input.read_32b()?];
            communities.push(LargeCommunity::new(global_administrator, local_data));
        }
        Ok(AttributeValue::LargeCommunities(communities))
    }

    fn parse_extended_community(
        &self,
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
                    let global = input.read_u16::<BE>()?;
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
                    let global = input.read_u16::<BE>()?;
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

    fn parse_ipv6_extended_community(
        &self,
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

    /// parse RFC9234 OnlyToCustomer attribute.
    ///
    /// RFC: https://www.rfc-editor.org/rfc/rfc9234.html#name-bgp-only-to-customer-otc-at
    ///
    /// ```text
    /// The OTC Attribute is an optional transitive Path Attribute of the UPDATE message with Attribute Type Code 35 and a length of 4 octets.
    ///
    /// The following ingress procedure applies to the processing of the OTC Attribute on route receipt:
    /// 1. If a route with the OTC Attribute is received from a Customer or an RS-Client, then it is a route leak and MUST be considered ineligible (see Section 3).
    /// 2. If a route with the OTC Attribute is received from a Peer (i.e., remote AS with a Peer Role) and the Attribute has a value that is not equal to the remote (i.e., Peer's) AS number, then it is a route leak and MUST be considered ineligible.
    /// 3. If a route is received from a Provider, a Peer, or an RS and the OTC Attribute is not present, then it MUST be added with a value equal to the AS number of the remote AS.
    ///
    /// The following egress procedure applies to the processing of the OTC Attribute on route advertisement:
    /// 1. If a route is to be advertised to a Customer, a Peer, or an RS-Client (when the sender is an RS), and the OTC Attribute is not present, then when advertising the route, an OTC Attribute MUST be added with a value equal to the AS number of the local AS.
    /// 2. If a route already contains the OTC Attribute, it MUST NOT be propagated to Providers, Peers, or RSes.
    /// ```
    fn parse_only_to_customer_attr(
        &self,
        input: &mut Cursor<&[u8]>,
    ) -> Result<AttributeValue, ParserError> {
        let remote_asn = input.read_32b()?;
        Ok(AttributeValue::OnlyToCustomer(remote_asn))
    }
}
