mod attr_01_origin;
mod attr_02_17_as_path;
mod attr_03_next_hop;
mod attr_04_med;
mod attr_05_local_pref;
mod attr_07_18_aggregator;
mod attr_08_communities;
mod attr_09_originator;
mod attr_10_13_cluster;
mod attr_14_15_nlri;
mod attr_16_25_extended_communities;
mod attr_32_large_communities;
mod attr_35_otc;

use bytes::{Buf, Bytes};
use log::{debug, warn};

use crate::encoder::MrtEncode;
use crate::models::*;
use num_traits::FromPrimitive;

use crate::error::ParserError;
use crate::parser::bgp::attributes::attr_01_origin::{encode_origin, parse_origin};
use crate::parser::bgp::attributes::attr_02_17_as_path::{encode_as_path, parse_as_path};
use crate::parser::bgp::attributes::attr_03_next_hop::{encode_next_hop, parse_next_hop};
use crate::parser::bgp::attributes::attr_04_med::{encode_med, parse_med};
use crate::parser::bgp::attributes::attr_05_local_pref::parse_local_pref;
use crate::parser::bgp::attributes::attr_07_18_aggregator::parse_aggregator;
use crate::parser::bgp::attributes::attr_08_communities::parse_regular_communities;
use crate::parser::bgp::attributes::attr_09_originator::parse_originator_id;
use crate::parser::bgp::attributes::attr_10_13_cluster::parse_clusters;
use crate::parser::bgp::attributes::attr_14_15_nlri::parse_nlri;
use crate::parser::bgp::attributes::attr_16_25_extended_communities::{
    parse_extended_community, parse_ipv6_extended_community,
};
use crate::parser::bgp::attributes::attr_32_large_communities::parse_large_communities;
use crate::parser::bgp::attributes::attr_35_otc::parse_only_to_customer;
use crate::parser::ReadUtils;

pub struct AttributeParser {
    additional_paths: bool,
}

impl AttributeParser {
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
        mut data: Bytes,
        asn_len: &AsnLength,
        afi: Option<Afi>,
        safi: Option<Safi>,
        prefixes: Option<&[NetworkPrefix]>,
    ) -> Result<Vec<Attribute>, ParserError> {
        let mut attributes: Vec<Attribute> = Vec::with_capacity(20);

        while data.remaining() >= 3 {
            // each attribute is at least 3 bytes: flag(1) + type(1) + length(1)
            // thus the while loop condition is set to be at least 3 bytes to read.

            // has content to read
            let flag = data.get_u8();
            let attr_type = data.get_u8();
            let length = match flag & AttributeFlagsBit::ExtendedLengthBit as u8 {
                0 => data.get_u8() as usize,
                _ => data.get_u16() as usize,
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
                    data.has_n_remaining(length)?;
                    data.advance(length);
                    return match get_deprecated_attr_type(attr_type) {
                        Some(t) => Err(ParserError::DeprecatedAttr(format!(
                            "deprecated attribute type: {} - {}",
                            attr_type, t
                        ))),
                        None => Err(ParserError::UnknownAttr(format!(
                            "unknown attribute type: {}",
                            attr_type
                        ))),
                    };
                }
            };

            let bytes_left = data.remaining();

            if data.remaining() < length {
                warn!(
                    "not enough bytes: input bytes left - {}, want to read - {}; skipping",
                    bytes_left, length
                );
                // break and return already parsed attributes
                break;
            }

            // we know data has enough bytes to read, so we can split the bytes into a new Bytes object
            let mut attr_data = data.split_to(length);

            let attr = match attr_type {
                AttrType::ORIGIN => parse_origin(attr_data),
                AttrType::AS_PATH => parse_as_path(attr_data, asn_len),
                AttrType::NEXT_HOP => parse_next_hop(attr_data, &afi),
                AttrType::MULTI_EXIT_DISCRIMINATOR => parse_med(attr_data),
                AttrType::LOCAL_PREFERENCE => parse_local_pref(attr_data),
                AttrType::ATOMIC_AGGREGATE => {
                    Ok(AttributeValue::AtomicAggregate(AtomicAggregate::AG))
                }
                AttrType::AGGREGATOR => parse_aggregator(attr_data, asn_len, &afi),
                AttrType::ORIGINATOR_ID => parse_originator_id(attr_data, &afi),
                AttrType::CLUSTER_LIST => parse_clusters(attr_data, &afi),
                AttrType::MP_REACHABLE_NLRI => parse_nlri(
                    attr_data,
                    &afi,
                    &safi,
                    &prefixes,
                    true,
                    self.additional_paths,
                ),
                AttrType::MP_UNREACHABLE_NLRI => parse_nlri(
                    attr_data,
                    &afi,
                    &safi,
                    &prefixes,
                    false,
                    self.additional_paths,
                ),
                AttrType::AS4_PATH => parse_as_path(attr_data, &AsnLength::Bits32),
                AttrType::AS4_AGGREGATOR => parse_aggregator(attr_data, &AsnLength::Bits32, &afi),

                // communities
                AttrType::COMMUNITIES => parse_regular_communities(attr_data),
                AttrType::LARGE_COMMUNITIES => parse_large_communities(attr_data),
                AttrType::EXTENDED_COMMUNITIES => parse_extended_community(attr_data),
                AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES => {
                    parse_ipv6_extended_community(attr_data)
                }
                AttrType::DEVELOPMENT => {
                    let mut value = vec![];
                    for _i in 0..length {
                        value.push(attr_data.get_u8());
                    }
                    Ok(AttributeValue::Development(value))
                }
                AttrType::ONLY_TO_CUSTOMER => parse_only_to_customer(attr_data),
                _ => Err(ParserError::Unsupported(format!(
                    "unsupported attribute type: {:?}",
                    attr_type
                ))),
            };

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
}

impl MrtEncode for Attribute {
    fn encode(&self) -> Bytes {
        let bytes = match &self.value {
            AttributeValue::Origin(v) => encode_origin(v),
            AttributeValue::AsPath(v) => encode_as_path(v, AsnLength::Bits16),
            AttributeValue::As4Path(v) => encode_as_path(v, AsnLength::Bits32),
            AttributeValue::NextHop(v) => encode_next_hop(v),
            AttributeValue::MultiExitDiscriminator(v) => encode_med(*v),
            AttributeValue::LocalPreference(v) => {
                todo!()
            }
            AttributeValue::OnlyToCustomer(v) => {
                todo!()
            }
            AttributeValue::AtomicAggregate(v) => {
                todo!()
            }
            AttributeValue::Aggregator(v, _) => {
                todo!()
            }
            AttributeValue::Communities(v) => {
                todo!()
            }
            AttributeValue::ExtendedCommunities(v) => {
                todo!()
            }
            AttributeValue::LargeCommunities(v) => {
                todo!()
            }
            AttributeValue::OriginatorId(v) => {
                todo!()
            }
            AttributeValue::Clusters(v) => {
                todo!()
            }
            AttributeValue::MpReachNlri(v) => {
                todo!()
            }
            AttributeValue::MpUnreachNlri(v) => {
                todo!()
            }
            AttributeValue::Development(v) => {
                todo!()
            }
        };
        todo!()
    }
}
