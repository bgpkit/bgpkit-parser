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

use crate::models::*;

use crate::error::ParserError;
use crate::parser::bgp::attributes::attr_01_origin::parse_origin;
use crate::parser::bgp::attributes::attr_02_17_as_path::parse_as_path;
use crate::parser::bgp::attributes::attr_03_next_hop::parse_next_hop;
use crate::parser::bgp::attributes::attr_04_med::parse_med;
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
    ) -> Result<Attributes, ParserError> {
        let mut attributes: Vec<Attribute> = Vec::with_capacity(20);

        while data.remaining() >= 3 {
            // each attribute is at least 3 bytes: flag(1) + type(1) + length(1)
            // thus the while loop condition is set to be at least 3 bytes to read.

            // has content to read
            let flag = AttrFlags::from_bits_retain(data.read_u8()?);
            let attr_type = data.read_u8()?;
            let attr_length = match flag.contains(AttrFlags::EXTENDED) {
                false => data.read_u8()? as usize,
                true => data.read_u16()? as usize,
            };

            let mut partial = false;
            if flag.contains(AttrFlags::PARTIAL) {
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
                &attr_type, attr_length
            );
            let attr_type = match AttrType::from(attr_type) {
                attr_type @ AttrType::Unknown(unknown_type) => {
                    // skip pass the remaining bytes of this attribute
                    let bytes = data.read_n_bytes(attr_length)?;
                    let attr_value = match get_deprecated_attr_type(unknown_type) {
                        Some(t) => {
                            debug!("deprecated attribute type: {} - {}", unknown_type, t);
                            AttributeValue::Deprecated(AttrRaw { attr_type, bytes })
                        }
                        None => {
                            debug!("unknown attribute type: {}", unknown_type);
                            AttributeValue::Unknown(AttrRaw { attr_type, bytes })
                        }
                    };

                    assert_eq!(attr_type, attr_value.attr_type());
                    attributes.push(Attribute {
                        value: attr_value,
                        flag,
                    });
                    continue;
                }
                t => t,
            };

            // we know data has enough bytes to read, so we can split the bytes into a new Bytes object
            data.require_n_remaining(attr_length, "Attribute")?;
            let mut attr_data = data.split_to(attr_length);

            let attr = match attr_type {
                AttrType::ORIGIN => parse_origin(attr_data),
                AttrType::AS_PATH => {
                    parse_as_path(attr_data, asn_len).map(|path| AttributeValue::AsPath {
                        path,
                        is_as4: false,
                    })
                }
                AttrType::NEXT_HOP => parse_next_hop(attr_data, &afi),
                AttrType::MULTI_EXIT_DISCRIMINATOR => parse_med(attr_data),
                AttrType::LOCAL_PREFERENCE => parse_local_pref(attr_data),
                AttrType::ATOMIC_AGGREGATE => Ok(AttributeValue::AtomicAggregate),
                AttrType::AGGREGATOR => parse_aggregator(attr_data, asn_len).map(|(asn, id)| {
                    AttributeValue::Aggregator {
                        asn,
                        id,
                        is_as4: false,
                    }
                }),
                AttrType::ORIGINATOR_ID => parse_originator_id(attr_data),
                AttrType::CLUSTER_LIST => parse_clusters(attr_data),
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
                AttrType::AS4_PATH => parse_as_path(attr_data, &AsnLength::Bits32)
                    .map(|path| AttributeValue::AsPath { path, is_as4: true }),
                AttrType::AS4_AGGREGATOR => {
                    parse_aggregator(attr_data, &AsnLength::Bits32).map(|(asn, id)| {
                        AttributeValue::Aggregator {
                            asn,
                            id,
                            is_as4: true,
                        }
                    })
                }

                // communities
                AttrType::COMMUNITIES => parse_regular_communities(attr_data),
                AttrType::LARGE_COMMUNITIES => parse_large_communities(attr_data),
                AttrType::EXTENDED_COMMUNITIES => parse_extended_community(attr_data),
                AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES => {
                    parse_ipv6_extended_community(attr_data)
                }
                AttrType::DEVELOPMENT => {
                    let mut value = vec![];
                    for _i in 0..attr_length {
                        value.push(attr_data.read_u8()?);
                    }
                    Ok(AttributeValue::Development(value))
                }
                AttrType::ONLY_TO_CUSTOMER => parse_only_to_customer(attr_data),
                // TODO: Should it be treated as a raw attribute instead?
                _ => Err(ParserError::UnsupportedAttributeType(attr_type)),
            };

            match attr {
                Ok(value) => {
                    assert_eq!(attr_type, value.attr_type());
                    attributes.push(Attribute { value, flag });
                }
                Err(e) if partial => {
                    // TODO: Is this correct? If we don't have enough bytes, split_to would panic.
                    // it's ok to have errors when reading partial bytes
                    warn!("PARTIAL: {}", e);
                }
                Err(e) => {
                    warn!("{}", e);
                    return Err(e);
                }
            };
        }

        Ok(Attributes::from(attributes))
    }
}
