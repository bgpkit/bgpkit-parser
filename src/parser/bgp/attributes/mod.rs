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

use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::{debug, warn};
use std::net::IpAddr;

use crate::models::*;

use crate::error::ParserError;
use crate::parser::bgp::attributes::attr_01_origin::{encode_origin, parse_origin};
use crate::parser::bgp::attributes::attr_02_17_as_path::{encode_as_path, parse_as_path};
use crate::parser::bgp::attributes::attr_03_next_hop::{encode_next_hop, parse_next_hop};
use crate::parser::bgp::attributes::attr_04_med::{encode_med, parse_med};
use crate::parser::bgp::attributes::attr_05_local_pref::{encode_local_pref, parse_local_pref};
use crate::parser::bgp::attributes::attr_07_18_aggregator::{encode_aggregator, parse_aggregator};
use crate::parser::bgp::attributes::attr_08_communities::{
    encode_regular_communities, parse_regular_communities,
};
use crate::parser::bgp::attributes::attr_09_originator::{
    encode_originator_id, parse_originator_id,
};
use crate::parser::bgp::attributes::attr_10_13_cluster::{encode_clusters, parse_clusters};
use crate::parser::bgp::attributes::attr_14_15_nlri::{encode_nlri, parse_nlri};
use crate::parser::bgp::attributes::attr_16_25_extended_communities::{
    encode_extended_communities, parse_extended_community, parse_ipv6_extended_community,
};
use crate::parser::bgp::attributes::attr_32_large_communities::{
    encode_large_communities, parse_large_communities,
};
use crate::parser::bgp::attributes::attr_35_otc::{
    encode_only_to_customer, parse_only_to_customer,
};
use crate::parser::ReadUtils;

/// Parse BGP attributes given a slice of u8 and some options.
///
/// The `data: &[u8]` contains the entirety of the attributes bytes, therefore the size of
/// the slice is the total byte length of the attributes section of the message.
pub fn parse_attributes(
    mut data: Bytes,
    asn_len: &AsnLength,
    add_path: bool,
    afi: Option<Afi>,
    safi: Option<Safi>,
    prefixes: Option<&[NetworkPrefix]>,
) -> Result<Attributes, ParserError> {
    let mut attributes: Vec<Attribute> = Vec::with_capacity(20);

    while data.remaining() >= 3 {
        // each attribute is at least 3 bytes: flag(1) + type(1) + length(1)
        // thus the while loop condition is set to be at least 3 bytes to read.

        // has content to read
        let flag = AttrFlags::from_bits_retain(data.get_u8());
        let attr_type = data.get_u8();
        let attr_length = match flag.contains(AttrFlags::EXTENDED) {
            false => data.get_u8() as usize,
            true => data.get_u16() as usize,
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

        let bytes_left = data.remaining();

        if data.remaining() < attr_length {
            warn!(
                "not enough bytes: input bytes left - {}, want to read - {}; skipping",
                bytes_left, attr_length
            );
            // break and return already parsed attributes
            break;
        }

        // we know data has enough bytes to read, so we can split the bytes into a new Bytes object
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
            AttrType::AGGREGATOR => {
                parse_aggregator(attr_data, asn_len).map(|(asn, id)| AttributeValue::Aggregator {
                    asn,
                    id,
                    is_as4: false,
                })
            }
            AttrType::ORIGINATOR_ID => parse_originator_id(attr_data),
            AttrType::CLUSTER_LIST => parse_clusters(attr_data),
            AttrType::MP_REACHABLE_NLRI => {
                parse_nlri(attr_data, &afi, &safi, &prefixes, true, add_path)
            }
            AttrType::MP_UNREACHABLE_NLRI => {
                parse_nlri(attr_data, &afi, &safi, &prefixes, false, add_path)
            }
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
                assert_eq!(attr_type, value.attr_type());
                attributes.push(Attribute { value, flag });
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

    Ok(Attributes::from(attributes))
}

impl Attribute {
    pub fn encode(&self, add_path: bool, asn_len: AsnLength) -> Bytes {
        let mut bytes = BytesMut::new();

        bytes.put_u8(self.flag.bits());
        bytes.put_u8(self.value.attr_type().into());

        let value_bytes = match &self.value {
            AttributeValue::Origin(v) => encode_origin(v),
            AttributeValue::AsPath { path, is_as4 } => {
                let four_byte = match is_as4 {
                    true => AsnLength::Bits32,
                    false => match asn_len.is_four_byte() {
                        true => AsnLength::Bits32,
                        false => AsnLength::Bits16,
                    },
                };
                encode_as_path(path, four_byte)
            }
            AttributeValue::NextHop(v) => encode_next_hop(v),
            AttributeValue::MultiExitDiscriminator(v) => encode_med(*v),
            AttributeValue::LocalPreference(v) => encode_local_pref(*v),
            AttributeValue::OnlyToCustomer(v) => encode_only_to_customer(v.into()),
            AttributeValue::AtomicAggregate => Bytes::default(),
            AttributeValue::Aggregator { asn, id, is_as4: _ } => {
                encode_aggregator(asn, &IpAddr::from(*id))
            }
            AttributeValue::Communities(v) => encode_regular_communities(v),
            AttributeValue::ExtendedCommunities(v) => encode_extended_communities(v),
            AttributeValue::LargeCommunities(v) => encode_large_communities(v),
            AttributeValue::OriginatorId(v) => encode_originator_id(&IpAddr::from(*v)),
            AttributeValue::Clusters(v) => encode_clusters(v),
            AttributeValue::MpReachNlri(v) => encode_nlri(v, true, add_path),
            AttributeValue::MpUnreachNlri(v) => encode_nlri(v, false, add_path),
            AttributeValue::Development(v) => Bytes::from(v.to_owned()),
            AttributeValue::Deprecated(v) => Bytes::from(v.bytes.to_owned()),
            AttributeValue::Unknown(v) => Bytes::from(v.bytes.to_owned()),
        };

        match self.is_extended() {
            false => {
                bytes.put_u8(value_bytes.len() as u8);
            }
            true => {
                bytes.put_u16(value_bytes.len() as u16);
            }
        }
        bytes.extend(value_bytes);
        bytes.freeze()
    }
}
