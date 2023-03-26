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

use byteorder::{ReadBytesExt, BE};
use log::{debug, warn};
use std::io::{Cursor, Seek, SeekFrom};

use bgp_models::prelude::*;
use num_traits::FromPrimitive;

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
                AttrType::ORIGIN => parse_origin(&mut input),
                AttrType::AS_PATH => parse_as_path(&mut input, asn_len, length),
                AttrType::NEXT_HOP => parse_next_hop(&mut input, &afi),
                AttrType::MULTI_EXIT_DISCRIMINATOR => parse_med(&mut input),
                AttrType::LOCAL_PREFERENCE => parse_local_pref(&mut input),
                AttrType::ATOMIC_AGGREGATE => {
                    Ok(AttributeValue::AtomicAggregate(AtomicAggregate::AG))
                }
                AttrType::AGGREGATOR => parse_aggregator(&mut input, asn_len, &afi),
                AttrType::ORIGINATOR_ID => parse_originator_id(&mut input, &afi),
                AttrType::CLUSTER_LIST => parse_clusters(&mut input, &afi, length),
                AttrType::MP_REACHABLE_NLRI => parse_nlri(
                    &mut input,
                    &afi,
                    &safi,
                    &prefixes,
                    true,
                    self.additional_paths,
                    length,
                ),
                AttrType::MP_UNREACHABLE_NLRI => parse_nlri(
                    &mut input,
                    &afi,
                    &safi,
                    &prefixes,
                    false,
                    self.additional_paths,
                    length,
                ),
                AttrType::AS4_PATH => parse_as_path(&mut input, &AsnLength::Bits32, length),
                AttrType::AS4_AGGREGATOR => parse_aggregator(&mut input, &AsnLength::Bits32, &afi),

                // communities
                AttrType::COMMUNITIES => parse_regular_communities(&mut input, length),
                AttrType::LARGE_COMMUNITIES => parse_large_communities(&mut input, length),
                AttrType::EXTENDED_COMMUNITIES => parse_extended_community(&mut input, length),
                AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES => {
                    parse_ipv6_extended_community(&mut input, length)
                }
                AttrType::DEVELOPMENT => {
                    let mut value = vec![];
                    for _i in 0..length {
                        value.push(input.read_8b()?);
                    }
                    Ok(AttributeValue::Development(value))
                }
                AttrType::ONLY_TO_CUSTOMER => parse_only_to_customer(&mut input),
                _ => Err(ParserError::Unsupported(format!(
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
}
