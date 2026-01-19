//! RIB Generic entries parser - supports VPN routes (SAFI 128)
//!
//! This module parses RIB_GENERIC subtype (6) entries from MRT TABLE_DUMP_V2 format.
//! RIB_GENERIC is used for NLRI types that don't fit the standard AFI-specific subtypes,
//! including VPN routes (SAFI 128).
//!
//! Reference: RFC 6396 Section 4.3.3

use crate::bgp::attributes::parse_attributes;
use crate::models::{Afi, AsnLength, NetworkPrefix, RibEntry, RibGenericEntries, Safi};
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, Bytes};
use log::warn;

/// Parse RIB_GENERIC entries (subtype 6).
///
/// RFC 6396 Section 4.3.3:
/// ```text
///         0                   1                   2                   3
///         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                         Sequence Number                       |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |    Address Family Identifier  |Subsequent AFI |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |     Network Layer Reachability Information (variable)         |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |         Entry Count           |  RIB Entries (variable)
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn parse_rib_generic_entries(
    data: &mut Bytes,
    is_add_path: bool,
) -> Result<RibGenericEntries, ParserError> {
    let sequence_number = data.read_u32()?;
    let afi = data.read_afi()?;
    let safi = data.read_safi()?;

    // Parse NLRI based on SAFI
    let nlri = match safi {
        Safi::MplsVpn => {
            // VPN NLRI format: [Label 3B] + [RD 8B] + [Prefix variable]
            data.read_vpn_nlri_prefix(&afi, is_add_path)?
        }
        _ => {
            // For other SAFIs, fall back to standard prefix parsing
            data.read_nlri_prefix(&afi, is_add_path)?
        }
    };

    let entry_count = data.read_u16()?;

    // Pre-allocate cautiously to avoid overflow/OOM with malformed inputs
    let min_entry_size =
        2 /*peer_index*/ + 4 /*time*/ + 2 /*attr_len*/ + if is_add_path { 4 } else { 0 };
    let max_possible = data.remaining() / min_entry_size;
    let reserve = (entry_count as usize).min(max_possible).saturating_mul(2);
    let mut rib_entries = Vec::with_capacity(reserve);

    for _i in 0..entry_count {
        let entry = match parse_rib_generic_entry(data, is_add_path, &afi, &safi, nlri) {
            Ok(entry) => entry,
            Err(e) => {
                warn!("early break due to error {}", e);
                break;
            }
        };
        rib_entries.push(entry);
    }

    Ok(RibGenericEntries {
        sequence_number,
        afi,
        safi,
        nlri,
        rib_entries,
    })
}

/// Parse a single RIB entry for RIB_GENERIC.
///
/// The format is the same as for AFI-specific RIB entries (RFC 6396 Section 4.3.4).
fn parse_rib_generic_entry(
    input: &mut Bytes,
    is_add_path: bool,
    afi: &Afi,
    safi: &Safi,
    prefix: NetworkPrefix,
) -> Result<RibEntry, ParserError> {
    if input.remaining() < 8 {
        return Err(ParserError::TruncatedMsg("truncated msg".to_string()));
    }

    let peer_index = input.read_u16()?;
    let originated_time = input.read_u32()?;

    let path_id = match is_add_path {
        true => Some(input.read_u32()?),
        false => None,
    };

    let attribute_length = input.read_u16()? as usize;

    input.has_n_remaining(attribute_length)?;
    let attr_data_slice = input.split_to(attribute_length);
    let attributes = parse_attributes(
        attr_data_slice,
        &AsnLength::Bits32,
        is_add_path,
        Some(*afi),
        Some(*safi),
        Some(&[prefix]),
    )?;

    Ok(RibEntry {
        peer_index,
        originated_time,
        path_id,
        attributes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;

    #[test]
    fn test_parse_rib_generic_vpn_empty() {
        // Create a minimal RIB_GENERIC message with VPN NLRI
        let mut bytes = bytes::BytesMut::new();

        // Sequence number
        bytes.put_u32(1);

        // AFI (IPv4 = 1)
        bytes.put_u16(1);

        // SAFI (MplsVpn = 128)
        bytes.put_u8(128);

        // VPN NLRI: length + label + RD + prefix
        // For a /24 prefix: 24 (label) + 64 (RD) + 24 (prefix) = 112 bits
        bytes.put_u8(112); // Total bit length

        // MPLS label (3 bytes)
        bytes.put_u8(0x00);
        bytes.put_u8(0x00);
        bytes.put_u8(0x01);

        // Route Distinguisher (8 bytes) - Type 1: ASN:Value
        bytes.put_u16(0x0001); // Type 1 (ASN2:Value4)
        bytes.put_u16(65001); // ASN
        bytes.put_u32(100); // Value

        // Prefix (3 bytes for /24)
        bytes.put_u8(10);
        bytes.put_u8(0);
        bytes.put_u8(0);

        // Entry count
        bytes.put_u16(0);

        let mut data = bytes.freeze();
        let result = parse_rib_generic_entries(&mut data, false);

        assert!(result.is_ok());
        let entries = result.unwrap();
        assert_eq!(entries.sequence_number, 1);
        assert_eq!(entries.afi, Afi::Ipv4);
        assert_eq!(entries.safi, Safi::MplsVpn);
        assert!(entries.nlri.route_distinguisher.is_some());
        assert_eq!(entries.rib_entries.len(), 0);
    }
}
