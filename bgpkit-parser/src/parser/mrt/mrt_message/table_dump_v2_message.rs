use crate::error::ParserError;
use crate::models::*;
use crate::parser::bgp::attributes::parse_attributes;
use crate::parser::ReadUtils;
use bytes::{Buf, Bytes};
use log::warn;
use num_traits::FromPrimitive;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// Parse TABLE_DUMP V2 format MRT message.
///
/// RFC: https://www.rfc-editor.org/rfc/rfc6396#section-4.3
///
/// Subtypes include
/// 1. PEER_INDEX_TABLE
/// 2. RIB_IPV4_UNICAST
/// 3. RIB_IPV4_MULTICAST
/// 4. RIB_IPV6_UNICAST
/// 5. RIB_IPV6_MULTICAST
/// 6. RIB_GENERIC
///
pub fn parse_table_dump_v2_message(
    sub_type: u16,
    mut input: Bytes,
) -> Result<TableDumpV2Message, ParserError> {
    let v2_type: TableDumpV2Type = match TableDumpV2Type::from_u16(sub_type) {
        Some(t) => t,
        None => {
            return Err(ParserError::ParseError(format!(
                "cannot parse table dump v2 type: {}",
                sub_type
            )))
        }
    };

    let msg: TableDumpV2Message = match v2_type {
        TableDumpV2Type::PeerIndexTable => {
            // peer index table type
            TableDumpV2Message::PeerIndexTable(parse_peer_index_table(&mut input)?)
        }
        TableDumpV2Type::RibIpv4Unicast
        | TableDumpV2Type::RibIpv4Multicast
        | TableDumpV2Type::RibIpv6Unicast
        | TableDumpV2Type::RibIpv6Multicast
        | TableDumpV2Type::RibIpv4UnicastAddPath
        | TableDumpV2Type::RibIpv4MulticastAddPath
        | TableDumpV2Type::RibIpv6UnicastAddPath
        | TableDumpV2Type::RibIpv6MulticastAddPath => {
            TableDumpV2Message::RibAfiEntries(parse_rib_afi_entries(&mut input, v2_type)?)
        }
        TableDumpV2Type::RibGeneric
        | TableDumpV2Type::RibGenericAddPath
        | TableDumpV2Type::GeoPeerTable => {
            return Err(ParserError::Unsupported(
                "TableDumpV2 RibGeneric and GeoPeerTable is not currently supported".to_string(),
            ))
        }
    };

    Ok(msg)
}

/// Peer index table
///
/// RFC: https://www.rfc-editor.org/rfc/rfc6396#section-4.3.1
pub fn parse_peer_index_table(data: &mut Bytes) -> Result<PeerIndexTable, ParserError> {
    let collector_bgp_id = Ipv4Addr::from(data.read_u32()?);
    // read and ignore view name
    let view_name_length = data.read_u16()?;
    let view_name =
        String::from_utf8(data.read_n_bytes(view_name_length as usize)?).unwrap_or("".to_string());

    let peer_count = data.read_u16()?;
    let mut peers = vec![];
    for _index in 0..peer_count {
        let peer_type = data.read_u8()?;
        let afi = match peer_type & 1 {
            1 => Afi::Ipv6,
            _ => Afi::Ipv4,
        };
        let asn_len = match peer_type & 2 {
            2 => AsnLength::Bits32,
            _ => AsnLength::Bits16,
        };

        let peer_bgp_id = Ipv4Addr::from(data.read_u32()?);
        let peer_address: IpAddr = data.read_address(&afi)?;
        let peer_asn = data.read_asn(&asn_len)?;
        peers.push(Peer {
            peer_type,
            peer_bgp_id,
            peer_address,
            peer_asn,
        })
    }

    let mut peers_map = HashMap::new();

    for (id, p) in peers.into_iter().enumerate() {
        peers_map.insert(id as u32, p);
    }

    Ok(PeerIndexTable {
        collector_bgp_id,
        view_name_length,
        view_name,
        peer_count,
        peers_map,
    })
}

/// RIB AFI-specific entries
///
/// https://tools.ietf.org/html/rfc6396#section-4.3
pub fn parse_rib_afi_entries(
    data: &mut Bytes,
    rib_type: TableDumpV2Type,
) -> Result<RibAfiEntries, ParserError> {
    let afi: Afi;
    let safi: Safi;
    match rib_type {
        TableDumpV2Type::RibIpv4Unicast | TableDumpV2Type::RibIpv4UnicastAddPath => {
            afi = Afi::Ipv4;
            safi = Safi::Unicast
        }
        TableDumpV2Type::RibIpv4Multicast | TableDumpV2Type::RibIpv4MulticastAddPath => {
            afi = Afi::Ipv4;
            safi = Safi::Multicast
        }
        TableDumpV2Type::RibIpv6Unicast | TableDumpV2Type::RibIpv6UnicastAddPath => {
            afi = Afi::Ipv6;
            safi = Safi::Unicast
        }
        TableDumpV2Type::RibIpv6Multicast | TableDumpV2Type::RibIpv6MulticastAddPath => {
            afi = Afi::Ipv6;
            safi = Safi::Multicast
        }
        _ => {
            return Err(ParserError::ParseError(format!(
                "wrong RIB type for parsing: {:?}",
                rib_type
            )))
        }
    };

    let add_path = matches!(
        rib_type,
        TableDumpV2Type::RibIpv4UnicastAddPath
            | TableDumpV2Type::RibIpv4MulticastAddPath
            | TableDumpV2Type::RibIpv6UnicastAddPath
            | TableDumpV2Type::RibIpv6MulticastAddPath
    );

    let sequence_number = data.read_u32()?;

    // NOTE: here we parse the prefix as only length and prefix, the path identifier for add_path
    //       entry is not handled here. We follow RFC6396 here https://www.rfc-editor.org/rfc/rfc6396.html#section-4.3.2
    let prefix = data.read_nlri_prefix(&afi, false)?;

    let entry_count = data.read_u16()?;
    let mut rib_entries = Vec::with_capacity((entry_count * 2) as usize);

    // get the u8 slice of the rest of the data
    // let attr_data_slice = &input.into_inner()[(input.position() as usize)..];

    for _i in 0..entry_count {
        let entry = match parse_rib_entry(data, add_path, &afi, &safi, prefix) {
            Ok(entry) => entry,
            Err(e) => {
                warn!("early break due to error {}", e.to_string());
                break;
            }
        };
        rib_entries.push(entry);
    }

    Ok(RibAfiEntries {
        rib_type,
        sequence_number,
        prefix,
        rib_entries,
    })
}

/// RIB entry: one prefix per entry
pub fn parse_rib_entry(
    input: &mut Bytes,
    add_path: bool,
    afi: &Afi,
    safi: &Safi,
    prefix: NetworkPrefix,
) -> Result<RibEntry, ParserError> {
    if input.remaining() < 8 {
        // total length - current position less than 16 --
        // meaning less than 16 bytes available to read
        return Err(ParserError::TruncatedMsg("truncated msg".to_string()));
    }

    let peer_index = input.read_u16()?;
    let originated_time = input.read_u32()?;
    if add_path {
        let _path_id = input.read_u32()?;
    }
    let attribute_length = input.read_u16()? as usize;

    if input.remaining() < attribute_length {
        return Err(ParserError::TruncatedMsg("truncated msg".to_string()));
    }

    let attr_data_slice = input.split_to(attribute_length);
    let attributes = parse_attributes(
        attr_data_slice,
        &AsnLength::Bits32,
        add_path,
        Some(*afi),
        Some(*safi),
        Some(&[prefix]),
    )?;

    Ok(RibEntry {
        peer_index,
        originated_time,
        attributes,
    })
}
