use crate::error::ParserError;
use crate::parser::{AttributeParser, ReadUtils};
use bgp_models::prelude::*;
use byteorder::{ReadBytesExt, BE};
use log::warn;
use num_traits::FromPrimitive;
use std::collections::HashMap;
use std::io::{Cursor, Seek, SeekFrom};
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
    input: &[u8],
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
            TableDumpV2Message::PeerIndexTable(parse_peer_index_table(input)?)
        }
        TableDumpV2Type::RibIpv4Unicast
        | TableDumpV2Type::RibIpv4Multicast
        | TableDumpV2Type::RibIpv6Unicast
        | TableDumpV2Type::RibIpv6Multicast
        | TableDumpV2Type::RibIpv4UnicastAddPath
        | TableDumpV2Type::RibIpv4MulticastAddPath
        | TableDumpV2Type::RibIpv6UnicastAddPath
        | TableDumpV2Type::RibIpv6MulticastAddPath => {
            TableDumpV2Message::RibAfiEntries(parse_rib_afi_entries(input, v2_type)?)
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
pub fn parse_peer_index_table(data: &[u8]) -> Result<PeerIndexTable, ParserError> {
    let mut input = Cursor::new(data);

    let collector_bgp_id = Ipv4Addr::from(input.read_32b()?);
    // read and ignore view name
    let view_name_length = input.read_u16::<BE>()?;
    // TODO: properly parse view_name
    input.seek(SeekFrom::Current(view_name_length as i64))?;

    let peer_count = input.read_u16::<BE>()?;
    let mut peers = vec![];
    for _index in 0..peer_count {
        let peer_type = input.read_8b()?;
        let afi = match peer_type & 1 {
            1 => Afi::Ipv6,
            _ => Afi::Ipv4,
        };
        let asn_len = match peer_type & 2 {
            2 => AsnLength::Bits32,
            _ => AsnLength::Bits16,
        };

        let peer_bgp_id = Ipv4Addr::from(input.read_32b()?);
        let peer_address: IpAddr = input.read_address(&afi)?;
        let peer_asn = input.read_asn(&asn_len)?;
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
        view_name: "".to_owned(),
        peer_count,
        peers_map,
    })
}

/// RIB AFI-specific entries
///
/// https://tools.ietf.org/html/rfc6396#section-4.3
pub fn parse_rib_afi_entries(
    data: &[u8],
    rib_type: TableDumpV2Type,
) -> Result<RibAfiEntries, ParserError> {
    let mut input = Cursor::new(data);

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

    let sequence_number = input.read_32b()?;

    // NOTE: here we parse the prefix as only length and prefix, the path identifier for add_path
    //       entry is not handled here. We follow RFC6396 here https://www.rfc-editor.org/rfc/rfc6396.html#section-4.3.2
    let prefix = input.read_nlri_prefix(&afi, false)?;
    let prefixes = vec![prefix];

    let entry_count = input.read_u16::<BE>()?;
    let mut rib_entries = Vec::with_capacity((entry_count * 2) as usize);

    // get the u8 slice of the rest of the data
    // let attr_data_slice = &input.into_inner()[(input.position() as usize)..];

    for _i in 0..entry_count {
        let entry = match parse_rib_entry(&mut input, add_path, &afi, &safi, &prefixes) {
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

pub fn parse_rib_entry(
    input: &mut Cursor<&[u8]>,
    add_path: bool,
    afi: &Afi,
    safi: &Safi,
    prefixes: &[NetworkPrefix],
) -> Result<RibEntry, ParserError> {
    // TODO: fix the implementation here
    let mut total_bytes_left = input.get_ref().len() - (input.position() as usize);
    if total_bytes_left < 8 {
        // total length - current position less than 16 --
        // meaning less than 16 bytes available to read
        return Err(ParserError::TruncatedMsg("truncated msg".to_string()));
    }

    let peer_index = input.read_u16::<BE>()?;
    let originated_time = input.read_32b()?;
    total_bytes_left -= 6;
    if add_path {
        let _path_id = input.read_32b()?;
        total_bytes_left -= 4;
    }
    let attribute_length = input.read_u16::<BE>()? as usize;
    total_bytes_left -= 2;

    // TODO: fix the implementation here
    if total_bytes_left < attribute_length {
        return Err(ParserError::TruncatedMsg("truncated msg".to_string()));
    }

    let attr_parser = AttributeParser::new(add_path);

    let pos = input.position() as usize;
    let pos_end = pos + attribute_length;
    let attr_data_slice = &input.get_ref()[pos..pos_end];
    let attributes = attr_parser.parse_attributes(
        attr_data_slice,
        &AsnLength::Bits32,
        Some(*afi),
        Some(*safi),
        Some(prefixes),
    )?;
    input.seek(SeekFrom::Start(pos_end as u64))?;

    Ok(RibEntry {
        peer_index,
        originated_time,
        attributes,
    })
}
