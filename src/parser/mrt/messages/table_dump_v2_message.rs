use crate::error::ParserError;
use crate::models::*;
use crate::parser::{AttributeParser, ReadUtils};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr};

/// Parse TABLE_DUMP V2 format MRT message.
///
/// RFC: <https://www.rfc-editor.org/rfc/rfc6396#section-4.3>
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
    mut input: &[u8],
) -> Result<TableDumpV2Message, ParserError> {
    let v2_type: TableDumpV2Type = TableDumpV2Type::try_from(sub_type)?;

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
            TableDumpV2Message::RibAfi(parse_rib_afi_entries(&mut input, v2_type)?)
        }
        TableDumpV2Type::RibGeneric
        | TableDumpV2Type::RibGenericAddPath
        | TableDumpV2Type::GeoPeerTable => {
            return Err(ParserError::UnsupportedMrtType {
                mrt_type: EntryType::TABLE_DUMP_V2,
                subtype: sub_type,
            });
        }
    };

    Ok(msg)
}

/// Peer index table
///
/// RFC: https://www.rfc-editor.org/rfc/rfc6396#section-4.3.1
pub fn parse_peer_index_table(mut data: &[u8]) -> Result<PeerIndexTable, ParserError> {
    let collector_bgp_id = data.read_ipv4_address()?;
    // read and ignore view name
    let view_name_length = data.read_u16()?;
    let view_name =
        String::from_utf8(data.read_n_bytes(view_name_length as usize)?).unwrap_or("".to_string());

    let peer_count = data.read_u16()?;
    let mut peers = vec![];
    for _index in 0..peer_count {
        let peer_type = PeerType::from_bits_retain(data.read_u8()?);
        let afi = match peer_type.contains(PeerType::ADDRESS_FAMILY_IPV6) {
            true => Afi::Ipv6,
            false => Afi::Ipv4,
        };
        let asn_len = match peer_type.contains(PeerType::AS_SIZE_32BIT) {
            true => AsnLength::Bits32,
            false => AsnLength::Bits16,
        };

        let peer_bgp_id = Ipv4Addr::from(data.read_u32()?);
        let peer_address: IpAddr = data.read_address(&afi)?;
        let peer_asn = data.read_asn(asn_len)?;
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
    data: &mut &[u8],
    rib_type: TableDumpV2Type,
) -> Result<RibAfiEntries, ParserError> {
    let (afi, safi) = match rib_type {
        TableDumpV2Type::RibIpv4Unicast | TableDumpV2Type::RibIpv4UnicastAddPath => {
            (Afi::Ipv4, Safi::Unicast)
        }
        TableDumpV2Type::RibIpv4Multicast | TableDumpV2Type::RibIpv4MulticastAddPath => {
            (Afi::Ipv4, Safi::Multicast)
        }
        TableDumpV2Type::RibIpv6Unicast | TableDumpV2Type::RibIpv6UnicastAddPath => {
            (Afi::Ipv6, Safi::Unicast)
        }
        TableDumpV2Type::RibIpv6Multicast | TableDumpV2Type::RibIpv6MulticastAddPath => {
            (Afi::Ipv6, Safi::Multicast)
        }
        ty => panic!(
            "Invalid TableDumpV2Type {:?} passed to parse_rib_afi_entries",
            ty
        ),
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
        rib_entries.push(parse_rib_entry(
            data,
            add_path,
            &afi,
            &safi,
            std::slice::from_ref(&prefix),
        )?);
    }

    Ok(RibAfiEntries {
        rib_type,
        sequence_number,
        prefix,
        rib_entries,
    })
}

pub fn parse_rib_entry(
    input: &mut &[u8],
    add_path: bool,
    afi: &Afi,
    safi: &Safi,
    prefixes: &[NetworkPrefix],
) -> Result<RibEntry, ParserError> {
    // total length - current position less than 16 --
    // meaning less than 16 bytes available to read
    input.require_n_remaining(8, "rib entry")?;

    let peer_index = input.read_u16()?;
    let originated_time = input.read_u32()?;
    if add_path {
        // TODO: Why is this value unused?
        let _path_id = input.read_u32()?;
    }
    let attribute_length = input.read_u16()? as usize;

    input.require_n_remaining(attribute_length, "rib entry attributes")?;

    let attr_parser = AttributeParser::new(add_path);

    let attr_data_slice = input.split_to(attribute_length)?;
    let attributes = attr_parser.parse_attributes(
        attr_data_slice,
        &AsnLength::Bits32,
        Some(*afi),
        Some(*safi),
        Some(prefixes),
    )?;

    Ok(RibEntry {
        peer_index,
        originated_time,
        attributes,
    })
}
