use std::collections::HashMap;
use crate::error::ParserError;
use std::net::{IpAddr, Ipv4Addr};
use bgp_models::mrt::tabledump::{Peer, PeerIndexTable, RibAfiEntries, RibEntry, TableDumpV2Message, TableDumpV2Type};
use bgp_models::network::*;
use log::warn;
use num_traits::FromPrimitive;
use crate::parser::{AttributeParser, DataBytes};

pub fn parse_table_dump_v2_message(
    sub_type: u16,
    input: &mut DataBytes) -> Result<TableDumpV2Message, ParserError> {

    let v2_type: TableDumpV2Type = match TableDumpV2Type::from_u16(sub_type) {
        Some(t) => t,
        None => {return Err(ParserError::ParseError(format!("cannot parse table dump v2 type: {}", sub_type)))}
    };

    let msg: TableDumpV2Message = match v2_type {
        TableDumpV2Type:: PeerIndexTable => {
            TableDumpV2Message::PeerIndexTable (parse_peer_index_table(input)?)
        },
        TableDumpV2Type:: RibIpv4Unicast|TableDumpV2Type::RibIpv4Multicast|
        TableDumpV2Type:: RibIpv6Unicast|TableDumpV2Type::RibIpv6Multicast |
        TableDumpV2Type::RibIpv4UnicastAddPath | TableDumpV2Type::RibIpv4MulticastAddPath |
        TableDumpV2Type::RibIpv6UnicastAddPath | TableDumpV2Type::RibIpv6MulticastAddPath => {
            TableDumpV2Message::RibAfiEntries(parse_rib_afi_entries(input, v2_type)?)
        },
        TableDumpV2Type::RibGeneric| TableDumpV2Type::RibGenericAddPath| TableDumpV2Type::GeoPeerTable => {
            return Err(ParserError::Unsupported("TableDumpV2 RibGeneric and GeoPeerTable is not currently supported".to_string()))
        }
    };

    Ok(msg)
}

/// Peer index table
///
/// https://tools.ietf.org/html/rfc6396#section-4.3
pub fn parse_peer_index_table(input: &mut DataBytes) -> Result<PeerIndexTable, ParserError> {
    let collector_bgp_id = Ipv4Addr::from(input.read_32b()?);
    // read and ignore view name
    let view_name_length = input.read_16b()?;
    // TODO: properly parse view_name
    input.read_and_drop_n_bytes(view_name_length as usize)?;

    let peer_count = input.read_16b()?;
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
        peers.push(Peer{
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

    Ok(
        PeerIndexTable{
            collector_bgp_id,
            view_name_length,
            view_name: "".to_owned(),
            peer_count,
            peers_map,
        }
    )
}

/// RIB AFI-specific entries
///
/// https://tools.ietf.org/html/rfc6396#section-4.3
pub fn parse_rib_afi_entries(input: &mut DataBytes, rib_type: TableDumpV2Type) -> Result<RibAfiEntries, ParserError> {
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
            return Err(ParserError::ParseError(format!("wrong RIB type for parsing: {:?}", rib_type)))
        }
    };

    let add_path = matches!(rib_type, TableDumpV2Type::RibIpv4UnicastAddPath | TableDumpV2Type::RibIpv4MulticastAddPath |
        TableDumpV2Type::RibIpv6UnicastAddPath | TableDumpV2Type::RibIpv6MulticastAddPath);

    let sequence_number = input.read_32b()?;

    // NOTE: here we parse the prefix as only length and prefix, the path identifier for add_path
    //       entry is not handled here. We follow RFC6396 here https://www.rfc-editor.org/rfc/rfc6396.html#section-4.3.2
    let prefix = input.read_nlri_prefix(&afi, false)?;
    let prefixes = vec!(prefix);

    let entry_count = input.read_16b()?;
    let mut rib_entries = Vec::with_capacity((entry_count*2) as usize);

    for _i in 0..entry_count {
        let entry = match parse_rib_entry(input, add_path, &afi, &safi, &prefixes) {
            Ok(entry) => entry,
            Err(e) => {
                warn!("early break due to error {}", e.to_string());
                break;
            }
        };
        rib_entries.push(entry);
    }

    Ok(
        RibAfiEntries{
            rib_type,
            sequence_number,
            prefix,
            rib_entries
        }
    )
}

pub fn parse_rib_entry(input: &mut DataBytes, add_path: bool, afi: &Afi, safi: &Safi, prefixes: &[NetworkPrefix]) -> Result<RibEntry, ParserError> {
    if input.bytes_left() < 16 {
        return Err(ParserError::TruncatedMsg("truncated msg".to_string()))
    }
    let peer_index = input.read_16b()?;
    let originated_time = input.read_32b()?;
    if add_path {
        let _path_id = input.read_32b()?;
    }
    let attribute_length = input.read_16b()? as usize;

    if input.bytes_left() < attribute_length  {
        return Err(ParserError::TruncatedMsg("truncated msg".to_string()))
    }

    let attr_parser = AttributeParser::new(add_path);

    let attributes = attr_parser.parse_attributes(input, &AsnLength::Bits32, Some(*afi), Some(*safi), Some(prefixes), attribute_length)?;

    Ok(
        RibEntry{
            peer_index,
            originated_time,
            attributes
        }
    )
}
