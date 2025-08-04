mod geo_peer_table;
mod peer_index_table;
mod rib_afi_entries;

use crate::error::ParserError;
use crate::messages::table_dump_v2::geo_peer_table::parse_geo_peer_table;
use crate::messages::table_dump_v2::peer_index_table::parse_peer_index_table;
use crate::messages::table_dump_v2::rib_afi_entries::parse_rib_afi_entries;
use crate::models::*;
use bytes::Bytes;
use std::convert::TryFrom;

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
/// 7. GEO_PEER_TABLE
///
pub fn parse_table_dump_v2_message(
    sub_type: u16,
    mut input: Bytes,
) -> Result<TableDumpV2Message, ParserError> {
    let v2_type: TableDumpV2Type = TableDumpV2Type::try_from(sub_type)?;

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
            TableDumpV2Message::RibAfi(parse_rib_afi_entries(&mut input, v2_type)?)
        }
        TableDumpV2Type::RibGeneric | TableDumpV2Type::RibGenericAddPath => {
            return Err(ParserError::Unsupported(
                "TableDumpV2 RibGeneric is not currently supported".to_string(),
            ))
        }
        TableDumpV2Type::GeoPeerTable => {
            TableDumpV2Message::GeoPeerTable(parse_geo_peer_table(&mut input)?)
        }
    };

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsupported_type() {
        let msg = parse_table_dump_v2_message(7, Bytes::new());
        assert!(msg.is_err());
    }
}
