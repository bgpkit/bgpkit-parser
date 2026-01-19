mod geo_peer_table;
mod peer_index_table;
mod rib_afi_entries;
mod rib_generic_entries;

use crate::error::ParserError;
use crate::messages::table_dump_v2::geo_peer_table::parse_geo_peer_table;
use crate::messages::table_dump_v2::peer_index_table::parse_peer_index_table;
use crate::messages::table_dump_v2::rib_afi_entries::parse_rib_afi_entries;
use crate::messages::table_dump_v2::rib_generic_entries::parse_rib_generic_entries;
use crate::models::*;
#[cfg(test)]
use bytes::BufMut;
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
        TableDumpV2Type::RibGeneric => {
            TableDumpV2Message::RibGeneric(parse_rib_generic_entries(&mut input, false)?)
        }
        TableDumpV2Type::RibGenericAddPath => {
            TableDumpV2Message::RibGeneric(parse_rib_generic_entries(&mut input, true)?)
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
    fn test_rib_generic_vpn_parsing() {
        // Test RibGeneric (subtype 6) with VPN NLRI
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

        // Route Distinguisher (8 bytes)
        bytes.put_u64(0x0001FDE900000064); // Type 1: ASN 65001, Value 100

        // Prefix (3 bytes for /24)
        bytes.put_u8(10);
        bytes.put_u8(0);
        bytes.put_u8(0);

        // Entry count
        bytes.put_u16(0);

        let bytes = bytes.freeze();
        let result = parse_table_dump_v2_message(6, bytes);
        assert!(result.is_ok());

        if let Ok(TableDumpV2Message::RibGeneric(entries)) = result {
            assert_eq!(entries.sequence_number, 1);
            assert_eq!(entries.afi, Afi::Ipv4);
            assert_eq!(entries.safi, Safi::MplsVpn);
            assert!(entries.nlri.route_distinguisher.is_some());
        } else {
            panic!("Expected RibGeneric message");
        }
    }

    #[test]
    fn test_rib_generic_truncated() {
        // Test RibGeneric with truncated data - should fail
        let msg = parse_table_dump_v2_message(6, Bytes::new());
        assert!(msg.is_err());
    }

    #[test]
    fn test_geo_peer_table_parsing() {
        // Test GeoPeerTable (subtype 7) parsing path
        // Create minimal valid GeoPeerTable bytes
        let mut bytes = bytes::BytesMut::new();

        // Collector BGP ID (4 bytes)
        bytes.put_u32(0x01020304);

        // View name length (2 bytes) and name (0 bytes for empty string)
        bytes.put_u16(0);

        // Collector coordinates (8 bytes)
        bytes.put_f32(0.0); // latitude
        bytes.put_f32(0.0); // longitude

        // Peer count (2 bytes) - 0 peers
        bytes.put_u16(0);

        let bytes = bytes.freeze();
        let result = parse_table_dump_v2_message(7, bytes);
        assert!(result.is_ok());

        if let Ok(TableDumpV2Message::GeoPeerTable(geo_table)) = result {
            assert_eq!(geo_table.view_name, "");
            assert_eq!(geo_table.geo_peers.len(), 0);
        } else {
            panic!("Expected GeoPeerTable message");
        }
    }
}
