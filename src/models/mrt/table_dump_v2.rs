//! MRT table dump version 2 structs
use crate::models::*;
use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// TableDump message version 2 enum
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TableDumpV2Message {
    PeerIndexTable(PeerIndexTable),
    RibAfi(RibAfiEntries),
    /// Currently unsupported
    RibGeneric(RibGenericEntries),
}

impl TableDumpV2Message {
    pub const fn dump_type(&self) -> TableDumpV2Type {
        match self {
            TableDumpV2Message::PeerIndexTable(_) => TableDumpV2Type::PeerIndexTable,
            TableDumpV2Message::RibAfi(x) => x.rib_type,
            TableDumpV2Message::RibGeneric(_) => TableDumpV2Type::RibGeneric,
        }
    }
}

/// TableDump version 2 subtypes.
///
/// <https://www.iana.org/assignments/mrt/mrt.xhtml#subtype-codes>
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum TableDumpV2Type {
    PeerIndexTable = 1,
    RibIpv4Unicast = 2,
    RibIpv4Multicast = 3,
    RibIpv6Unicast = 4,
    RibIpv6Multicast = 5,
    RibGeneric = 6,
    GeoPeerTable = 7,
    RibIpv4UnicastAddPath = 8,
    RibIpv4MulticastAddPath = 9,
    RibIpv6UnicastAddPath = 10,
    RibIpv6MulticastAddPath = 11,
    RibGenericAddPath = 12,
}

/// AFI/SAFI-Specific RIB Subtypes.
///
/// ```text
///    The AFI/SAFI-specific RIB Subtypes consist of the RIB_IPV4_UNICAST,
///    RIB_IPV4_MULTICAST, RIB_IPV6_UNICAST, and RIB_IPV6_MULTICAST
///    Subtypes.  These specific RIB table entries are given their own MRT
///    TABLE_DUMP_V2 subtypes as they are the most common type of RIB table
///    instances, and providing specific MRT subtypes for them permits more
///    compact encodings.  These subtypes permit a single MRT record to
///    encode multiple RIB table entries for a single prefix.  The Prefix
///    Length and Prefix fields are encoded in the same manner as the BGP
///    NLRI encoding for IPv4 and IPv6 prefixes.  Namely, the Prefix field
///    contains address prefixes followed by enough trailing bits to make
///    the end of the field fall on an octet boundary.  The value of
///    trailing bits is irrelevant.
///
///         0                   1                   2                   3
///         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                         Sequence Number                       |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        | Prefix Length |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                        Prefix (variable)                      |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |         Entry Count           |  RIB Entries (variable)
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RibAfiEntries {
    pub rib_type: TableDumpV2Type,
    pub sequence_number: u32,
    pub prefix: NetworkPrefix,
    pub rib_entries: Vec<RibEntry>,
}

/// RIB generic entries subtype.
///
/// ```text
/// The RIB_GENERIC header is shown below.  It is used to cover RIB
/// entries that do not fall under the common case entries defined above.
/// It consists of an AFI, Subsequent AFI (SAFI), and a single NLRI
/// entry.  The NLRI information is specific to the AFI and SAFI values.
/// An implementation that does not recognize particular AFI and SAFI
/// values SHOULD discard the remainder of the MRT record.
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RibGenericEntries {
    pub sequence_number: u32,
    pub afi: Afi,
    pub safi: Safi,
    pub nlri: NetworkPrefix,
    pub rib_entries: Vec<RibEntry>,
}

/// RIB entry.
///
/// ```text
///    The RIB Entries are repeated Entry Count times.  These entries share
///    a common format as shown below.  They include a Peer Index from the
///    PEER_INDEX_TABLE MRT record, an originated time for the RIB Entry,
///    and the BGP path attribute length and attributes.  All AS numbers in
///    the AS_PATH attribute MUST be encoded as 4-byte AS numbers.
///
///         0                   1                   2                   3
///         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |         Peer Index            |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                         Originated Time                       |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |      Attribute Length         |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                    BGP Attributes... (variable)
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RibEntry {
    pub peer_index: u16,
    pub originated_time: u32,
    pub attributes: Attributes,
}

/// peer index table.
///
/// ```text
///    An initial PEER_INDEX_TABLE MRT record provides the BGP ID of the
///    collector, an OPTIONAL view name, and a list of indexed peers.
///    Following the PEER_INDEX_TABLE MRT record, a series of MRT records is
///    used to encode RIB table entries.  This series of MRT records uses
///    subtypes 2-6 and is separate from the PEER_INDEX_TABLE MRT record
///    itself and includes full MRT record headers.  The RIB entry MRT
///    records MUST immediately follow the PEER_INDEX_TABLE MRT record.
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeerIndexTable {
    pub collector_bgp_id: BgpIdentifier,
    pub view_name: String,
    pub id_peer_map: HashMap<u16, Peer>,
    pub peer_addr_id_map: HashMap<IpAddr, u16>,
}

impl Default for PeerIndexTable {
    fn default() -> Self {
        PeerIndexTable {
            collector_bgp_id: Ipv4Addr::from_str("0.0.0.0").unwrap(),
            view_name: "".to_string(),
            id_peer_map: HashMap::new(),
            peer_addr_id_map: HashMap::new(),
        }
    }
}

bitflags! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PeerType: u8 {
        const AS_SIZE_32BIT = 0x2;
        const ADDRESS_FAMILY_IPV6 = 0x1;
    }
}

/// Peer struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Peer {
    pub peer_type: PeerType,
    pub peer_bgp_id: BgpIdentifier,
    pub peer_address: IpAddr,
    pub peer_asn: Asn,
}

impl Peer {
    pub fn new(peer_bgp_id: BgpIdentifier, peer_address: IpAddr, peer_asn: Asn) -> Self {
        let mut peer_type = PeerType::empty();

        if peer_asn.is_four_byte() {
            peer_type.insert(PeerType::AS_SIZE_32BIT);
        }

        if peer_address.is_ipv6() {
            peer_type.insert(PeerType::ADDRESS_FAMILY_IPV6);
        }

        Peer {
            peer_type,
            peer_bgp_id,
            peer_address,
            peer_asn,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Create a helper function to initialize Peer structure
    fn create_peer() -> Peer {
        let bgp_id = Ipv4Addr::from_str("1.1.1.1").unwrap();
        let peer_address: IpAddr = Ipv4Addr::from_str("2.2.2.2").unwrap().into();
        // Assuming Asn::new(u32) is defined.
        let asn = Asn::new_32bit(65000);
        Peer::new(bgp_id, peer_address, asn)
    }

    #[test]
    fn test_peer_new() {
        let peer = create_peer();
        assert_eq!(peer.peer_type, PeerType::AS_SIZE_32BIT);
        assert_eq!(peer.peer_bgp_id, Ipv4Addr::from_str("1.1.1.1").unwrap());
        assert_eq!(
            peer.peer_address,
            IpAddr::V4(Ipv4Addr::from_str("2.2.2.2").unwrap())
        );
        assert_eq!(peer.peer_asn, Asn::new_32bit(65000));
    }

    #[test]
    fn test_default_peer_index_table() {
        let peer_index_table = PeerIndexTable::default();
        assert_eq!(
            peer_index_table.collector_bgp_id,
            Ipv4Addr::from_str("0.0.0.0").unwrap()
        );
        assert_eq!(peer_index_table.view_name, "".to_string());
        assert_eq!(peer_index_table.id_peer_map, HashMap::new());
        assert_eq!(peer_index_table.peer_addr_id_map, HashMap::new());
    }

    #[test]
    fn test_peer_type_flags() {
        let mut peer_type = PeerType::empty();
        assert_eq!(peer_type, PeerType::empty());

        peer_type.insert(PeerType::AS_SIZE_32BIT);
        assert_eq!(peer_type, PeerType::AS_SIZE_32BIT);

        peer_type.insert(PeerType::ADDRESS_FAMILY_IPV6);
        assert_eq!(
            peer_type,
            PeerType::AS_SIZE_32BIT | PeerType::ADDRESS_FAMILY_IPV6
        );

        peer_type.remove(PeerType::AS_SIZE_32BIT);
        assert_eq!(peer_type, PeerType::ADDRESS_FAMILY_IPV6);

        peer_type.remove(PeerType::ADDRESS_FAMILY_IPV6);
        assert_eq!(peer_type, PeerType::empty());
    }

    #[test]
    fn test_dump_type() {
        let peer_index_table = TableDumpV2Message::PeerIndexTable(PeerIndexTable::default());
        assert_eq!(
            peer_index_table.dump_type(),
            TableDumpV2Type::PeerIndexTable
        );

        let rib_afi = TableDumpV2Message::RibAfi(RibAfiEntries {
            rib_type: TableDumpV2Type::RibIpv4Unicast,
            sequence_number: 1,
            prefix: NetworkPrefix::from_str("10.0.0.0/24").unwrap(),
            rib_entries: vec![],
        });
        assert_eq!(rib_afi.dump_type(), TableDumpV2Type::RibIpv4Unicast);

        let rib_generic = TableDumpV2Message::RibGeneric(RibGenericEntries {
            sequence_number: 1,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            nlri: NetworkPrefix::from_str("10.0.0.0/24").unwrap(),
            rib_entries: vec![],
        });
        assert_eq!(rib_generic.dump_type(), TableDumpV2Type::RibGeneric);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serialization() {
        let peer_index_table = TableDumpV2Message::PeerIndexTable(PeerIndexTable::default());
        let serialized = serde_json::to_string(&peer_index_table).unwrap();
        let deserialized: TableDumpV2Message = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, peer_index_table);

        let rib_entry = RibEntry {
            peer_index: 1,
            originated_time: 1,
            attributes: Attributes::default(),
        };
        let rib_afi = TableDumpV2Message::RibAfi(RibAfiEntries {
            rib_type: TableDumpV2Type::RibIpv4Unicast,
            sequence_number: 1,
            prefix: NetworkPrefix::from_str("10.0.0.0/24").unwrap(),
            rib_entries: vec![rib_entry],
        });
        let serialized = serde_json::to_string(&rib_afi).unwrap();
        let deserialized: TableDumpV2Message = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, rib_afi);

        let rib_generic = TableDumpV2Message::RibGeneric(RibGenericEntries {
            sequence_number: 1,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            nlri: NetworkPrefix::from_str("10.0.0.0/24").unwrap(),
            rib_entries: vec![],
        });
        let serialized = serde_json::to_string(&rib_generic).unwrap();
        let deserialized: TableDumpV2Message = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, rib_generic);
    }
}
