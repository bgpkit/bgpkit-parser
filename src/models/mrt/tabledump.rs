//! MRT table dump version 1 and 2 structs
use crate::models::*;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// TableDump message version 1
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TableDumpMessage {
    pub view_number: u16,
    pub sequence_number: u16,
    pub prefix: NetworkPrefix,
    pub status: u8,
    pub originated_time: u64,
    pub peer_address: IpAddr,
    pub peer_asn: Asn,
    pub attributes: Vec<Attribute>,
}

/// TableDump message version 2 enum
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TableDumpV2Message {
    PeerIndexTable(PeerIndexTable),
    RibAfiEntries(RibAfiEntries),
    RibGenericEntries(RibGenericEntries),
}

/// TableDump version 2 subtypes.
///
/// <https://www.iana.org/assignments/mrt/mrt.xhtml#subtype-codes>
#[derive(Debug, Primitive, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    pub attributes: Vec<Attribute>,
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
    pub collector_bgp_id: Ipv4Addr,
    pub view_name_length: u16,
    pub view_name: String,
    pub peer_count: u16,
    pub peers_map: HashMap<u32, Peer>,
}

/// Peer struct.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Peer {
    pub peer_type: u8,
    pub peer_bgp_id: Ipv4Addr,
    pub peer_address: IpAddr,
    pub peer_asn: Asn,
}
