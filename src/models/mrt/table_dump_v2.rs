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
    /// RFC 6397: Geo-location peer table
    GeoPeerTable(GeoPeerTable),
}

impl TableDumpV2Message {
    pub const fn dump_type(&self) -> TableDumpV2Type {
        match self {
            TableDumpV2Message::PeerIndexTable(_) => TableDumpV2Type::PeerIndexTable,
            TableDumpV2Message::RibAfi(x) => x.rib_type,
            TableDumpV2Message::RibGeneric(_) => TableDumpV2Type::RibGeneric,
            TableDumpV2Message::GeoPeerTable(_) => TableDumpV2Type::GeoPeerTable,
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
///        |                         Optional Path ID                      |
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
    pub path_id: Option<u32>,
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
    pub peer_ip_id_map: HashMap<IpAddr, u16>,
}

impl Default for PeerIndexTable {
    fn default() -> Self {
        PeerIndexTable {
            collector_bgp_id: Ipv4Addr::from_str("0.0.0.0").unwrap(),
            view_name: "".to_string(),
            id_peer_map: HashMap::new(),
            peer_ip_id_map: HashMap::new(),
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

/// Geo-location peer entry - RFC 6397
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GeoPeer {
    pub peer: Peer,
    pub peer_latitude: f32,
    pub peer_longitude: f32,
}

impl GeoPeer {
    pub fn new(peer: Peer, latitude: f32, longitude: f32) -> Self {
        Self {
            peer,
            peer_latitude: latitude,
            peer_longitude: longitude,
        }
    }
}

impl Eq for GeoPeer {}

/// RFC 6397: Geo-location peer table
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GeoPeerTable {
    pub collector_bgp_id: BgpIdentifier,
    pub view_name: String,
    pub collector_latitude: f32,
    pub collector_longitude: f32,
    pub geo_peers: Vec<GeoPeer>,
}

impl GeoPeerTable {
    pub fn new(
        collector_bgp_id: BgpIdentifier,
        view_name: String,
        collector_latitude: f32,
        collector_longitude: f32,
    ) -> Self {
        Self {
            collector_bgp_id,
            view_name,
            collector_latitude,
            collector_longitude,
            geo_peers: Vec::new(),
        }
    }

    pub fn add_geo_peer(&mut self, geo_peer: GeoPeer) {
        self.geo_peers.push(geo_peer);
    }

    /// Encode the GEO_PEER_TABLE into bytes according to RFC 6397
    ///
    /// # Returns
    ///
    /// A `Bytes` object containing the encoded GEO_PEER_TABLE data.
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use std::str::FromStr;
    /// use bgpkit_parser::models::{GeoPeerTable, GeoPeer, Peer, Asn};
    ///
    /// let mut geo_table = GeoPeerTable::new(
    ///     Ipv4Addr::from_str("10.0.0.1").unwrap(),
    ///     "test-view".to_string(),
    ///     51.5074,  // London latitude
    ///     -0.1278,  // London longitude
    /// );
    ///
    /// let encoded = geo_table.encode();
    /// ```
    pub fn encode(&self) -> bytes::Bytes {
        use bytes::{BufMut, BytesMut};

        let mut buf = BytesMut::new();

        // Encode collector BGP ID (4 bytes)
        buf.put_u32(self.collector_bgp_id.into());

        // Encode view name length and view name
        let view_name_bytes = self.view_name.as_bytes();
        buf.put_u16(view_name_bytes.len() as u16);
        buf.extend(view_name_bytes);

        // Encode collector coordinates (4 bytes each, 32-bit float)
        buf.put_f32(self.collector_latitude);
        buf.put_f32(self.collector_longitude);

        // Encode peer count
        buf.put_u16(self.geo_peers.len() as u16);

        // Encode each peer entry
        for geo_peer in &self.geo_peers {
            // Encode peer type (1 byte)
            buf.put_u8(geo_peer.peer.peer_type.bits());

            // Encode peer BGP ID (4 bytes)
            buf.put_u32(geo_peer.peer.peer_bgp_id.into());

            // Encode peer IP address (4 or 16 bytes depending on address family)
            match geo_peer.peer.peer_ip {
                std::net::IpAddr::V4(ipv4) => {
                    buf.put_u32(ipv4.into());
                }
                std::net::IpAddr::V6(ipv6) => {
                    buf.extend_from_slice(&ipv6.octets());
                }
            }

            // Encode peer AS number (2 or 4 bytes depending on AS size)
            if geo_peer
                .peer
                .peer_type
                .contains(crate::models::PeerType::AS_SIZE_32BIT)
            {
                buf.put_u32(u32::from(geo_peer.peer.peer_asn));
            } else {
                buf.put_u16(u16::from(geo_peer.peer.peer_asn));
            }

            // Encode peer coordinates (4 bytes each, 32-bit float)
            buf.put_f32(geo_peer.peer_latitude);
            buf.put_f32(geo_peer.peer_longitude);
        }

        buf.freeze()
    }
}

impl Eq for GeoPeerTable {}

/// Peer struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Peer {
    pub peer_type: PeerType,
    pub peer_bgp_id: BgpIdentifier,
    pub peer_ip: IpAddr,
    pub peer_asn: Asn,
}

impl Peer {
    pub fn new(peer_bgp_id: BgpIdentifier, peer_ip: IpAddr, peer_asn: Asn) -> Self {
        let mut peer_type = PeerType::empty();

        if peer_asn.is_four_byte() {
            peer_type.insert(PeerType::AS_SIZE_32BIT);
        }

        if peer_ip.is_ipv6() {
            peer_type.insert(PeerType::ADDRESS_FAMILY_IPV6);
        }

        Peer {
            peer_type,
            peer_bgp_id,
            peer_ip,
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
        let peer_ip: IpAddr = Ipv4Addr::from_str("2.2.2.2").unwrap().into();
        // Assuming Asn::new(u32) is defined.
        let asn = Asn::new_32bit(65000);
        Peer::new(bgp_id, peer_ip, asn)
    }

    #[test]
    fn test_peer_new() {
        let peer = create_peer();
        assert_eq!(peer.peer_type, PeerType::AS_SIZE_32BIT);
        assert_eq!(peer.peer_bgp_id, Ipv4Addr::from_str("1.1.1.1").unwrap());
        assert_eq!(
            peer.peer_ip,
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
        assert_eq!(peer_index_table.peer_ip_id_map, HashMap::new());
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
            path_id: None,
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

    #[test]
    fn test_geo_peer() {
        let peer = create_peer();
        let geo_peer = GeoPeer::new(peer, 40.7128, -74.0060);

        assert_eq!(geo_peer.peer, peer);
        assert_eq!(geo_peer.peer_latitude, 40.7128);
        assert_eq!(geo_peer.peer_longitude, -74.0060);

        // Test with NaN coordinates
        let private_geo_peer = GeoPeer::new(peer, f32::NAN, f32::NAN);
        assert!(private_geo_peer.peer_latitude.is_nan());
        assert!(private_geo_peer.peer_longitude.is_nan());
    }

    #[test]
    fn test_geo_peer_table() {
        let collector_bgp_id = Ipv4Addr::from_str("10.0.0.1").unwrap();
        let mut geo_table = GeoPeerTable::new(
            collector_bgp_id,
            "test-view".to_string(),
            51.5074, // London latitude
            -0.1278, // London longitude
        );

        assert!(!geo_table.collector_latitude.is_nan());
        assert!(!geo_table.collector_longitude.is_nan());
        assert_eq!(geo_table.collector_latitude, 51.5074);
        assert_eq!(geo_table.collector_longitude, -0.1278);

        // Add a peer with valid location
        let peer1 = create_peer();
        let geo_peer1 = GeoPeer::new(peer1, 40.7128, -74.0060); // New York
        geo_table.add_geo_peer(geo_peer1);

        // Add a peer with private location (NaN)
        let peer2 = Peer::new(
            Ipv4Addr::from_str("2.2.2.2").unwrap(),
            Ipv4Addr::from_str("3.3.3.3").unwrap().into(),
            Asn::new_32bit(65001),
        );
        let geo_peer2 = GeoPeer::new(peer2, f32::NAN, f32::NAN);
        geo_table.add_geo_peer(geo_peer2);

        assert_eq!(geo_table.geo_peers.len(), 2);

        // Check that first peer has valid location, second doesn't
        assert!(!geo_table.geo_peers[0].peer_latitude.is_nan());
        assert!(!geo_table.geo_peers[0].peer_longitude.is_nan());
        assert!(geo_table.geo_peers[1].peer_latitude.is_nan());
        assert!(geo_table.geo_peers[1].peer_longitude.is_nan());

        // Test with private collector location
        let private_geo_table = GeoPeerTable::new(
            collector_bgp_id,
            "private-view".to_string(),
            f32::NAN,
            f32::NAN,
        );
        assert!(private_geo_table.collector_latitude.is_nan());
        assert!(private_geo_table.collector_longitude.is_nan());
    }

    #[test]
    fn test_geo_peer_table_encoding() {
        use bytes::{BufMut, BytesMut};

        let collector_bgp_id = Ipv4Addr::from_str("10.0.0.1").unwrap();
        let mut geo_table = GeoPeerTable::new(
            collector_bgp_id,
            "test-view".to_string(),
            51.5074, // London latitude
            -0.1278, // London longitude
        );

        // Add a peer with IPv4 address and 2-byte AS
        let peer1 = Peer::new(
            Ipv4Addr::from_str("1.1.1.1").unwrap(),
            Ipv4Addr::from_str("2.2.2.2").unwrap().into(),
            Asn::new_16bit(65001),
        );
        let geo_peer1 = GeoPeer::new(peer1, 40.7128, -74.0060); // New York
        geo_table.add_geo_peer(geo_peer1);

        // Add a peer with IPv6 address and 4-byte AS
        let peer2 = Peer::new(
            Ipv4Addr::from_str("3.3.3.3").unwrap(),
            std::net::Ipv6Addr::from_str("2001:db8::1").unwrap().into(),
            Asn::new_32bit(65002),
        );
        let geo_peer2 = GeoPeer::new(peer2, f32::NAN, f32::NAN); // Private coordinates
        geo_table.add_geo_peer(geo_peer2);

        // Encode the geo table
        let encoded = geo_table.encode();

        // Create expected bytes manually for comparison
        let mut expected = BytesMut::new();

        // Collector BGP ID
        expected.put_u32(0x0A000001); // 10.0.0.1

        // View name length and name
        let view_name = "test-view";
        expected.put_u16(view_name.len() as u16);
        expected.extend_from_slice(view_name.as_bytes());

        // Collector coordinates
        expected.put_f32(51.5074);
        expected.put_f32(-0.1278);

        // Peer count
        expected.put_u16(2);

        // First peer: IPv4, 2-byte AS
        expected.put_u8(0x00); // Peer type: IPv4, 2-byte AS
        expected.put_u32(0x01010101); // BGP ID: 1.1.1.1
        expected.put_u32(0x02020202); // Peer IP: 2.2.2.2
        expected.put_u16(65001); // AS number
        expected.put_f32(40.7128); // New York latitude
        expected.put_f32(-74.0060); // New York longitude

        // Second peer: IPv6, 4-byte AS
        expected.put_u8(0x03); // Peer type: IPv6, 4-byte AS
        expected.put_u32(0x03030303); // BGP ID: 3.3.3.3
                                      // IPv6 address: 2001:db8::1
        expected.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        expected.put_u32(65002); // AS number
        expected.put_f32(f32::NAN); // Private latitude
        expected.put_f32(f32::NAN); // Private longitude

        let expected_bytes = expected.freeze();

        // Compare the encoded bytes with expected
        assert_eq!(encoded.len(), expected_bytes.len());
        assert_eq!(encoded, expected_bytes);
    }
}
