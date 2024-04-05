use crate::models::*;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bitflags::bitflags;
use bytes::{Buf, Bytes};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr};

/// BMP message type enum.
///
/// ```text
///    o  Message Type (1 byte): This identifies the type of the BMP
///       message.  A BMP implementation MUST ignore unrecognized message
///       types upon receipt.
///
///       *  Type = 0: Route Monitoring
///       *  Type = 1: Statistics Report
///       *  Type = 2: Peer Down Notification
///       *  Type = 3: Peer Up Notification
///       *  Type = 4: Initiation Message
///       *  Type = 5: Termination Message
///       *  Type = 6: Route Mirroring Message
/// ```
#[derive(Debug, Clone, TryFromPrimitive, IntoPrimitive, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BmpMsgType {
    RouteMonitoring = 0,
    StatisticsReport = 1,
    PeerDownNotification = 2,
    PeerUpNotification = 3,
    InitiationMessage = 4,
    TerminationMessage = 5,
    RouteMirroringMessage = 6,
}

/// BMP Common Header
///
/// <https://www.rfc-editor.org/rfc/rfc7854#section-4.1>
/// ```text
///       0                   1                   2                   3
///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///      +-+-+-+-+-+-+-+-+
///      |    Version    |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///      |                        Message Length                         |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///      |   Msg. Type   |
///      +---------------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BmpCommonHeader {
    pub version: u8,
    pub msg_len: u32,
    pub msg_type: BmpMsgType,
}

pub fn parse_bmp_common_header(data: &mut Bytes) -> Result<BmpCommonHeader, ParserBmpError> {
    let version = data.read_u8()?;
    if version != 3 {
        // has to be 3 per rfc7854
        return Err(ParserBmpError::CorruptedBmpMessage);
    }

    let msg_len = data.read_u32()?;

    let msg_type = BmpMsgType::try_from(data.read_u8()?)?;
    Ok(BmpCommonHeader {
        version,
        msg_len,
        msg_type,
    })
}

/// BMP Per-peer Header
///
/// ```text
///       0                   1                   2                   3
///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///      |   Peer Type   |  Peer Flags   |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///      |         Peer Distinguisher (present based on peer type)       |
///      |                                                               |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///      |                 Peer Address (16 bytes)                       |
///      ~                                                               ~
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///      |                           Peer AS                             |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///      |                         Peer BGP ID                           |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///      |                    Timestamp (seconds)                        |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///      |                  Timestamp (microseconds)                     |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct BmpPerPeerHeader {
    pub peer_type: BmpPeerType,
    pub peer_flags: PerPeerFlags,
    pub peer_distinguisher: u64,
    pub peer_ip: IpAddr,
    pub peer_asn: Asn,
    pub peer_bgp_id: BgpIdentifier,
    pub timestamp: f64,
}

impl BmpPerPeerHeader {
    #[inline]
    pub fn afi(&self) -> Afi {
        Afi::from(self.peer_ip)
    }

    pub fn asn_length(&self) -> AsnLength {
        match self.peer_flags {
            PerPeerFlags::PeerFlags(f) => f.asn_length(),
            PerPeerFlags::LocalRibPeerFlags(_) => AsnLength::Bits32,
        }
    }
}

/// Peer type
///
/// - RFC7854: https://datatracker.ietf.org/doc/html/rfc7854#section-4.2
/// - RFC9069: https://datatracker.ietf.org/doc/html/rfc9069
#[derive(Debug, TryFromPrimitive, IntoPrimitive, PartialEq, Eq, Hash, Clone)]
#[repr(u8)]
pub enum BmpPeerType {
    Global = 0,
    RD = 1,
    Local = 2,
    LocalRib = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PerPeerFlags {
    PeerFlags(PeerFlags),
    LocalRibPeerFlags(LocalRibPeerFlags),
}

bitflags! {
    /// BMP per-peer header flags
    ///
    /// RFC section at
    /// - RFC 7854: https://www.rfc-editor.org/rfc/rfc7854#section-4.2.
    /// - RFC 8671: https://www.rfc-editor.org/rfc/rfc8671#section-4
    ///
    /// RFC 8671 extended the flags definition by adding one additional flag to indicate whenther
    /// the messages are Adj-RIB-in or Adj-RIB-out.
    ///
    /// ```text
    ///  0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+
    /// |V|L|A|O| Resv  |
    /// +-+-+-+-+-+-+-+-+
    /// ```
    /// When the O flag is set to 1, the following fields in the per-peer header are redefined:
    /// - Peer Address: The remote IP address associated with the TCP session over which the encapsulated Protocol Data Unit (PDU) is sent.
    /// - Peer AS: The Autonomous System number of the peer to which the encapsulated PDU is sent.
    /// - Peer BGP ID: The BGP Identifier of the peer to which the encapsulated PDU is sent.
    /// - Timestamp: The time when the encapsulated routes were advertised (one may also think of
    ///   this as the time when they were installed in the Adj-RIB-Out), expressed in seconds and
    ///   microseconds since midnight (zero hour), January 1, 1970 (UTC). If zero, the time is
    ///   unavailable. Precision of the timestamp is implementation-dependent.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PeerFlags: u8 {
        const ADDRESS_FAMILY_IPV6 = 0b1000_0000;
        const IS_POST_POLICY = 0b0100_0000;
        const AS_SIZE_16BIT = 0b0010_0000;
        const IS_ADJ_RIB_OUT = 0b0001_0000;
    }
}

impl PeerFlags {
    pub const fn address_family(&self) -> Afi {
        if self.contains(PeerFlags::ADDRESS_FAMILY_IPV6) {
            return Afi::Ipv6;
        }

        Afi::Ipv4
    }

    pub const fn asn_length(&self) -> AsnLength {
        if self.contains(PeerFlags::AS_SIZE_16BIT) {
            return AsnLength::Bits16;
        }

        AsnLength::Bits32
    }

    /// Returns true if the peer streams Adj-RIB-out BMP messages
    pub const fn is_adj_rib_out(&self) -> bool {
        self.contains(PeerFlags::IS_ADJ_RIB_OUT)
    }

    /// Returns true if the peer streams post-policy BMP messages
    pub const fn is_post_policy(&self) -> bool {
        self.contains(PeerFlags::IS_POST_POLICY)
    }
}

bitflags! {
    /// BMP local RIB per-peer header flags
    ///
    /// RFC section at
    /// - RFC 9069: https://datatracker.ietf.org/doc/html/rfc9069#section-4.2
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct LocalRibPeerFlags: u8 {
        const IS_FILTERED = 0b1000_0000;
    }
}

impl LocalRibPeerFlags {
    pub const fn is_filtered(&self) -> bool {
        self.contains(LocalRibPeerFlags::IS_FILTERED)
    }
}

pub fn parse_per_peer_header(data: &mut Bytes) -> Result<BmpPerPeerHeader, ParserBmpError> {
    let peer_type = BmpPeerType::try_from(data.read_u8()?)?;

    match peer_type {
        BmpPeerType::Global | BmpPeerType::RD | BmpPeerType::Local => {
            let peer_flags = PeerFlags::from_bits_retain(data.read_u8()?);

            let peer_distinguisher = data.read_u64()?;
            let peer_ip = match peer_flags.address_family() {
                Afi::Ipv4 => {
                    data.advance(12);
                    IpAddr::V4(data.read_ipv4_address()?)
                }
                Afi::Ipv6 => IpAddr::V6(data.read_ipv6_address()?),
            };

            let peer_asn = match peer_flags.asn_length() {
                AsnLength::Bits16 => {
                    data.advance(2);
                    Asn::new_16bit(data.read_u16()?)
                }
                AsnLength::Bits32 => Asn::new_32bit(data.read_u32()?),
            };

            let peer_bgp_id = data.read_ipv4_address()?;

            let t_sec = data.read_u32()?;
            let t_usec = data.read_u32()?;
            let timestamp = t_sec as f64 + (t_usec as f64) / 1_000_000.0;

            Ok(BmpPerPeerHeader {
                peer_type,
                peer_flags: PerPeerFlags::PeerFlags(peer_flags),
                peer_distinguisher,
                peer_ip,
                peer_asn,
                peer_bgp_id,
                timestamp,
            })
        }
        BmpPeerType::LocalRib => {
            let local_rib_peer_flags = LocalRibPeerFlags::from_bits_retain(data.read_u8()?);

            let peer_distinguisher = data.read_u64()?;
            // zero-filled peer_ip address field
            let peer_ip = IpAddr::V4(Ipv4Addr::from(0));
            data.advance(16);

            let peer_asn = Asn::new_32bit(data.read_u32()?);

            let peer_bgp_id = data.read_ipv4_address()?;

            let t_sec = data.read_u32()?;
            let t_usec = data.read_u32()?;
            let timestamp = t_sec as f64 + (t_usec as f64) / 1_000_000.0;

            Ok(BmpPerPeerHeader {
                peer_type,
                peer_flags: PerPeerFlags::LocalRibPeerFlags(local_rib_peer_flags),
                peer_distinguisher,
                peer_ip,
                peer_asn,
                peer_bgp_id,
                timestamp,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_error() {
        let mut data = Bytes::from(vec![0, 0, 0, 0, 0]);
        assert!(parse_bmp_common_header(&mut data).is_err(),);
        assert_eq!(
            parse_bmp_common_header(&mut data).unwrap_err(),
            ParserBmpError::CorruptedBmpMessage
        );
    }

    #[test]
    fn test_bmp_per_peer_header_basics() {
        // test AFI checking
        let per_peer_header = BmpPerPeerHeader {
            peer_type: BmpPeerType::Global,
            peer_flags: PerPeerFlags::LocalRibPeerFlags(LocalRibPeerFlags::empty()),
            peer_distinguisher: 0,
            peer_ip: IpAddr::V4(Ipv4Addr::from(0)),
            peer_asn: Default::default(),
            peer_bgp_id: Ipv4Addr::from(0),
            timestamp: 0.0,
        };
        assert_eq!(per_peer_header.afi(), Afi::Ipv4);

        // check ASN length
        assert_eq!(per_peer_header.asn_length(), AsnLength::Bits32);
    }

    #[test]
    fn test_peer_flags() {
        let mut flags = PeerFlags::empty();
        assert_eq!(flags.address_family(), Afi::Ipv4);
        assert_eq!(flags.asn_length(), AsnLength::Bits32);
        assert!(!flags.is_adj_rib_out());
        assert!(!flags.is_post_policy());

        flags |= PeerFlags::ADDRESS_FAMILY_IPV6;
        assert_eq!(flags.address_family(), Afi::Ipv6);

        flags |= PeerFlags::AS_SIZE_16BIT;
        assert_eq!(flags.asn_length(), AsnLength::Bits16);

        flags |= PeerFlags::IS_ADJ_RIB_OUT;
        assert!(flags.is_adj_rib_out());

        flags |= PeerFlags::IS_POST_POLICY;
        assert!(flags.is_post_policy());
    }

    #[test]
    fn test_local_rib_peer_flags() {
        let mut flags = LocalRibPeerFlags::empty();
        assert!(!flags.is_filtered());

        flags |= LocalRibPeerFlags::IS_FILTERED;
        assert!(flags.is_filtered());
    }

    #[test]
    fn test_parsing_local_rib_per_peer_header() {
        let input_data = vec![
            3, // PeerType::LocalRib
            0, // LocalRibPeerFlags is empty
            0, 0, 0, 0, 0, 0, 0, 1, // Peer Distinguisher
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // advance 16 bytes
            0, 0, 0, 1, // Peer ASN
            192, 168, 1, 1, // Peer BGP ID
            0, 0, 0, 10, // Timestamp (seconds)
            0, 0, 0, 100, // Timestamp (microseconds)
        ];

        let mut bytes = Bytes::from(input_data);
        let header =
            parse_per_peer_header(&mut bytes).expect("Failed to parse local rib per peer header");

        assert_eq!(header.peer_type, BmpPeerType::LocalRib);
        assert_eq!(
            header.peer_flags,
            PerPeerFlags::LocalRibPeerFlags(LocalRibPeerFlags::empty())
        );
        assert_eq!(header.peer_asn, Asn::new_32bit(1));
        assert_eq!(header.peer_bgp_id, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(header.timestamp, 10.0001);
    }
}
