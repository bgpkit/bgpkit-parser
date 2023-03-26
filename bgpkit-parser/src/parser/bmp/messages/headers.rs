use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bgp_models::prelude::*;
use num_traits::FromPrimitive;
use std::io::{Cursor, Seek, SeekFrom};
use std::net::IpAddr;

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
#[derive(Debug, Primitive)]
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
#[derive(Debug)]
pub struct BmpCommonHeader {
    pub version: u8,
    pub msg_len: u32,
    pub msg_type: BmpMsgType,
}

pub fn parse_bmp_common_header(
    reader: &mut Cursor<&[u8]>,
) -> Result<BmpCommonHeader, ParserBmpError> {
    let version = reader.read_8b()?;
    if version != 3 {
        // has to be 3 per rfc7854
        return Err(ParserBmpError::CorruptedBmpMessage);
    }

    let msg_len = reader.read_32b()?;

    let msg_type = BmpMsgType::from_u8(reader.read_8b()?).unwrap();
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
#[derive(Debug)]
pub struct BmpPerPeerHeader {
    pub peer_type: PeerType,
    pub peer_flags: u8,
    pub peer_distinguisher: u64,
    pub peer_ip: IpAddr,
    pub peer_asn: u32,
    pub peer_bgp_id: u32,
    pub timestamp: f64,
    pub afi: Afi,
    pub asn_len: AsnLength,
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Primitive)]
pub enum PeerType {
    GlobalInstancePeer = 0,
    RDInstancePeer = 1,
    LocalInstancePeer = 2,
}

pub fn parse_per_peer_header(
    reader: &mut Cursor<&[u8]>,
) -> Result<BmpPerPeerHeader, ParserBmpError> {
    let peer_type = PeerType::from_u8(reader.read_8b()?).unwrap();

    let peer_flags = reader.read_8b()?;

    let peer_distinguisher = reader.read_64b()?;

    let (is_router_ipv6, is_2byte_asn) = (peer_flags & 0x80 > 0, peer_flags & 0x20 > 0);

    let afi = match is_router_ipv6 {
        true => Afi::Ipv6,
        false => Afi::Ipv4,
    };

    let asn_len = match is_2byte_asn {
        true => AsnLength::Bits16,
        false => AsnLength::Bits32,
    };

    let peer_ip: IpAddr = if is_router_ipv6 {
        reader.read_ipv6_address()?.into()
    } else {
        reader.seek(SeekFrom::Current(12))?;
        let ip = reader.read_ipv4_address()?;
        ip.into()
    };

    let peer_asn: u32 = if is_2byte_asn {
        reader.seek(SeekFrom::Current(2))?;
        reader.read_16b()? as u32
    } else {
        reader.read_32b()?
    };

    let peer_bgp_id = reader.read_32b()?;

    let t_sec = reader.read_32b()?;
    let t_usec = reader.read_32b()?;
    let timestamp = t_sec as f64 + (t_usec as f64) / 1_000_000.0;

    Ok(BmpPerPeerHeader {
        peer_type,
        peer_flags,
        peer_distinguisher,
        peer_ip,
        peer_asn,
        peer_bgp_id,
        timestamp,
        afi,
        asn_len,
    })
}
