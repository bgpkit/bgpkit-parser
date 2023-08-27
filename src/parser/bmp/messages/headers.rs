use crate::models::*;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bytes::{Buf, Bytes};
use num_traits::FromPrimitive;
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

pub fn parse_bmp_common_header(data: &mut Bytes) -> Result<BmpCommonHeader, ParserBmpError> {
    let version = data.read_u8()?;
    if version != 3 {
        // has to be 3 per rfc7854
        return Err(ParserBmpError::CorruptedBmpMessage);
    }

    let msg_len = data.read_u32()?;

    let msg_type = BmpMsgType::from_u8(data.read_u8()?).unwrap();
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

#[derive(Debug, Primitive)]
pub enum PeerType {
    Global = 0,
    RD = 1,
    Local = 2,
}

pub fn parse_per_peer_header(data: &mut Bytes) -> Result<BmpPerPeerHeader, ParserBmpError> {
    let peer_type = PeerType::from_u8(data.read_u8()?).unwrap();

    let peer_flags = data.read_u8()?;

    let peer_distinguisher = data.read_u64()?;

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
        data.read_ipv6_address()?.into()
    } else {
        data.advance(12);
        let ip = data.read_ipv4_address()?;
        ip.into()
    };

    let peer_asn: u32 = if is_2byte_asn {
        data.advance(2);
        data.read_u16()? as u32
    } else {
        data.read_u32()?
    };

    let peer_bgp_id = data.read_u32()?;

    let t_sec = data.read_u32()?;
    let t_usec = data.read_u32()?;
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
