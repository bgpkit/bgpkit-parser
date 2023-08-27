//! BGP messages and relevant structs.

pub mod attributes;
pub mod capabilities;
pub mod community;
pub mod elem;
pub mod error;
pub mod role;

pub use attributes::*;
pub use capabilities::*;
pub use community::*;
pub use elem::*;
pub use error::*;
pub use role::*;

use crate::models::network::*;
use capabilities::BgpCapabilityType;
use error::BgpError;
use std::net::Ipv4Addr;

#[derive(Debug, Primitive, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BgpMessageType {
    OPEN = 1,
    UPDATE = 2,
    NOTIFICATION = 3,
    KEEPALIVE = 4,
}

// https://tools.ietf.org/html/rfc4271#section-4
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BgpMessage {
    Open(BgpOpenMessage),
    Update(BgpUpdateMessage),
    Notification(BgpNotificationMessage),
    KeepAlive(BgpKeepAliveMessage),
}

/// BGP Open Message
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+
///  |    Version    |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |     My Autonomous System      |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |           Hold Time           |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                         BGP Identifier                        |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  | Opt Parm Len  |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                                                               |
///  |             Optional Parameters (variable)                    |
///  |                                                               |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BgpOpenMessage {
    pub version: u8,
    pub asn: Asn,
    pub hold_time: u16,
    pub sender_ip: Ipv4Addr,
    pub extended_length: bool,
    pub opt_params: Vec<OptParam>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OptParam {
    pub param_type: u8,
    pub param_len: u16,
    pub param_value: ParamValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ParamValue {
    Raw(Vec<u8>),
    Capability(Capability),
}

/// BGP Capability.
///
/// - RFC3392: <https://datatracker.ietf.org/doc/html/rfc3392>
/// - Capability codes: <https://www.iana.org/assignments/capability-codes/capability-codes.xhtml#capability-codes-2>
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Capability {
    pub code: u8,
    pub len: u8,
    pub value: Vec<u8>,
    pub capability_type: Option<BgpCapabilityType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BgpUpdateMessage {
    pub withdrawn_prefixes: Vec<NetworkPrefix>,
    pub attributes: Vec<Attribute>,
    pub announced_prefixes: Vec<NetworkPrefix>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BgpNotificationMessage {
    pub error_code: u8,
    pub error_subcode: u8,
    pub error_type: Option<BgpError>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BgpKeepAliveMessage {}
