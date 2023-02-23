//! BGP messages and relevant structs.

pub mod attributes;
pub mod capabilities;
pub mod community;
pub mod elem;
pub mod error;
pub mod role;

pub use crate::bgp::attributes::*;
pub use crate::bgp::capabilities::*;
pub use crate::bgp::community::*;
pub use crate::bgp::elem::*;
pub use crate::bgp::error::*;
pub use crate::bgp::role::*;

use crate::bgp::capabilities::BgpCapabilityType;
use crate::bgp::error::BgpError;
use crate::network::*;
use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Debug, Primitive, Copy, Clone, Serialize, PartialEq)]
pub enum BgpMessageType {
    OPEN = 1,
    UPDATE = 2,
    NOTIFICATION = 3,
    KEEPALIVE = 4,
}

// https://tools.ietf.org/html/rfc4271#section-4
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BgpOpenMessage {
    pub version: u8,
    pub asn: Asn,
    pub hold_time: u16,
    pub sender_ip: Ipv4Addr,
    pub extended_length: bool,
    pub opt_params: Vec<OptParam>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OptParam {
    pub param_type: u8,
    pub param_len: u16,
    pub param_value: ParamValue,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ParamValue {
    Raw(Vec<u8>),
    Capability(Capability),
}

/// BGP Capability.
///
/// - RFC3392: <https://datatracker.ietf.org/doc/html/rfc3392>
/// - Capability codes: <https://www.iana.org/assignments/capability-codes/capability-codes.xhtml#capability-codes-2>
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Capability {
    pub code: u8,
    pub len: u8,
    pub value: Vec<u8>,
    pub capability_type: Option<BgpCapabilityType>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BgpUpdateMessage {
    pub withdrawn_prefixes: Vec<NetworkPrefix>,
    pub attributes: Vec<Attribute>,
    pub announced_prefixes: Vec<NetworkPrefix>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BgpNotificationMessage {
    pub error_code: u8,
    pub error_subcode: u8,
    pub error_type: Option<BgpError>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BgpKeepAliveMessage {}
