//! BGP messages and relevant structs.

pub mod attributes;
pub mod capabilities;
pub mod community;
pub mod elem;
pub mod error;
pub mod role;

pub use attributes::*;
pub use community::*;
pub use elem::*;
pub use error::*;
pub use role::*;

use crate::models::network::*;
use capabilities::BgpCapabilityType;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::net::Ipv4Addr;

pub type BgpIdentifier = Ipv4Addr;

#[derive(Debug, TryFromPrimitive, IntoPrimitive, Copy, Clone, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
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
    KeepAlive,
}

impl BgpMessage {
    pub const fn msg_type(&self) -> BgpMessageType {
        match self {
            BgpMessage::Open(_) => BgpMessageType::OPEN,
            BgpMessage::Update(_) => BgpMessageType::UPDATE,
            BgpMessage::Notification(_) => BgpMessageType::NOTIFICATION,
            BgpMessage::KeepAlive => BgpMessageType::KEEPALIVE,
        }
    }
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
    pub ty: BgpCapabilityType,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BgpUpdateMessage {
    pub withdrawn_prefixes: Vec<NetworkPrefix>,
    pub attributes: Attributes,
    pub announced_prefixes: Vec<NetworkPrefix>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BgpNotificationMessage {
    pub error: BgpError,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type() {
        let open = BgpMessage::Open(BgpOpenMessage {
            version: 4,
            asn: Asn::new_32bit(1),
            hold_time: 180,
            sender_ip: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![],
        });
        assert_eq!(open.msg_type(), BgpMessageType::OPEN);

        let update = BgpMessage::Update(BgpUpdateMessage::default());
        assert_eq!(update.msg_type(), BgpMessageType::UPDATE);

        let notification = BgpMessage::Notification(BgpNotificationMessage {
            error: BgpError::Unknown(0, 0),
            data: vec![],
        });
        assert_eq!(notification.msg_type(), BgpMessageType::NOTIFICATION);

        let keepalive = BgpMessage::KeepAlive;
        assert_eq!(keepalive.msg_type(), BgpMessageType::KEEPALIVE);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde() {
        let open = BgpMessage::Open(BgpOpenMessage {
            version: 4,
            asn: Asn::new_32bit(1),
            hold_time: 180,
            sender_ip: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![],
        });
        let serialized = serde_json::to_string(&open).unwrap();
        let deserialized: BgpMessage = serde_json::from_str(&serialized).unwrap();
        assert_eq!(open, deserialized);

        let update = BgpMessage::Update(BgpUpdateMessage::default());
        let serialized = serde_json::to_string(&update).unwrap();
        let deserialized: BgpMessage = serde_json::from_str(&serialized).unwrap();
        assert_eq!(update, deserialized);

        let notification = BgpMessage::Notification(BgpNotificationMessage {
            error: BgpError::Unknown(0, 0),
            data: vec![],
        });
        let serialized = serde_json::to_string(&notification).unwrap();
        let deserialized: BgpMessage = serde_json::from_str(&serialized).unwrap();
        assert_eq!(notification, deserialized);

        let keepalive = BgpMessage::KeepAlive;
        let serialized = serde_json::to_string(&keepalive).unwrap();
        let deserialized: BgpMessage = serde_json::from_str(&serialized).unwrap();
        assert_eq!(keepalive, deserialized);
    }
}
