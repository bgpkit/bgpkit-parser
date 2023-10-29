//! MRT BGP4MP structs
use crate::models::*;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::net::IpAddr;

/// BGP states enum.
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum BgpState {
    Idle = 1,
    Connect = 2,
    Active = 3,
    OpenSent = 4,
    OpenConfirm = 5,
    Established = 6,
}

/// BGP4MP message types.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Bgp4MpEnum {
    StateChange(Bgp4MpStateChange),
    Message(Bgp4MpMessage),
}

impl Bgp4MpEnum {
    pub const fn msg_type(&self) -> Bgp4MpType {
        match self {
            Bgp4MpEnum::StateChange(x) => x.msg_type,
            Bgp4MpEnum::Message(x) => x.msg_type,
        }
    }
}

/// BGP4MP message subtypes.
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum Bgp4MpType {
    StateChange = 0,
    Message = 1,
    MessageAs4 = 4,
    StateChangeAs4 = 5,
    MessageLocal = 6,
    MessageAs4Local = 7,
    MessageAddpath = 8,
    MessageAs4Addpath = 9,
    MessageLocalAddpath = 10,
    MessageLocalAs4Addpath = 11,
}

/// BGP4MP state change message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bgp4MpStateChange {
    pub msg_type: Bgp4MpType,
    pub peer_asn: Asn,
    pub local_asn: Asn,
    pub interface_index: u16,
    pub peer_addr: IpAddr,
    pub local_addr: IpAddr,
    pub old_state: BgpState,
    pub new_state: BgpState,
}

/// BGP4MP message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bgp4MpMessage {
    pub msg_type: Bgp4MpType,
    pub peer_asn: Asn,
    pub local_asn: Asn,
    pub interface_index: u16,
    pub peer_ip: IpAddr,
    pub local_ip: IpAddr,
    pub bgp_message: BgpMessage,
}

impl Bgp4MpMessage {
    pub const fn is_local(&self) -> bool {
        matches!(
            self.msg_type,
            Bgp4MpType::MessageLocal
                | Bgp4MpType::MessageAs4Local
                | Bgp4MpType::MessageLocalAddpath
                | Bgp4MpType::MessageLocalAs4Addpath
        )
    }
}

pub const fn address_family(ip: &IpAddr) -> u16 {
    match ip {
        IpAddr::V4(_) => 1,
        IpAddr::V6(_) => 2,
    }
}
