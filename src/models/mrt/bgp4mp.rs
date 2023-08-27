//! MRT BGP4MP structs
use crate::models::*;
use serde::Serialize;
use std::net::IpAddr;

/// BGP states enum.
#[derive(Debug, Primitive, Copy, Clone, Serialize, PartialEq, Eq, Hash)]
pub enum BgpState {
    Idle = 1,
    Connect = 2,
    Active = 3,
    OpenSent = 4,
    OpenConfirm = 5,
    Established = 6,
}

/// BGP4MP message types.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum Bgp4Mp {
    StateChange(Bgp4MpStateChange),
    Message(Bgp4MpMessage),
}

impl Bgp4Mp {
    pub const fn msg_type(&self) -> Bgp4MpType {
        match self {
            Bgp4Mp::StateChange(x) => x.msg_type,
            Bgp4Mp::Message(x) => x.msg_type,
        }
    }
}

/// BGP4MP message subtypes.
#[derive(Debug, Primitive, Copy, Clone, Serialize, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Bgp4MpStateChange {
    pub msg_type: Bgp4MpType,
    pub peer_asn: Asn,
    pub local_asn: Asn,
    pub interface_index: u16,
    pub address_family: Afi,
    pub peer_addr: IpAddr,
    pub local_addr: IpAddr,
    pub old_state: BgpState,
    pub new_state: BgpState,
}

/// BGP4MP message.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Bgp4MpMessage {
    pub msg_type: Bgp4MpType,
    pub peer_asn: Asn,
    pub local_asn: Asn,
    pub interface_index: u16,
    pub afi: Afi,
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
