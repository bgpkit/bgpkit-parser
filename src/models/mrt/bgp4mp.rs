//! MRT BGP4MP structs
use crate::models::*;
use std::net::IpAddr;

/// BGP states enum.
#[derive(Debug, Primitive, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
pub enum Bgp4Mp {
    Bgp4MpStateChange(Bgp4MpStateChange),
    Bgp4MpStateChangeAs4(Bgp4MpStateChange),
    Bgp4MpMessage(Bgp4MpMessage),
    Bgp4MpMessageLocal(Bgp4MpMessage),
    Bgp4MpMessageAs4(Bgp4MpMessage),
    Bgp4MpMessageAs4Local(Bgp4MpMessage),
}

/// BGP4MP message subtypes.
#[derive(Debug, Primitive, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Bgp4MpType {
    Bgp4MpStateChange = 0,
    Bgp4MpMessage = 1,
    Bgp4MpMessageAs4 = 4,
    Bgp4MpStateChangeAs4 = 5,
    Bgp4MpMessageLocal = 6,
    Bgp4MpMessageAs4Local = 7,
    Bgp4MpMessageAddpath = 8,
    Bgp4MpMessageAs4Addpath = 9,
    Bgp4MpMessageLocalAddpath = 10,
    Bgp4MpMessageLocalAs4Addpath = 11,
}

/// BGP4MP state change message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
