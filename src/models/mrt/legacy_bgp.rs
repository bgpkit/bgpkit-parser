//! Models for the deprecated MRT Type 5 BGP format.

use crate::models::{Asn, BgpMessage, BgpState};
use std::net::IpAddr;

/// A deprecated MRT Type 5 BGP message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum LegacyBgp {
    /// An UPDATE or KEEPALIVE message with peer and local endpoint metadata.
    Message(LegacyBgpMessage),
    /// A BGP finite-state-machine transition.
    StateChange(LegacyBgpStateChange),
}

/// Peer metadata and payload for a deprecated MRT Type 5 BGP message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LegacyBgpMessage {
    pub peer_asn: Asn,
    pub peer_ip: IpAddr,
    pub local_asn: Asn,
    pub local_ip: IpAddr,
    pub bgp_message: BgpMessage,
}

/// A state transition from a deprecated MRT Type 5 BGP record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LegacyBgpStateChange {
    pub peer_asn: Asn,
    pub peer_ip: IpAddr,
    pub old_state: BgpState,
    pub new_state: BgpState,
}
