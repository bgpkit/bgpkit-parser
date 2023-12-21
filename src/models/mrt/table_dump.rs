//! MRT table dump version 1 and 2 structs
use crate::models::*;
use std::net::IpAddr;

/// TableDump message version 1
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TableDumpMessage {
    pub view_number: u16,
    pub sequence_number: u16,
    pub prefix: NetworkPrefix,
    pub status: u8,
    pub originated_time: u64,
    pub peer_address: IpAddr,
    pub peer_asn: Asn,
    pub attributes: Attributes,
}
