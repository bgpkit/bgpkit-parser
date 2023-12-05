//! MRT Encoder module
//!
//! `mrt_encoder` module handles serializing BGP/MRT messages back to MRT binary files. The main
//! difficulty part of this process is the handling of TableDumpV2 RIB dumps, which requires
//! reconstructing the peer index table before encoding all other contents.

use crate::models::{MrtRecord, Peer, PeerIndexTable};
use crate::BgpElem;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Default)]
pub struct MrtRibEncoder {
    index_table: PeerIndexTable,
}

impl MrtRibEncoder {
    pub fn new() -> Self {
        Self::default()
    }

    // TODO: implement encoding elem
    pub fn encode_elem(&mut self, elem: &BgpElem) {
        let bgp_identifier = match elem.peer_ip {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(ip) => Ipv4Addr::from(0),
        };
        let peer = Peer::new(bgp_identifier, elem.peer_ip, elem.peer_asn);
        let peer_id = self.index_table.add_peer(peer);
        todo!()
    }

    pub fn encode_record(&mut self, record: &MrtRecord) {
        record.message.
        todo!()
    }
}
