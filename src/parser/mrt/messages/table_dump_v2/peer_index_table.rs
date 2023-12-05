use crate::models::{Afi, AsnLength, Peer, PeerIndexTable, PeerType};
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// Peer index table
///
/// RFC: https://www.rfc-editor.org/rfc/rfc6396#section-4.3.1
pub fn parse_peer_index_table(data: &mut Bytes) -> Result<PeerIndexTable, ParserError> {
    let collector_bgp_id = Ipv4Addr::from(data.read_u32()?);
    // read and ignore view name
    let view_name_length = data.read_u16()?;
    let view_name =
        String::from_utf8(data.read_n_bytes(view_name_length as usize)?).unwrap_or("".to_string());

    let peer_count = data.read_u16()?;
    let mut peers = vec![];
    for _index in 0..peer_count {
        let peer_type = PeerType::from_bits_retain(data.read_u8()?);
        let afi = match peer_type.contains(PeerType::ADDRESS_FAMILY_IPV6) {
            true => Afi::Ipv6,
            false => Afi::Ipv4,
        };
        let asn_len = match peer_type.contains(PeerType::AS_SIZE_32BIT) {
            true => AsnLength::Bits32,
            false => AsnLength::Bits16,
        };

        let peer_bgp_id = Ipv4Addr::from(data.read_u32()?);
        let peer_address: IpAddr = data.read_address(&afi)?;
        let peer_asn = data.read_asn(asn_len)?;
        peers.push(Peer {
            peer_type,
            peer_bgp_id,
            peer_address,
            peer_asn,
        })
    }

    let mut id_peer_map = HashMap::new();
    let mut peer_addr_id_map = HashMap::new();

    for (id, p) in peers.into_iter().enumerate() {
        id_peer_map.insert(id as u16, p);
        peer_addr_id_map.insert(p.peer_address, id as u16);
    }

    Ok(PeerIndexTable {
        collector_bgp_id,
        view_name_length,
        view_name,
        peer_count,
        id_peer_map,
        peer_addr_id_map,
    })
}

impl PeerIndexTable {
    /// Add peer to peer index table and return peer id
    pub fn add_peer(&mut self, peer: Peer) -> u16 {
        match self.peer_addr_id_map.get(&peer.peer_address) {
            Some(id) => *id,
            None => {
                self.peer_count += 1;
                let peer_id = self.peer_count;
                self.peer_addr_id_map.insert(peer.peer_address, peer_id);
                self.id_peer_map.insert(peer_id, peer);
                peer_id
            }
        }
    }

    /// Get peer by id
    pub fn get_peer_by_id(&self, peer_id: &u16) -> Option<&Peer> {
        self.id_peer_map.get(peer_id)
    }

    /// Get peer id by IP address.
    pub fn get_peer_id_by_addr(&self, peer_addr: &IpAddr) -> Option<u16> {
        self.peer_addr_id_map.get(peer_addr).copied()
    }
}
