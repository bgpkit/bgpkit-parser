use crate::encoder::sink::put_u16_len_slice;
use crate::error::{check_max, EncodingError};
use crate::models::{Afi, AsnLength, Peer, PeerIndexTable, PeerType};
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// Parses a byte slice into a [PeerIndexTable].
///
/// RFC: https://www.rfc-editor.org/rfc/rfc6396#section-4.3.1
///
/// # Arguments
///
/// * `data` - The byte slice to parse.
///
/// # Returns
///
/// - `Ok(PeerIndexTable)` if the parsing is successful.
/// - `Err(ParserError)` if an error occurs during parsing.
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
        let peer_ip: IpAddr = data.read_address(&afi)?;
        let peer_asn = data.read_asn(asn_len)?;
        peers.push(Peer {
            peer_type,
            peer_bgp_id,
            peer_ip,
            peer_asn,
        })
    }

    let mut id_peer_map = HashMap::new();
    let mut peer_ip_id_map = HashMap::new();

    for (id, p) in peers.into_iter().enumerate() {
        id_peer_map.insert(id as u16, p);
        peer_ip_id_map.insert(p.peer_ip, id as u16);
    }

    Ok(PeerIndexTable {
        collector_bgp_id,
        view_name,
        id_peer_map,
        peer_ip_id_map,
    })
}

impl PeerIndexTable {
    /// Add peer to peer index table and return peer id.
    ///
    /// The PEER_INDEX_TABLE wire format uses a 16-bit peer count, so at most
    /// 65535 distinct peers can be stored. Adding a peer beyond that returns
    /// [`EncodingError::ValueTooLarge`] and leaves the table unmodified —
    /// previously the id silently wrapped, aliasing routes to the wrong peer.
    pub fn add_peer(&mut self, peer: Peer) -> Result<u16, EncodingError> {
        match self.peer_ip_id_map.get(&peer.peer_ip) {
            Some(id) => Ok(*id),
            None => {
                let next_id = self.peer_ip_id_map.len();
                check_max("PeerIndexTable peer count", next_id + 1, u16::MAX as usize)?;
                let peer_id = next_id as u16;
                self.peer_ip_id_map.insert(peer.peer_ip, peer_id);
                self.id_peer_map.insert(peer_id, peer);
                Ok(peer_id)
            }
        }
    }

    /// Returns the peer associated with the given peer ID.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - A reference to the peer ID.
    ///
    /// # Returns
    ///
    /// An `Option` containing a reference to the [Peer] if found, otherwise `None`.
    pub fn get_peer_by_id(&self, peer_id: &u16) -> Option<&Peer> {
        self.id_peer_map.get(peer_id)
    }

    /// Returns the peer ID associated with the given IP address.
    ///
    /// # Arguments
    ///
    /// * `peer_ip` - The IP address of the peer.
    ///
    /// # Returns
    ///
    /// An optional `u16` representing the peer ID. Returns `None` if the IP address is not found.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::IpAddr;
    /// use std::str::FromStr;
    /// use bgpkit_parser::models::PeerIndexTable;
    ///
    /// let index_table = PeerIndexTable::default();
    /// let peer_ip = IpAddr::from_str("127.0.0.1").unwrap();
    /// let peer_id = index_table.get_peer_id_by_addr(&peer_ip);
    /// ```
    pub fn get_peer_id_by_addr(&self, peer_ip: &IpAddr) -> Option<u16> {
        self.peer_ip_id_map.get(peer_ip).copied()
    }

    /// Encode the data in the struct into a byte array.
    ///
    /// # Returns
    ///
    /// A `Bytes` object containing the encoded data.
    ///
    /// # Example
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use std::net::Ipv4Addr;
    /// use bgpkit_parser::models::PeerIndexTable;
    ///
    /// let data = PeerIndexTable {
    ///     collector_bgp_id: Ipv4Addr::from(1234),
    ///     view_name: String::from("example"),
    ///     id_peer_map: HashMap::new(),
    ///     peer_ip_id_map: Default::default(),
    /// };
    ///
    /// let encoded = data.encode().unwrap();
    /// ```
    pub fn encode(&self) -> Result<Bytes, EncodingError> {
        let mut buf = BytesMut::new();

        // Encode collector_bgp_id
        buf.put_u32(self.collector_bgp_id.into());

        // Encode view_name_length and view_name
        put_u16_len_slice(
            &mut buf,
            "PeerIndexTable view name length",
            self.view_name.as_bytes(),
        )?;

        // Encode peer_count
        let peer_count = self.id_peer_map.len();
        check_max("PeerIndexTable peer count", peer_count, u16::MAX as usize)?;
        buf.put_u16(peer_count as u16);

        // Encode peers
        let mut peer_ids: Vec<_> = self.id_peer_map.keys().collect();
        peer_ids.sort();
        for id in peer_ids {
            let peer = self.id_peer_map.get(id).unwrap();
            // Encode PeerType
            buf.put_u8(peer.peer_type.bits());

            // Encode peer_bgp_id
            buf.put_u32(peer.peer_bgp_id.into());

            // Encode peer_ip
            match peer.peer_ip {
                IpAddr::V4(ipv4) => {
                    buf.put_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    buf.put_slice(&ipv6.octets());
                }
            };

            // Encode peer_asn
            match peer.peer_type.contains(PeerType::AS_SIZE_32BIT) {
                true => buf.put_u32(peer.peer_asn.to_u32()),
                false => buf.put_u16(peer.peer_asn.to_u32() as u16),
            };
        }

        // Return Bytes
        Ok(buf.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Asn;
    use std::str::FromStr;

    #[test]
    fn test_peer_index_table_encode() {
        let mut index_table = PeerIndexTable {
            collector_bgp_id: Ipv4Addr::from(1234),
            view_name: String::from("example"),
            id_peer_map: HashMap::new(),
            peer_ip_id_map: Default::default(),
        };

        index_table
            .add_peer(Peer::new(
                Ipv4Addr::from(1234),
                IpAddr::from_str("192.168.1.1").unwrap(),
                Asn::new_32bit(1234),
            ))
            .unwrap();
        index_table
            .add_peer(Peer::new(
                Ipv4Addr::from(12345),
                IpAddr::from_str("192.168.1.2").unwrap(),
                Asn::new_32bit(12345),
            ))
            .unwrap();

        let encoded = index_table.encode().unwrap();
        let parsed_index_table = parse_peer_index_table(&mut encoded.clone()).unwrap();
        assert_eq!(index_table, parsed_index_table);
    }

    #[test]
    fn test_get_peer_by_id() {
        let mut index_table = PeerIndexTable {
            collector_bgp_id: Ipv4Addr::from(1234),
            view_name: String::from("example"),
            id_peer_map: HashMap::new(),
            peer_ip_id_map: Default::default(),
        };

        let peer1 = Peer::new(
            Ipv4Addr::from(1234),
            IpAddr::from_str("10.0.0.1").unwrap(),
            Asn::new_32bit(1234),
        );
        let peer2 = Peer::new(
            Ipv4Addr::from(12345),
            IpAddr::from_str("10.0.0.2").unwrap(),
            Asn::new_32bit(12345),
        );

        let peer1_id = index_table.add_peer(peer1).unwrap();
        let peer2_id = index_table.add_peer(peer2).unwrap();

        assert_eq!(
            index_table.get_peer_by_id(&peer1_id),
            Some(&Peer::new(
                Ipv4Addr::from(1234),
                IpAddr::from_str("10.0.0.1").unwrap(),
                Asn::new_32bit(1234),
            ))
        );
        assert_eq!(
            index_table.get_peer_by_id(&peer2_id),
            Some(&Peer::new(
                Ipv4Addr::from(12345),
                IpAddr::from_str("10.0.0.2").unwrap(),
                Asn::new_32bit(12345),
            ))
        );
    }

    #[test]
    fn test_add_peer_rejects_overflow_without_corruption() {
        let mut index_table = PeerIndexTable::default();

        // fill the table to its 16-bit wire capacity of 65535 peers
        for i in 0..(u16::MAX as u32) {
            let ip = IpAddr::from(Ipv4Addr::from(i + 1));
            index_table
                .add_peer(Peer::new(Ipv4Addr::from(1), ip, Asn::new_32bit(i)))
                .unwrap();
        }
        assert_eq!(index_table.id_peer_map.len(), u16::MAX as usize);

        // the 65536th peer must be rejected, not aliased onto an existing id
        let overflow_ip = IpAddr::from(Ipv4Addr::from(u16::MAX as u32 + 1));
        let overflow_peer = Peer::new(Ipv4Addr::from(1), overflow_ip, Asn::new_32bit(65536));
        let err = index_table.add_peer(overflow_peer).unwrap_err();
        assert_eq!(
            err,
            EncodingError::ValueTooLarge {
                field: "PeerIndexTable peer count",
                actual: u16::MAX as usize + 1,
                max: u16::MAX as usize
            }
        );

        // the failed insert must not have modified the table
        assert_eq!(index_table.id_peer_map.len(), u16::MAX as usize);
        assert_eq!(index_table.get_peer_id_by_addr(&overflow_ip), None);

        // adding an existing peer still returns its id without error
        let existing_ip = IpAddr::from(Ipv4Addr::from(1u32));
        let existing = Peer::new(Ipv4Addr::from(1), existing_ip, Asn::new_32bit(0));
        assert_eq!(index_table.add_peer(existing).unwrap(), 0);

        // the full table still encodes successfully
        index_table.encode().unwrap();
    }
}
