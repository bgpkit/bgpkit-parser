//! MRT Encoder module
//!
//! `mrt_encoder` module handles serializing BGP/MRT messages back to MRT binary files. The main
//! difficulty part of this process is the handling of TableDumpV2 RIB dumps, which requires
//! reconstructing the peer index table before encoding all other contents.

use crate::models::{
    Attributes, Bgp4MpType, BgpElem, CommonHeader, EntryType, MrtMessage, MrtRecord, NetworkPrefix,
    Peer, PeerIndexTable, RibAfiEntries, RibEntry, TableDumpV2Message, TableDumpV2Type,
};
use bytes::{Bytes, BytesMut};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Default)]
pub struct MrtRibEncoder {
    index_table: PeerIndexTable,

    per_prefix_entries_map: HashMap<IpNet, HashMap<u16, RibEntry>>,

    timestamp: f64,
}

fn convert_timestamp(timestamp: f64) -> (u32, u32) {
    let seconds = timestamp as u32;
    let microseconds = ((timestamp - seconds as f64) * 1_000_000.0) as u32;
    (seconds, microseconds)
}

impl MrtRibEncoder {
    pub fn new() -> Self {
        Self {
            index_table: Default::default(),
            per_prefix_entries_map: Default::default(),
            timestamp: 0.0,
        }
    }

    pub fn process_elem(&mut self, elem: &BgpElem) {
        if self.timestamp == 0.0 {
            self.timestamp = elem.timestamp;
        }
        let bgp_identifier = match elem.peer_ip {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(ip) => Ipv4Addr::from(0),
        };
        let peer = Peer::new(bgp_identifier, elem.peer_ip, elem.peer_asn);
        let peer_id = self.index_table.add_peer(peer);
        let prefix = elem.prefix.prefix;

        let entries_map = self.per_prefix_entries_map.entry(prefix).or_default();
        let entry = RibEntry {
            peer_index: peer_id,
            originated_time: elem.timestamp as u32,
            attributes: Attributes::from(elem),
        };
        entries_map.insert(peer_id, entry);
    }

    pub fn export_bytes(&mut self) -> Bytes {
        let mut bytes = BytesMut::new();

        // encode peer-index-table
        let mrt_message = MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(
            self.index_table.clone(),
        ));
        let (seconds, microseconds) = convert_timestamp(self.timestamp);
        let subtype = TableDumpV2Type::PeerIndexTable as u16;
        let data_bytes = mrt_message.encode(subtype);
        let header_bytes = CommonHeader {
            timestamp: seconds,
            microsecond_timestamp: Some(microseconds),
            entry_type: EntryType::TABLE_DUMP_V2,
            entry_subtype: subtype,
            length: data_bytes.len() as u32,
        }
        .encode();
        bytes.extend(header_bytes);
        bytes.extend(data_bytes);

        // encode each RibAfiEntries
        for (entry_count, (prefix, entries_map)) in self.per_prefix_entries_map.iter().enumerate() {
            let rib_type = match prefix.addr().is_ipv6() {
                true => TableDumpV2Type::RibIpv6Unicast,
                false => TableDumpV2Type::RibIpv4Unicast,
            };

            let mut prefix_rib_entry = RibAfiEntries {
                rib_type,
                sequence_number: entry_count as u32,
                prefix: NetworkPrefix::new(*prefix, 0),
                rib_entries: vec![],
            };
            for entry in entries_map.values() {
                prefix_rib_entry.rib_entries.push(entry.clone());
            }

            let mrt_message =
                MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(prefix_rib_entry));

            let (seconds, microseconds) = convert_timestamp(self.timestamp);
            let subtype = rib_type as u16;
            let data_bytes = mrt_message.encode(subtype);
            let header_bytes = CommonHeader {
                timestamp: seconds,
                microsecond_timestamp: Some(microseconds),
                entry_type: EntryType::TABLE_DUMP_V2,
                entry_subtype: subtype,
                length: data_bytes.len() as u32,
            }
            .encode();
            bytes.extend(header_bytes);
            bytes.extend(data_bytes);
        }

        self.index_table = PeerIndexTable::default();
        self.per_prefix_entries_map = HashMap::default();
        self.timestamp = 0.0;

        bytes.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_mrt_record;
    use std::io::Cursor;

    #[test]
    fn test_encoding_rib() {
        let mut encoder = MrtRibEncoder::new();
        let elem = BgpElem::default();
        encoder.process_elem(&elem);
        let bytes = encoder.export_bytes();

        let parsed = parse_mrt_record(&mut Cursor::new(bytes)).unwrap();
        dbg!(&parsed);
    }
}
