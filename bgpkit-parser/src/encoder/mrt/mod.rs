use crate::encoder::MrtEncode;
use crate::models::{EntryType, MrtMessage, MrtRecord, TableDumpMessage};
use bytes::{BufMut, Bytes, BytesMut};
use ipnet::IpNet;
use std::net::IpAddr;

mod common_header;

impl MrtEncode for MrtRecord {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&self.common_header.encode());
        bytes.put_slice(&self.message.encode());
        bytes.freeze()
    }
}

impl MrtMessage {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        match self {
            MrtMessage::TableDumpMessage(m) => {
                let entry_type = EntryType::TABLE_DUMP;
                bytes.put_u16(m.view_number);
                bytes.put_u16(m.sequence_number);
                match &m.prefix.prefix {
                    IpNet::V4(prefix) => {
                        todo!();
                        // bytes.put_u32(prefix..into());
                    }
                    IpNet::V6(prefix) => {
                        todo!();
                        // bytes.put_u128(prefix.ip().to_be());
                    }
                }
                match &m.prefix.prefix {
                    IpNet::V4(prefix) => {}
                    IpNet::V6(prefix) => {}
                }
            }
            MrtMessage::TableDumpV2Message(m) => {
                let entry_type = EntryType::TABLE_DUMP_V2;
            }
            MrtMessage::Bgp4Mp(m) => {
                let entry_type = EntryType::BGP4MP;
            }
        }

        todo!()
    }
}

impl MrtEncode for TableDumpMessage {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put_u16(self.view_number);
        bytes.put_u16(self.sequence_number);
        // TODO: prefix
        match &self.prefix.prefix {
            IpNet::V4(p) => {
                bytes.put_u32(p.addr().into());
                bytes.put_u8(p.prefix_len());
            }
            IpNet::V6(p) => {
                bytes.put_u128(p.addr().into());
                bytes.put_u8(p.prefix_len());
            }
        }
        bytes.put_u8(self.status);
        bytes.put_u32(self.originated_time as u32);

        // peer address and peer asn
        match self.peer_address {
            IpAddr::V4(a) => {
                bytes.put_u32(a.into());
            }
            IpAddr::V6(a) => {
                bytes.put_u128(a.into());
            }
        }
        bytes.put_u16(self.peer_asn.asn as u16);

        // encode attributes
        let attr_bytes = BytesMut::new();
        // TODO encode attributes to attr_bytes
        for attr in &self.attributes {}

        bytes.put_u16(attr_bytes.len() as u16);
        bytes.put_slice(&attr_bytes);

        bytes.freeze()
    }
}
