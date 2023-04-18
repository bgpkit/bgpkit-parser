use crate::encoder::MrtEncode;
use crate::models::{EntryType, MrtMessage, MrtRecord, TableDumpMessage};
use bytes::{BufMut, Bytes, BytesMut};
use ipnet::IpNet;

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
                        bytes.put_u32(prefix.into());
                    }
                    IpNet::V6(prefix) => {
                        bytes.put_u128(prefix.ip().to_be());
                    }
                }
                match &m.prefix.prefix {
                    IpNet::V4(prefix) => {}
                    IpNet::V6(prefix) => {}
                }
            },
            MrtMessage::TableDumpV2Message(m) => {
                let entry_type = EntryType::TABLE_DUMP_V2;
            },
            MrtMessage::Bgp4Mp(m) => {
                let entry_type = EntryType::BGP4MP;
            },
        }

        todo!()
    }
}

impl MrtEncode for TableDumpMessage {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put_u16(self.view_number);
        bytes.put_u16(self.sequence_number);
        match self.
        bytes.put_u32(self.prefix_length);
        bytes.put_u8(self.status);
        bytes.freeze()
    }
}
