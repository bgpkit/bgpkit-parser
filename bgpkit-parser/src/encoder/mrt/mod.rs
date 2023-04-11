use crate::encoder::MrtEncode;
use crate::models::{MrtMessage, MrtRecord, TableDumpMessage};
use bytes::{BufMut, Bytes, BytesMut};

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
        match self {
            MrtMessage::TableDumpMessage(m) => m.encode(),
            MrtMessage::TableDumpV2Message(m) => m.encode(),
            MrtMessage::Bgp4Mp(m) => m.encode(),
        }
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
