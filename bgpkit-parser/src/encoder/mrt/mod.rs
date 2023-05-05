use crate::encoder::MrtEncode;
use crate::models::{AsnLength, Bgp4Mp, Bgp4MpType, MrtMessage, MrtRecord, TableDumpMessage};

use bytes::{BufMut, Bytes, BytesMut};
use ipnet::IpNet;
use num_traits::FromPrimitive;
use std::net::IpAddr;

mod common_header;

impl MrtEncode for MrtRecord {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        let header_bytes = self.common_header.encode();
        let message_bytes = self.message.encode(self.common_header.entry_subtype);
        // let parsed_body = crate::parser::mrt::mrt_record::parse_mrt_body(
        //     self.common_header.entry_type as u16,
        //     self.common_header.entry_subtype,
        //     message_bytes.clone(),
        // )
        // .unwrap();
        // assert!(self.message == parsed_body);
        bytes.put_slice(&header_bytes);
        bytes.put_slice(&message_bytes);
        bytes.freeze()
    }
}

impl MrtMessage {
    fn encode(&self, sub_type: u16) -> Bytes {
        let msg_bytes: Bytes = match self {
            MrtMessage::TableDumpMessage(m) => {
                todo!("tabledump message is not supported yet");
                // let entry_type = EntryType::TABLE_DUMP;
                // bytes.put_u16(m.view_number);
                // bytes.put_u16(m.sequence_number);
                // match &m.prefix.prefix {
                //     IpNet::V4(prefix) => {
                //         todo!();
                //         // bytes.put_u32(prefix..into());
                //     }
                //     IpNet::V6(prefix) => {
                //         todo!();
                //         // bytes.put_u128(prefix.ip().to_be());
                //     }
                // }
                // match &m.prefix.prefix {
                //     IpNet::V4(prefix) => {}
                //     IpNet::V6(prefix) => {}
                // }
            }
            MrtMessage::TableDumpV2Message(m) => {
                todo!("tabledump message is not supported yet");
                // let entry_type = EntryType::TABLE_DUMP_V2;
            }
            MrtMessage::Bgp4Mp(m) => {
                let msg_type = Bgp4MpType::from_u16(sub_type).unwrap();
                let add_path = matches!(
                    msg_type,
                    Bgp4MpType::Bgp4MpMessageAddpath
                        | Bgp4MpType::Bgp4MpMessageAs4Addpath
                        | Bgp4MpType::Bgp4MpMessageLocalAddpath
                        | Bgp4MpType::Bgp4MpMessageLocalAs4Addpath
                );
                let asn_len = match matches!(
                    msg_type,
                    Bgp4MpType::Bgp4MpMessageAs4
                        | Bgp4MpType::Bgp4MpMessageAs4Addpath
                        | Bgp4MpType::Bgp4MpMessageLocalAs4Addpath
                        | Bgp4MpType::Bgp4MpMessageAs4Local
                ) {
                    true => AsnLength::Bits32,
                    false => AsnLength::Bits16,
                };

                match m {
                    Bgp4Mp::Bgp4MpStateChange(msg) | Bgp4Mp::Bgp4MpStateChangeAs4(msg) => {
                        let asn_len = match matches!(msg_type, Bgp4MpType::Bgp4MpStateChangeAs4) {
                            true => AsnLength::Bits32,
                            false => AsnLength::Bits16,
                        };
                        msg.encode(asn_len)
                    }
                    Bgp4Mp::Bgp4MpMessage(msg)
                    | Bgp4Mp::Bgp4MpMessageLocal(msg)
                    | Bgp4Mp::Bgp4MpMessageAs4(msg)
                    | Bgp4Mp::Bgp4MpMessageAs4Local(msg) => msg.encode(add_path, asn_len),
                }
            }
        };

        msg_bytes
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
