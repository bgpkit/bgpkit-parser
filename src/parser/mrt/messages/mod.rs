use crate::models::{AsnLength, Bgp4Mp, Bgp4MpType, EntryType, MrtMessage};
use crate::parser::{parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message};
use crate::ParserError;
use bytes::Bytes;

pub(crate) mod bgp4mp;
pub(crate) mod table_dump_message;
pub(crate) mod table_dump_v2_message;

impl MrtMessage {
    pub fn encode(&self, sub_type: u16) -> Bytes {
        let msg_bytes: Bytes = match self {
            MrtMessage::TableDumpMessage(m) => m.encode(),
            MrtMessage::TableDumpV2Message(_m) => {
                todo!("TableDumpV2 message is not supported yet");
            }
            MrtMessage::Bgp4Mp(m) => {
                let msg_type = Bgp4MpType::try_from(sub_type).unwrap();
                let add_path = matches!(
                    msg_type,
                    Bgp4MpType::MessageAddpath
                        | Bgp4MpType::MessageAs4Addpath
                        | Bgp4MpType::MessageLocalAddpath
                        | Bgp4MpType::MessageLocalAs4Addpath
                );
                let asn_len = match matches!(
                    msg_type,
                    Bgp4MpType::MessageAs4
                        | Bgp4MpType::MessageAs4Addpath
                        | Bgp4MpType::MessageLocalAs4Addpath
                        | Bgp4MpType::MessageAs4Local
                ) {
                    true => AsnLength::Bits32,
                    false => AsnLength::Bits16,
                };

                match m {
                    Bgp4Mp::StateChange(msg) => {
                        let asn_len = match matches!(msg_type, Bgp4MpType::StateChangeAs4) {
                            true => AsnLength::Bits32,
                            false => AsnLength::Bits16,
                        };
                        msg.encode(asn_len)
                    }
                    Bgp4Mp::Message(msg) => msg.encode(add_path, asn_len),
                }
            }
        };

        msg_bytes
    }
}
