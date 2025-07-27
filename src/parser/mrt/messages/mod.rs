use crate::models::{AsnLength, Bgp4MpEnum, Bgp4MpType, MrtMessage, TableDumpV2Message};
use bytes::Bytes;

pub(crate) mod bgp4mp;
pub(crate) mod table_dump;
pub(crate) mod table_dump_v2;

impl MrtMessage {
    pub fn encode(&self, sub_type: u16) -> Bytes {
        let msg_bytes: Bytes = match self {
            MrtMessage::TableDumpMessage(m) => m.encode(),
            MrtMessage::TableDumpV2Message(m) => match m {
                TableDumpV2Message::PeerIndexTable(p) => p.encode(),
                TableDumpV2Message::RibAfi(r) => r.encode(),
                TableDumpV2Message::RibGeneric(_) => {
                    todo!("RibGeneric message is not supported yet");
                }
            },
            MrtMessage::Bgp4Mp(m) => {
                let msg_type = Bgp4MpType::try_from(sub_type).unwrap();

                match m {
                    Bgp4MpEnum::StateChange(msg) => {
                        let asn_len = match matches!(msg_type, Bgp4MpType::StateChangeAs4) {
                            true => AsnLength::Bits32,
                            false => AsnLength::Bits16,
                        };
                        msg.encode(asn_len)
                    }
                    Bgp4MpEnum::Message(msg) => {
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
                        msg.encode(asn_len)
                    }
                }
            }
        };

        msg_bytes
    }
}
