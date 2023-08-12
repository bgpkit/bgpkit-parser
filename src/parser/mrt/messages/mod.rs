use crate::models::{AsnLength, Bgp4Mp, Bgp4MpType, EntryType, MrtMessage};
use crate::parser::{parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message};
use crate::ParserError;
use bytes::Bytes;
use num_traits::FromPrimitive;

pub(crate) mod bgp4mp;
pub(crate) mod table_dump_message;
pub(crate) mod table_dump_v2_message;

/// Parse MRT message body with given entry type and subtype.
///
/// The entry type and subtype are parsed from the common header. The message body is parsed
/// according to the entry type and subtype. The message body is the remaining bytes after the
/// common header. The length of the message body is also parsed from the common header.
pub fn parse_mrt_message(
    entry_type: u16,
    entry_subtype: u16,
    data: Bytes,
) -> Result<MrtMessage, ParserError> {
    let etype = match EntryType::from_u16(entry_type) {
        Some(t) => Ok(t),
        None => Err(ParserError::ParseError(format!(
            "Failed to parse entry type: {}",
            entry_type
        ))),
    }?;

    let message: MrtMessage = match &etype {
        EntryType::TABLE_DUMP => {
            let msg = parse_table_dump_message(entry_subtype, data);
            match msg {
                Ok(msg) => MrtMessage::TableDumpMessage(msg),
                Err(e) => {
                    return Err(e);
                }
            }
        }
        EntryType::TABLE_DUMP_V2 => {
            let msg = parse_table_dump_v2_message(entry_subtype, data);
            match msg {
                Ok(msg) => MrtMessage::TableDumpV2Message(msg),
                Err(e) => {
                    return Err(e);
                }
            }
        }
        EntryType::BGP4MP | EntryType::BGP4MP_ET => {
            let msg = parse_bgp4mp(entry_subtype, data);
            match msg {
                Ok(msg) => MrtMessage::Bgp4Mp(msg),
                Err(e) => {
                    return Err(e);
                }
            }
        }
        v => {
            // deprecated
            return Err(ParserError::Unsupported(format!(
                "unsupported MRT type: {:?}",
                v
            )));
        }
    };
    Ok(message)
}

impl MrtMessage {
    pub fn encode(&self, sub_type: u16) -> Bytes {
        let msg_bytes: Bytes = match self {
            MrtMessage::TableDumpMessage(_m) => {
                todo!("TableDump message is not supported yet");
            }
            MrtMessage::TableDumpV2Message(_m) => {
                todo!("TableDumpV2 message is not supported yet");
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
