use super::mrt_header::parse_common_header;
use crate::error::ParserError;
use crate::models::*;
use crate::parser::{
    parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message, ParserErrorWithBytes,
};
use bytes::{BufMut, Bytes, BytesMut};
use std::convert::TryFrom;
use std::io::Read;

pub fn parse_mrt_record(input: &mut impl Read) -> Result<MrtRecord, ParserErrorWithBytes> {
    // parse common header
    let common_header = match parse_common_header(input) {
        Ok(v) => v,
        Err(e) => {
            if let ParserError::EofError(e) = &e {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Err(ParserErrorWithBytes::from(ParserError::EofExpected));
                }
            }
            return Err(ParserErrorWithBytes {
                error: e,
                bytes: None,
            });
        }
    };

    // read the whole message bytes to buffer
    let mut buffer = BytesMut::with_capacity(common_header.length as usize);
    buffer.resize(common_header.length as usize, 0);
    match input
        .take(common_header.length as u64)
        .read_exact(&mut buffer)
    {
        Ok(_) => {}
        Err(e) => {
            return Err(ParserErrorWithBytes {
                error: ParserError::IoError(e),
                bytes: None,
            })
        }
    }

    match parse_mrt_body(
        common_header.entry_type as u16,
        common_header.entry_subtype,
        buffer.freeze(), // freeze the BytesMute to Bytes
    ) {
        Ok(message) => Ok(MrtRecord {
            common_header,
            message,
        }),
        Err(e) => {
            // TODO: find more efficient way to preserve the bytes during error
            // let mut total_bytes = vec![];
            // if common_header.write_header(&mut total_bytes).is_err() {
            //     unreachable!("Vec<u8> will never produce errors when used as a std::io::Write")
            // }

            // total_bytes.extend(buffer);
            // Err(ParserErrorWithBytes {
            //     error: e,
            //     bytes: Some(total_bytes),
            // })
            Err(ParserErrorWithBytes {
                error: e,
                bytes: None,
            })
        }
    }
}

/// Parse MRT message body with given entry type and subtype.
///
/// The entry type and subtype are parsed from the common header. The message body is parsed
/// according to the entry type and subtype. The message body is the remaining bytes after the
/// common header. The length of the message body is also parsed from the common header.
pub fn parse_mrt_body(
    entry_type: u16,
    entry_subtype: u16,
    data: Bytes,
) -> Result<MrtMessage, ParserError> {
    let etype = EntryType::try_from(entry_type)?;

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

impl MrtRecord {
    pub fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        let header_bytes = self.common_header.encode();
        let message_bytes = self.message.encode(self.common_header.entry_subtype);

        // // debug begins
        // let parsed_body = parse_mrt_body(
        //     self.common_header.entry_type as u16,
        //     self.common_header.entry_subtype,
        //     message_bytes.clone(),
        // )
        // .unwrap();
        // assert!(self.message == parsed_body);
        // // debug ends

        bytes.put_slice(&header_bytes);
        bytes.put_slice(&message_bytes);
        bytes.freeze()
    }
}
