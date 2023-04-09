use crate::error::ParserError;
use crate::models::*;
use crate::parser::{
    parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message, ParserErrorWithBytes,
};
use bytes::{Buf, Bytes, BytesMut};
use num_traits::{FromPrimitive, ToPrimitive};
use std::io::Read;

/// MRT common header
///
/// A MRT record is constructed as the following:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Type              |            Subtype            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Length                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Message... (variable)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ```
///
/// Or with extended timestamp:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Type              |            Subtype            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Length                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Microsecond Timestamp                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Message... (variable)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn parse_common_header<T: Read>(input: &mut T) -> Result<CommonHeader, ParserError> {
    let mut raw_bytes = [0u8; 12];
    input.read_exact(&mut raw_bytes)?;
    let mut data = BytesMut::from(&raw_bytes[..]);

    let timestamp = data.get_u32();
    let entry_type_raw = data.get_u16();
    let entry_type = EntryType::from_u16(entry_type_raw).ok_or_else(|| {
        ParserError::ParseError(format!("Failed to parse entry type: {}", entry_type_raw))
    })?;
    let entry_subtype = data.get_u16();
    let mut length = data.get_u32();

    let microsecond_timestamp = match &entry_type {
        EntryType::BGP4MP_ET => {
            length -= 4;
            let mut raw_bytes: [u8; 4] = [0; 4];
            input.read_exact(&mut raw_bytes)?;
            Some(BytesMut::from(&raw_bytes[..]).get_u32())
        }
        _ => None,
    };

    Ok(CommonHeader {
        timestamp,
        microsecond_timestamp,
        entry_type,
        entry_subtype,
        length,
    })
}

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
        common_header.entry_type.to_u16().unwrap(),
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
fn parse_mrt_body(
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
