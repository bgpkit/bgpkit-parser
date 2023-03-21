use crate::error::ParserError;
use crate::parser::{
    parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message, ParserErrorWithBytes,
    ReadUtils,
};
use bgp_models::prelude::*;
use byteorder::{ReadBytesExt, BE};
use num_traits::FromPrimitive;
use std::io::{ErrorKind, Read};

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
    let timestamp = match input.read_32b() {
        Ok(t) => t,
        Err(e) => {
            return match e.kind() {
                ErrorKind::UnexpectedEof => Err(ParserError::EofExpected),
                _ => Err(ParserError::from(e)),
            }
        }
    };

    let entry_type_raw = input.read_u16::<BE>()?;
    let entry_type = match EntryType::from_u16(entry_type_raw) {
        Some(t) => Ok(t),
        None => Err(ParserError::ParseError(format!(
            "Failed to parse entry type: {}",
            entry_type_raw
        ))),
    }?;
    let entry_subtype = input.read_u16::<BE>()?;
    let mut length = input.read_32b()?;
    let microsecond_timestamp = match &entry_type {
        EntryType::BGP4MP_ET => {
            length -= 4;
            Some(input.read_32b()?)
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
            return Err(ParserErrorWithBytes {
                error: e,
                bytes: None,
            })
        }
    };

    // read the whole message bytes to buffer
    let mut buffer = Vec::with_capacity(common_header.length as usize);
    match input
        .take(common_header.length as u64)
        .read_to_end(&mut buffer)
    {
        Ok(_) => {}
        Err(e) => {
            return Err(ParserErrorWithBytes {
                error: ParserError::IoError(e),
                bytes: None,
            })
        }
    }

    match parse_raw_bytes(&common_header, buffer.as_slice()) {
        Ok(message) => Ok(MrtRecord {
            common_header,
            message,
        }),
        Err(e) => {
            let mut total_bytes = vec![];
            if common_header.write_header(&mut total_bytes).is_err() {
                unreachable!("Vec<u8> will never produce errors when used as a std::io::Write")
            }

            total_bytes.extend(buffer);
            Err(ParserErrorWithBytes {
                error: e,
                bytes: Some(total_bytes),
            })
        }
    }
}

fn parse_raw_bytes(common_header: &CommonHeader, data: &[u8]) -> Result<MrtMessage, ParserError> {
    let message: MrtMessage = match &common_header.entry_type {
        EntryType::TABLE_DUMP => {
            let msg = parse_table_dump_message(common_header.entry_subtype, data);
            match msg {
                Ok(msg) => MrtMessage::TableDumpMessage(msg),
                Err(e) => {
                    return Err(e);
                }
            }
        }
        EntryType::TABLE_DUMP_V2 => {
            let msg = parse_table_dump_v2_message(common_header.entry_subtype, data);
            match msg {
                Ok(msg) => MrtMessage::TableDumpV2Message(msg),
                Err(e) => {
                    return Err(e);
                }
            }
        }
        EntryType::BGP4MP | EntryType::BGP4MP_ET => {
            let msg = parse_bgp4mp(common_header.entry_subtype, data);
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
