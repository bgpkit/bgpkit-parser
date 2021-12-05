use std::io::{ErrorKind, Read};
use bgp_models::mrt::{CommonHeader, EntryType, MrtMessage, MrtRecord};
use byteorder::{BigEndian, ReadBytesExt};
use crate::parser::{parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message, ParserError};
use crate::error::ParserErrorKind;
use crate::parser::ReadUtils;
use crate::num_traits::FromPrimitive;

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
pub fn parse_common_header<T: std::io::Read>(input: &mut T) -> Result<(Vec<u8>, CommonHeader), ParserErrorKind> {
    let timestamp = match input.read_32b() {
        Ok(t) => {t}
        Err(e) => {
            return match e.kind() {
                ErrorKind::UnexpectedEof => {
                    Err(ParserErrorKind::EofExpected)
                }
                _ => {
                    Err(ParserErrorKind::from(e))
                }
            }
        }
    };

    let entry_type_raw = input.read_16b()?;
    let entry_type = match EntryType::from_u16(entry_type_raw) {
        Some(t) => Ok(t),
        None => Err(ParserErrorKind::ParseError(
            format!("Failed to parse entry type: {}", entry_type_raw),
        )),
    }?;
    let entry_subtype = input.read_u16::<BigEndian>()?;
    let mut length = input.read_u32::<BigEndian>()?;
    let microsecond_timestamp = match &entry_type {
        EntryType::BGP4MP_ET => {
            length -= 4;
            Some(input.read_u32::<BigEndian>()?)

        },
        _ => None,
    };
    let mut bytes: Vec<u8> = vec![];
    bytes.extend(timestamp.to_be_bytes());
    bytes.extend(entry_type_raw.to_be_bytes());
    bytes.extend(entry_subtype.to_be_bytes());
    bytes.extend(length.to_be_bytes());
    if let Some(mt) = &microsecond_timestamp {
        bytes.extend(mt.to_be_bytes());
    }
    Ok((bytes, CommonHeader {
        timestamp,
        microsecond_timestamp,
        entry_type,
        entry_subtype,
        length,
    }))
}

pub fn parse_mrt_record<T: Read>(input: &mut T) -> Result<MrtRecord, ParserError> {
    // parse common header
    let (header_bytes, common_header) = match parse_common_header(input){
        Ok(v) => v,
        Err(e) => return Err(ParserError{error: e, bytes: None})
    };

    // read the whole message bytes to buffer
    let mut buffer = Vec::with_capacity(common_header.length as usize);
    match input.take(common_header.length as u64).read_to_end(&mut buffer) {
        Ok(_) => {}
        Err(e) => return Err(ParserError{error: ParserErrorKind::IoError(e), bytes: None})
    }

    match parse_raw_bytes(&common_header, &buffer) {
        Ok(message) => {
            Ok(MrtRecord {
                common_header,
                message,
            })
        },
        Err(e) => {
            let mut total_bytes = vec![];
            total_bytes.extend(header_bytes);
            total_bytes.extend(buffer);
            Err(ParserError{ error: e, bytes: Some(total_bytes) })
        }
    }
}

fn parse_raw_bytes(common_header: &CommonHeader, data: &Vec<u8>) -> Result<MrtMessage, ParserErrorKind>{
    let total_len = data.len();
    let message: MrtMessage = match &common_header.entry_type {
        EntryType::TABLE_DUMP => {
            let msg = parse_table_dump_message(common_header.entry_subtype,&mut data.as_slice());
            match msg {
                Ok(msg) => MrtMessage::TableDumpMessage(msg),
                Err(e) => {
                    dbg!(&e);
                    return Err(e);
                }
            }
        }
        EntryType::TABLE_DUMP_V2 => {
            let msg = parse_table_dump_v2_message(common_header.entry_subtype, &mut data.as_slice().take(total_len as u64));
            match msg {
                Ok(msg) => MrtMessage::TableDumpV2Message(msg),
                Err(e) => {
                    return Err(e);
                }
            }
        }
        EntryType::BGP4MP|EntryType::BGP4MP_ET => {
            let msg = parse_bgp4mp(common_header.entry_subtype, &mut data.as_slice(), total_len);
            match msg {
                Ok(msg) => MrtMessage::Bgp4Mp(msg),
                Err(e) => {
                    return Err(e);
                }
            }
        }
        v => {
            // deprecated
            dbg!(common_header);
            return Err(ParserErrorKind::Unsupported(format!("unsupported MRT type: {:?}", v)))
        }
    };
    Ok(message)
}

