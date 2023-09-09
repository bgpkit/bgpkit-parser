use crate::error::ParserError;
use crate::models::*;
use crate::parser::{
    parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message, ReadUtils,
};
use bytes::{Bytes, BytesMut};
use std::convert::TryFrom;
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

    let timestamp = data.read_u32()?;
    let entry_type_raw = data.read_u16()?;
    let entry_type = match EntryType::try_from(entry_type_raw) {
        Ok(v) => v,
        Err(_) => return Err(ParserError::UnrecognizedMrtType(entry_type_raw)),
    };
    let entry_subtype = data.read_u16()?;
    let mut length = data.read_u32()?;

    let microsecond_timestamp = match &entry_type {
        EntryType::BGP4MP_ET => {
            // TODO: Error if length < 4
            length -= 4;
            let mut raw_bytes: [u8; 4] = [0; 4];
            input.read_exact(&mut raw_bytes)?;
            Some(BytesMut::from(&raw_bytes[..]).read_u32()?)
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

/// An alternative to [parse_common_header] which returns `None` if the end of the file is reached
/// upon beginning to read the header.
pub fn try_parse_common_header<T: Read>(
    input: &mut T,
) -> Result<Option<CommonHeader>, ParserError> {
    let mut first_byte = [0];
    match input.read(&mut first_byte)? {
        0 => Ok(None),
        1 => {
            let mut reader = &first_byte[..];
            parse_common_header(&mut Read::chain(&mut reader, input)).map(Some)
        }
        _ => unreachable!("Can only read 0 or 1 bytes into buffer of length 1 "),
    }
}

pub fn try_parse_mrt_record<T: Read>(input: &mut T) -> Result<Option<MrtRecord>, ParserError> {
    // parse common header
    let common_header = match try_parse_common_header(input)? {
        Some(v) => v,
        None => return Ok(None),
    };

    // read the whole message bytes to buffer
    let mut buffer = BytesMut::zeroed(common_header.length as usize);
    input.read_exact(&mut buffer)?;

    let message = parse_mrt_body(
        common_header.entry_type,
        common_header.entry_subtype,
        buffer.freeze(), // freeze the BytesMute to Bytes
    )?;

    Ok(Some(MrtRecord {
        common_header,
        message,
    }))
}

pub fn parse_mrt_record<T: Read>(input: &mut T) -> Result<MrtRecord, ParserError> {
    // parse common header
    let common_header = parse_common_header(input)?;

    // read the whole message bytes to buffer
    let mut buffer = BytesMut::zeroed(common_header.length as usize);
    input.read_exact(&mut buffer)?;

    let message = parse_mrt_body(
        common_header.entry_type,
        common_header.entry_subtype,
        buffer.freeze(), // freeze the BytesMute to Bytes
    )?;

    Ok(MrtRecord {
        common_header,
        message,
    })
}

/// Parse MRT message body with given entry type and subtype.
///
/// The entry type and subtype are parsed from the common header. The message body is parsed
/// according to the entry type and subtype. The message body is the remaining bytes after the
/// common header. The length of the message body is also parsed from the common header.
pub fn parse_mrt_body(
    entry_type: EntryType,
    entry_subtype: u16,
    data: Bytes,
) -> Result<MrtMessage, ParserError> {
    match entry_type {
        EntryType::TABLE_DUMP => {
            let msg = parse_table_dump_message(entry_subtype, data)?;
            Ok(MrtMessage::TableDumpMessage(msg))
        }
        EntryType::TABLE_DUMP_V2 => {
            let msg = parse_table_dump_v2_message(entry_subtype, data)?;
            Ok(MrtMessage::TableDumpV2Message(msg))
        }
        EntryType::BGP4MP | EntryType::BGP4MP_ET => {
            let msg = parse_bgp4mp(entry_subtype, data)?;
            Ok(MrtMessage::Bgp4Mp(msg))
        }
        mrt_type => {
            // deprecated
            Err(ParserError::UnsupportedMrtType {
                mrt_type,
                subtype: entry_subtype,
            })
        }
    }
}
