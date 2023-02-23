use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use num_traits::FromPrimitive;
use std::io::Cursor;

#[derive(Debug)]
pub struct TerminationMessage {
    pub tlvs: Vec<TerminationTlv>,
}

#[derive(Debug)]
pub struct TerminationTlv {
    pub info_type: TerminationTlvType,
    pub info_len: u16,
    pub info: String,
}

///Type-Length-Value Type
///
/// For more, see: https://datatracker.ietf.org/doc/html/rfc1213
#[derive(Debug, Primitive)]
pub enum TerminationTlvType {
    String = 0,
    Reason = 1,
}

pub fn parse_termination_message(
    reader: &mut Cursor<&[u8]>,
) -> Result<TerminationMessage, ParserBmpError> {
    let mut tlvs = vec![];
    let total = reader.get_ref().len() as u64;

    while total - reader.position() > 4 {
        let info_type: TerminationTlvType =
            TerminationTlvType::from_u16(reader.read_16b()?).unwrap();
        let info_len = reader.read_16b()?;
        if total - reader.position() < info_len as u64 {
            // not enough bytes to read
            break;
        }
        let info = reader.read_n_bytes_to_string(info_len as usize)?;
        tlvs.push(TerminationTlv {
            info_type,
            info_len,
            info,
        })
    }

    Ok(TerminationMessage { tlvs })
}
