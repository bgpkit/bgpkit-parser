use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use num_traits::FromPrimitive;
use std::io::Cursor;

#[derive(Debug)]
pub struct InitiationMessage {
    pub tlvs: Vec<InitiationTlv>,
}

#[derive(Debug)]
pub struct InitiationTlv {
    pub info_type: InitiationTlvType,
    pub info_len: u16,
    pub info: String,
}

///Type-Length-Value Type
///
/// For more, see: https://datatracker.ietf.org/doc/html/rfc1213
#[derive(Debug, Primitive)]
pub enum InitiationTlvType {
    String = 0,
    SysDescr = 1,
    SysName = 2,
}

pub fn parse_initiation_message(
    reader: &mut Cursor<&[u8]>,
) -> Result<InitiationMessage, ParserBmpError> {
    let mut tlvs = vec![];
    let total = reader.get_ref().len() as u64;

    while total - reader.position() > 4 {
        let info_type: InitiationTlvType = InitiationTlvType::from_u16(reader.read_16b()?).unwrap();
        let info_len = reader.read_16b()?;
        if total - reader.position() < info_len as u64 {
            // not enough bytes to read
            break;
        }
        let info = reader.read_n_bytes_to_string(info_len as usize)?;
        tlvs.push(InitiationTlv {
            info_type,
            info_len,
            info,
        });
    }

    Ok(InitiationMessage { tlvs })
}
