use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::convert::TryFrom;

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
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum InitiationTlvType {
    String = 0,
    SysDescr = 1,
    SysName = 2,
}

pub fn parse_initiation_message(data: &mut &[u8]) -> Result<InitiationMessage, ParserBmpError> {
    let mut tlvs = vec![];

    while data.remaining() > 4 {
        let info_type: InitiationTlvType = InitiationTlvType::try_from(data.read_u16()?)?;
        let info_len = data.read_u16()?;
        if data.remaining() < info_len as usize {
            // not enough bytes to read
            break;
        }
        let info = data.read_n_bytes_to_string(info_len as usize)?;
        tlvs.push(InitiationTlv {
            info_type,
            info_len,
            info,
        });
    }

    Ok(InitiationMessage { tlvs })
}
