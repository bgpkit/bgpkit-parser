use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bytes::{Buf, Bytes};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::convert::TryFrom;

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
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum TerminationTlvType {
    String = 0,
    Reason = 1,
}

pub fn parse_termination_message(data: &mut Bytes) -> Result<TerminationMessage, ParserBmpError> {
    let mut tlvs = vec![];

    while data.remaining() > 4 {
        let info_type: TerminationTlvType = TerminationTlvType::try_from(data.read_u16()?)?;
        let info_len = data.read_u16()?;
        if data.remaining() < info_len as usize {
            // not enough bytes to read
            break;
        }
        let info = data.read_n_bytes_to_string(info_len as usize)?;
        tlvs.push(TerminationTlv {
            info_type,
            info_len,
            info,
        })
    }

    Ok(TerminationMessage { tlvs })
}
