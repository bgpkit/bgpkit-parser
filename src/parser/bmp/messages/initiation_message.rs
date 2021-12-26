use std::io::Read;
use crate::parser::bmp::error::ParserBmpError;
use crate::num_traits::FromPrimitive;
use crate::parser::ReadUtils;

#[derive(Debug)]
pub struct InitiationMessage {
    pub tlvs: Vec<InitiationTlv>
}

#[derive(Debug)]
pub struct InitiationTlv {
    pub info_type: InitiationTlvType,
    pub info_len: u16,
    pub info: String
}

///Type-Length-Value Type
///
/// For more, see: https://datatracker.ietf.org/doc/html/rfc1213
#[derive(Debug, Primitive)]
pub enum InitiationTlvType {
    String=0,
    SysDescr=1,
    SysName=2,
}

pub fn parse_initiation_message<T: Read>(reader: &mut T, total_len: u64) -> Result<InitiationMessage, ParserBmpError> {
    let mut read_count = 0;
    let mut tlvs = vec![];

    while total_len - read_count > 4 {
        let info_type: InitiationTlvType = InitiationTlvType::from_u16(reader.read_16b()?).unwrap();
        let info_len = reader.read_16b()?;
        read_count += 4;
        if total_len - read_count < info_len as u64 {
            // not enough bytes to read
            break
        }
        let info = reader.read_n_bytes_to_string(info_len as u64)?;
        tlvs.push(
            InitiationTlv {
                info_type,
                info_len,
                info,
            }
        );
        read_count += info_len as u64;
    }

    Ok(InitiationMessage{ tlvs })
}