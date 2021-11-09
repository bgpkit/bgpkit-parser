use std::io::Read;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use crate::num_traits::FromPrimitive;

#[derive(Debug)]
pub struct TerminationMessage {
    pub tlvs: Vec<TerminationTlv>
}

#[derive(Debug)]
pub struct TerminationTlv {
    pub info_type: TerminationTlvType,
    pub info_len: u16,
    pub info: String
}

///Type-Length-Value Type
///
/// For more, see: https://datatracker.ietf.org/doc/html/rfc1213
#[derive(Debug, Primitive)]
pub enum TerminationTlvType {
    String=0,
    Reason=1,
}

pub fn parse_termination_message<T: Read>(reader: &mut T, total_len: u64) -> Result<TerminationMessage, ParserBmpError> {
    let mut read_count = 0;
    let mut tlvs = vec![];

    while total_len - read_count > 4 {
        let info_type: TerminationTlvType = TerminationTlvType::from_u16(reader.read_16b()?).unwrap();
        let info_len = reader.read_16b()?;
        read_count += 4;
        if total_len - read_count < info_len as u64 {
            // not enough bytes to read
            break
        }
        let info = reader.read_n_bytes_to_string(info_len as u64)?;
        tlvs.push(
            TerminationTlv {
                info_type,
                info_len,
                info,
            }
        )
    }

    Ok(TerminationMessage{ tlvs })
}
