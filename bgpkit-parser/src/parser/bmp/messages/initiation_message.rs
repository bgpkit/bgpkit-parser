use crate::parser::bmp::error::ParserBmpError;
use num_traits::FromPrimitive;
use crate::parser::DataBytes;

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

pub fn parse_initiation_message(reader: &mut DataBytes) -> Result<InitiationMessage, ParserBmpError> {
    let mut tlvs = vec![];

    while reader.bytes_left() > 4 {
        let info_type: InitiationTlvType = InitiationTlvType::from_u16(reader.read_16b()?).unwrap();
        let info_len = reader.read_16b()?;
        if reader.bytes_left() < info_len as usize {
            // not enough bytes to read
            break
        }
        let info = reader.read_n_bytes_to_string(info_len as usize)?;
        tlvs.push(
            InitiationTlv {
                info_type,
                info_len,
                info,
            }
        );
    }

    Ok(InitiationMessage{ tlvs })
}