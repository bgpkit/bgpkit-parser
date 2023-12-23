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
#[derive(Debug, TryFromPrimitive, IntoPrimitive, PartialEq, Clone, Copy)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_parse_termination_message() {
        // Create a Bytes object to simulate the incoming data
        let mut data = Bytes::copy_from_slice(&[
            0, 0, // info_type: String
            0, 5, // info_len: 5
            67, 79, 68, 69, 83, // info: "CODES"
            0, 1, // info_type: Reason
            0, 4, // info_len: 4
            84, 69, 83, 84, // info: "TEST"
        ]);

        // Check if parse_termination_message correctly reads the data
        let result = parse_termination_message(&mut data);
        match result {
            Ok(termination_message) => {
                assert_eq!(termination_message.tlvs.len(), 2);

                // tlvs[0] assertions
                assert_eq!(
                    termination_message.tlvs[0].info_type,
                    TerminationTlvType::String
                );
                assert_eq!(termination_message.tlvs[0].info_len, 5);
                assert_eq!(termination_message.tlvs[0].info, "CODES");

                // tlvs[1] assertions
                assert_eq!(
                    termination_message.tlvs[1].info_type,
                    TerminationTlvType::Reason
                );
                assert_eq!(termination_message.tlvs[1].info_len, 4);
                assert_eq!(termination_message.tlvs[1].info, "TEST");
            }
            Err(e) => panic!("Failed to parse: {}", e),
        }
    }
}
