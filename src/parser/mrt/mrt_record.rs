use super::messages::parse_mrt_message;
use super::mrt_header::parse_common_header;
use crate::error::ParserError;
use crate::models::*;
use crate::parser::ParserErrorWithBytes;
use bytes::{BufMut, Bytes, BytesMut};
use num_traits::ToPrimitive;
use std::io::Read;

pub fn parse_mrt_record(input: &mut impl Read) -> Result<MrtRecord, ParserErrorWithBytes> {
    // parse common header
    let common_header = match parse_common_header(input) {
        Ok(v) => v,
        Err(e) => {
            if let ParserError::EofError(e) = &e {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Err(ParserErrorWithBytes::from(ParserError::EofExpected));
                }
            }
            return Err(ParserErrorWithBytes {
                error: e,
                bytes: None,
            });
        }
    };

    // read the whole message bytes to buffer
    let mut buffer = BytesMut::with_capacity(common_header.length as usize);
    buffer.resize(common_header.length as usize, 0);
    match input
        .take(common_header.length as u64)
        .read_exact(&mut buffer)
    {
        Ok(_) => {}
        Err(e) => {
            return Err(ParserErrorWithBytes {
                error: ParserError::IoError(e),
                bytes: None,
            })
        }
    }

    match parse_mrt_message(
        common_header.entry_type.to_u16().unwrap(),
        common_header.entry_subtype,
        buffer.freeze(), // freeze the BytesMute to Bytes
    ) {
        Ok(message) => Ok(MrtRecord {
            common_header,
            message,
        }),
        Err(e) => {
            // TODO: find more efficient way to preserve the bytes during error
            // let mut total_bytes = vec![];
            // if common_header.write_header(&mut total_bytes).is_err() {
            //     unreachable!("Vec<u8> will never produce errors when used as a std::io::Write")
            // }

            // total_bytes.extend(buffer);
            // Err(ParserErrorWithBytes {
            //     error: e,
            //     bytes: Some(total_bytes),
            // })
            Err(ParserErrorWithBytes {
                error: e,
                bytes: None,
            })
        }
    }
}

impl MrtRecord {
    pub fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        let header_bytes = self.common_header.encode();
        let message_bytes = self.message.encode(self.common_header.entry_subtype);
        // let parsed_body = crate::parser::mrt::mrt_record::parse_mrt_body(
        //     self.common_header.entry_type as u16,
        //     self.common_header.entry_subtype,
        //     message_bytes.clone(),
        // )
        // .unwrap();
        // assert!(self.message == parsed_body);
        bytes.put_slice(&header_bytes);
        bytes.put_slice(&message_bytes);
        bytes.freeze()
    }
}
