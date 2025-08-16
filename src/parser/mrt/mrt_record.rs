use super::mrt_header::parse_common_header;
use crate::bmp::messages::{BmpMessage, BmpMessageBody};
use crate::error::ParserError;
use crate::models::*;
use crate::parser::{
    parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message, ParserErrorWithBytes,
};
use crate::utils::convert_timestamp;
use bytes::{BufMut, Bytes, BytesMut};
use log::warn;
use std::convert::TryFrom;
use std::io::Read;
use std::net::IpAddr;
use std::str::FromStr;

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
    let mut buffer = BytesMut::zeroed(common_header.length as usize);
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

    match parse_mrt_body(
        common_header.entry_type as u16,
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

/// Parse MRT message body with given entry type and subtype.
///
/// The entry type and subtype are parsed from the common header. The message body is parsed
/// according to the entry type and subtype. The message body is the remaining bytes after the
/// common header. The length of the message body is also parsed from the common header.
pub fn parse_mrt_body(
    entry_type: u16,
    entry_subtype: u16,
    data: Bytes,
) -> Result<MrtMessage, ParserError> {
    let etype = EntryType::try_from(entry_type)?;

    let message: MrtMessage = match &etype {
        EntryType::TABLE_DUMP => {
            let msg = parse_table_dump_message(entry_subtype, data);
            match msg {
                Ok(msg) => MrtMessage::TableDumpMessage(msg),
                Err(e) => {
                    return Err(e);
                }
            }
        }
        EntryType::TABLE_DUMP_V2 => {
            let msg = parse_table_dump_v2_message(entry_subtype, data);
            match msg {
                Ok(msg) => MrtMessage::TableDumpV2Message(msg),
                Err(e) => {
                    return Err(e);
                }
            }
        }
        EntryType::BGP4MP | EntryType::BGP4MP_ET => {
            let msg = parse_bgp4mp(entry_subtype, data);
            match msg {
                Ok(msg) => MrtMessage::Bgp4Mp(msg),
                Err(e) => {
                    return Err(e);
                }
            }
        }
        v => {
            // deprecated
            return Err(ParserError::Unsupported(format!(
                "unsupported MRT type: {v:?}"
            )));
        }
    };
    Ok(message)
}

impl MrtRecord {
    pub fn encode(&self) -> Bytes {
        let message_bytes = self.message.encode(self.common_header.entry_subtype);
        let mut new_header = self.common_header;
        if message_bytes.len() < new_header.length as usize {
            warn!("message length is less than the length in the header");
            new_header.length = message_bytes.len() as u32;
        }
        let header_bytes = new_header.encode();

        // // debug begins
        // let parsed_body = parse_mrt_body(
        //     self.common_header.entry_type as u16,
        //     self.common_header.entry_subtype,
        //     message_bytes.clone(),
        // )
        // .unwrap();
        // assert!(self.message == parsed_body);
        // // debug ends

        let mut bytes = BytesMut::with_capacity(header_bytes.len() + message_bytes.len());
        bytes.put_slice(&header_bytes);
        bytes.put_slice(&message_bytes);
        bytes.freeze()
    }
}

impl TryFrom<&BmpMessage> for MrtRecord {
    type Error = String;

    fn try_from(bmp_message: &BmpMessage) -> Result<Self, Self::Error> {
        let bgp_message = match &bmp_message.message_body {
            BmpMessageBody::RouteMonitoring(m) => &m.bgp_message,
            _ => return Err("unsupported bmp message type".to_string()),
        };
        let bmp_header = match &bmp_message.per_peer_header {
            Some(h) => h,
            None => return Err("missing per peer header".to_string()),
        };

        let local_ip = match bmp_header.peer_ip {
            IpAddr::V4(_) => IpAddr::from_str("0.0.0.0").unwrap(),
            IpAddr::V6(_) => IpAddr::from_str("::").unwrap(),
        };
        let local_asn = match bmp_header.peer_asn.is_four_byte() {
            true => Asn::new_32bit(0),
            false => Asn::new_16bit(0),
        };

        let bgp4mp_message = Bgp4MpMessage {
            msg_type: Bgp4MpType::MessageAs4, // TODO: check Message or MessageAs4
            peer_asn: bmp_header.peer_asn,
            local_asn,
            interface_index: 0,
            peer_ip: bmp_header.peer_ip,
            local_ip,
            bgp_message: bgp_message.clone(),
        };

        let mrt_message = MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(bgp4mp_message));

        let (seconds, microseconds) = convert_timestamp(bmp_header.timestamp);

        let subtype = Bgp4MpType::MessageAs4 as u16;
        let mrt_header = CommonHeader {
            timestamp: seconds,
            microsecond_timestamp: Some(microseconds),
            entry_type: EntryType::BGP4MP_ET,
            entry_subtype: Bgp4MpType::MessageAs4 as u16,
            length: mrt_message.encode(subtype).len() as u32,
        };

        Ok(MrtRecord {
            common_header: mrt_header,
            message: mrt_message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bmp::messages::headers::{BmpPeerType, PeerFlags, PerPeerFlags};
    use crate::bmp::messages::{BmpCommonHeader, BmpMsgType, BmpPerPeerHeader, RouteMonitoring};
    use std::net::Ipv4Addr;

    #[test]
    fn test_try_from_bmp_message() {
        let bmp_message = BmpMessage {
            common_header: BmpCommonHeader {
                version: 0,
                msg_len: 0,
                msg_type: BmpMsgType::RouteMonitoring,
            },
            per_peer_header: Some(BmpPerPeerHeader {
                peer_asn: Asn::new_32bit(0),
                peer_ip: IpAddr::from_str("10.0.0.1").unwrap(),
                peer_bgp_id: Ipv4Addr::from_str("10.0.0.2").unwrap(),
                timestamp: 0.0,
                peer_type: BmpPeerType::Global,
                peer_flags: PerPeerFlags::PeerFlags(PeerFlags::empty()),
                peer_distinguisher: 0,
            }),
            message_body: BmpMessageBody::RouteMonitoring(RouteMonitoring {
                bgp_message: BgpMessage::KeepAlive,
            }),
        };

        let mrt_record = MrtRecord::try_from(&bmp_message).unwrap();
        assert_eq!(mrt_record.common_header.entry_type, EntryType::BGP4MP_ET);
    }

    #[test]
    fn test_parse_mrt_body() {
        let mut data = BytesMut::new();
        data.put_u16(0);
        data.put_u16(0);
        data.put_u32(0);
        data.put_u16(0);

        let result = parse_mrt_body(0, 0, data.freeze());
        assert!(result.is_err());
    }
}
