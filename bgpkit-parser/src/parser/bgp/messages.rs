use crate::models::*;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_traits::FromPrimitive;

use crate::error::ParserError;
use crate::parser::{
    encode_ipaddr, encode_nlri_prefixes, parse_nlri_list, AttributeParser, ReadUtils,
};
use log::warn;

/// BGP message
///
/// Format:
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                                                               +
/// |                           Marker                              |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Length               |      Type     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn parse_bgp_message(
    data: &mut Bytes,
    add_path: bool,
    asn_len: &AsnLength,
) -> Result<BgpMessage, ParserError> {
    let total_size = data.len();
    data.has_n_remaining(19)?;
    data.advance(16);
    /*
    This 2-octet unsigned integer indicates the total length of the
    message, including the header in octets.  Thus, it allows one
    to locate the (Marker field of the) next message in the TCP
    stream.  The value of the Length field MUST always be at least
    19 and no greater than 4096, and MAY be further constrained,
    depending on the message type.  "padding" of extra data after
    the message is not allowed.  Therefore, the Length field MUST
    have the smallest value required, given the rest of the
    message.
    */
    let length = data.get_u16();
    if !(19..=4096).contains(&length) {
        return Err(ParserError::ParseError(format!(
            "invalid BGP message length {}",
            length
        )));
    }

    let bgp_msg_length = if (length as usize) > total_size {
        total_size - 19
    } else {
        length as usize - 19
    };

    let msg_type: BgpMessageType = match BgpMessageType::from_u8(data.get_u8()) {
        Some(t) => t,
        None => {
            return Err(ParserError::ParseError(
                "Unknown BGP Message Type".to_string(),
            ))
        }
    };

    if data.remaining() != bgp_msg_length {
        warn!(
            "BGP message length {} does not match the actual length {}",
            bgp_msg_length,
            data.remaining()
        );
    }
    let mut msg_data = data.split_to(bgp_msg_length);

    Ok(match msg_type {
        BgpMessageType::OPEN => BgpMessage::Open(parse_bgp_open_message(&mut msg_data)?),
        BgpMessageType::UPDATE => {
            BgpMessage::Update(parse_bgp_update_message(msg_data, add_path, asn_len)?)
        }
        BgpMessageType::NOTIFICATION => {
            BgpMessage::Notification(parse_bgp_notification_message(msg_data)?)
        }
        BgpMessageType::KEEPALIVE => BgpMessage::KeepAlive(BgpKeepAliveMessage {}),
    })
}

/// Parse BGP NOTIFICATION mrt_message.
///
/// The BGP NOTIFICATION mrt_message contains BGP error codes received from a connected BGP router. The
/// error code is parsed into [BgpError] data structure and any unknown codes will produce warning
/// mrt_message, but not critical errors.
pub fn parse_bgp_notification_message(
    mut input: Bytes,
) -> Result<BgpNotificationMessage, ParserError> {
    let total_bytes = input.len();
    let error_code = input.read_u8()?;
    let error_subcode = input.read_u8()?;
    let error_type = match parse_error_codes(&error_code, &error_subcode) {
        Ok(t) => Some(t),
        Err(e) => {
            warn!("error parsing BGP notification error code: {}", e);
            None
        }
    };

    let data = input.read_n_bytes(total_bytes - 2)?;
    Ok(BgpNotificationMessage {
        error_code,
        error_subcode,
        error_type,
        data,
    })
}

impl BgpNotificationMessage {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(self.error_code);
        buf.put_u8(self.error_subcode);
        buf.put_slice(&self.data);
        buf.freeze()
    }
}

/// Parse BGP OPEN mrt_message.
///
/// The parsing of BGP OPEN mrt_message also includes decoding the BGP capabilities.
pub fn parse_bgp_open_message(input: &mut Bytes) -> Result<BgpOpenMessage, ParserError> {
    input.has_n_remaining(10)?;
    let version = input.get_u8();
    let asn = Asn {
        asn: input.get_u16() as u32,
        len: AsnLength::Bits16,
    };
    let hold_time = input.get_u16();

    let sender_ip = input.read_ipv4_address()?;
    let opt_params_len = input.get_u8();

    // let pos_end = input.position() + opt_params_len as u64;
    if input.remaining() != opt_params_len as usize {
        warn!(
            "BGP open message length {} does not match the actual length {}",
            opt_params_len,
            input.remaining()
        );
    }

    let mut extended_length = false;
    let mut first = true;

    let mut params: Vec<OptParam> = vec![];
    while input.remaining() >= 2 {
        let param_type = input.get_u8();
        if first {
            // first parameter, check if it is extended length message
            if opt_params_len == 255 && param_type == 255 {
                extended_length = true;
                // TODO: handle extended length
                break;
            } else {
                first = false;
            }
        }
        // reaching here means all the remain params are regular non-extended-length parameters

        let parm_length = input.get_u8();
        // https://tools.ietf.org/html/rfc3392
        // https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11

        let param_value = match param_type {
            2 => {
                // capability codes:
                // https://www.iana.org/assignments/capability-codes/capability-codes.xhtml#capability-codes-2
                let code = input.read_u8()?;
                let len = input.read_u8()?;
                let value = input.read_n_bytes(len as usize)?;

                let capability_type = match parse_capability(&code) {
                    Ok(t) => Some(t),
                    Err(e) => {
                        warn!("error parsing BGP capability code: {}", e.to_string());
                        None
                    }
                };

                ParamValue::Capability(Capability {
                    code,
                    len,
                    value,
                    capability_type,
                })
            }
            _ => {
                // unsupported param, read as raw bytes
                let bytes = input.read_n_bytes(parm_length as usize)?;
                ParamValue::Raw(bytes)
            }
        };
        params.push(OptParam {
            param_type,
            param_len: parm_length as u16,
            param_value,
        });
    }

    Ok(BgpOpenMessage {
        version,
        asn,
        hold_time,
        sender_ip,
        extended_length,
        opt_params: params,
    })
}

impl BgpOpenMessage {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(self.version);
        buf.put_u16(self.asn.asn as u16);
        buf.put_u16(self.hold_time);
        buf.extend(encode_ipaddr(&self.sender_ip.into()));
        buf.put_u8(self.opt_params.len() as u8);
        for param in &self.opt_params {
            buf.put_u8(param.param_type);
            buf.put_u8(param.param_len as u8);
            match &param.param_value {
                ParamValue::Capability(cap) => {
                    buf.put_u8(cap.code);
                    buf.put_u8(cap.len);
                    buf.extend(&cap.value);
                }
                ParamValue::Raw(bytes) => {
                    buf.extend(bytes);
                }
            }
        }
        buf.freeze()
    }
}

/// read nlri portion of a bgp update message.
fn read_nlri(
    mut input: Bytes,
    afi: &Afi,
    add_path: bool,
) -> Result<Vec<NetworkPrefix>, ParserError> {
    let length = input.len();
    if length == 0 {
        return Ok(vec![]);
    }
    if length == 1 {
        // 1 byte does not make sense
        warn!("seeing strange one-byte NLRI field");
        input.advance(1); // skip the byte
        return Ok(vec![]);
    }

    parse_nlri_list(input, add_path, afi)
}

/// read bgp update message.
///
/// RFC: https://tools.ietf.org/html/rfc4271#section-4.3
pub fn parse_bgp_update_message(
    mut input: Bytes,
    add_path: bool,
    asn_len: &AsnLength,
) -> Result<BgpUpdateMessage, ParserError> {
    // AFI for routes out side attributes are IPv4 ONLY.
    let afi = Afi::Ipv4;

    // parse withdrawn prefixes nlri
    let withdrawn_bytes_length = input.read_u16()? as usize;
    let withdrawn_bytes = input.split_to(withdrawn_bytes_length);
    let withdrawn_prefixes = read_nlri(withdrawn_bytes, &afi, add_path)?;

    // parse attributes
    let attribute_length = input.read_u16()? as usize;
    let attr_parser = AttributeParser::new(add_path);

    input.has_n_remaining(attribute_length)?;
    let attr_data_slice = input.split_to(attribute_length);
    let attributes = attr_parser.parse_attributes(attr_data_slice, asn_len, None, None, None)?;

    // parse announced prefixes nlri.
    // the remaining bytes are announced prefixes.
    let announced_prefixes = read_nlri(input, &afi, add_path)?;

    Ok(BgpUpdateMessage {
        withdrawn_prefixes,
        attributes,
        announced_prefixes,
    })
}

impl BgpUpdateMessage {
    pub fn encode(&self, add_path: bool, asn_len: AsnLength) -> Bytes {
        let mut bytes = BytesMut::new();

        // withdrawn prefixes
        let withdrawn_bytes = encode_nlri_prefixes(&self.withdrawn_prefixes, add_path);
        bytes.put_u16(withdrawn_bytes.len() as u16);
        bytes.put_slice(&withdrawn_bytes);

        // attributes
        let mut attr_bytes = BytesMut::new();
        for attribute in &self.attributes {
            attr_bytes.extend(&attribute.encode(add_path, asn_len));
        }

        bytes.put_u16(attr_bytes.len() as u16);
        bytes.put_slice(&attr_bytes);

        bytes.extend(encode_nlri_prefixes(&self.announced_prefixes, add_path));
        bytes.freeze()
    }
}

impl BgpMessage {
    pub fn encode(&self, add_path: bool, asn_len: AsnLength) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put_u32(0); // marker
        bytes.put_u32(0); // marker
        bytes.put_u32(0); // marker
        bytes.put_u32(0); // marker

        let (msg_type, msg_bytes) = match self {
            BgpMessage::Open(msg) => (BgpMessageType::OPEN, msg.encode()),
            BgpMessage::Update(msg) => (BgpMessageType::UPDATE, msg.encode(add_path, asn_len)),
            BgpMessage::Notification(msg) => (BgpMessageType::NOTIFICATION, msg.encode()),
            BgpMessage::KeepAlive(_) => (BgpMessageType::KEEPALIVE, Bytes::new()),
        };

        // msg total bytes length = msg bytes + 16 bytes marker + 2 bytes length + 1 byte type
        bytes.put_u16(msg_bytes.len() as u16 + 16 + 2 + 1);
        bytes.put_u8(msg_type as u8);
        bytes.put_slice(&msg_bytes);
        bytes.freeze()
    }
}
