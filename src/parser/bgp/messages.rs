use crate::models::*;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryFrom;

use crate::error::ParserError;
use crate::models::capabilities::BgpCapabilityType;
use crate::models::error::BgpError;
use crate::parser::bgp::attributes::parse_attributes;
use crate::parser::{encode_ipaddr, encode_nlri_prefixes, parse_nlri_list, ReadUtils};
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

    let msg_type: BgpMessageType = match BgpMessageType::try_from(data.get_u8()) {
        Ok(t) => t,
        Err(_) => {
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
    data.has_n_remaining(bgp_msg_length)?;
    let mut msg_data = data.split_to(bgp_msg_length);

    Ok(match msg_type {
        BgpMessageType::OPEN => BgpMessage::Open(parse_bgp_open_message(&mut msg_data)?),
        BgpMessageType::UPDATE => {
            BgpMessage::Update(parse_bgp_update_message(msg_data, add_path, asn_len)?)
        }
        BgpMessageType::NOTIFICATION => {
            BgpMessage::Notification(parse_bgp_notification_message(msg_data)?)
        }
        BgpMessageType::KEEPALIVE => BgpMessage::KeepAlive,
    })
}

/// Parse BGP NOTIFICATION message.
///
/// The BGP NOTIFICATION messages contains BGP error codes received from a connected BGP router. The
/// error code is parsed into [BgpError] data structure and any unknown codes will produce warning
/// messages, but not critical errors.
///
pub fn parse_bgp_notification_message(
    mut input: Bytes,
) -> Result<BgpNotificationMessage, ParserError> {
    let error_code = input.read_u8()?;
    let error_subcode = input.read_u8()?;

    Ok(BgpNotificationMessage {
        error: BgpError::new(error_code, error_subcode),
        data: input.read_n_bytes(input.len())?,
    })
}

impl BgpNotificationMessage {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        let (code, subcode) = self.error.get_codes();
        buf.put_u8(code);
        buf.put_u8(subcode);
        buf.put_slice(&self.data);
        buf.freeze()
    }
}

/// Parse BGP OPEN message.
///
/// The parsing of BGP OPEN message also includes decoding the BGP capabilities.
pub fn parse_bgp_open_message(input: &mut Bytes) -> Result<BgpOpenMessage, ParserError> {
    input.has_n_remaining(10)?;
    let version = input.get_u8();
    let asn = Asn::new_16bit(input.get_u16());
    let hold_time = input.get_u16();

    let sender_ip = input.read_ipv4_address()?;
    let mut opt_params_len: u16 = input.get_u8() as u16;

    let mut extended_length = false;
    let mut first = true;

    let mut params: Vec<OptParam> = vec![];
    while input.remaining() >= 2 {
        let mut param_type = input.get_u8();
        if first {
            // first parameter, check if it is extended length message
            if opt_params_len == 255 && param_type == 255 {
                //
                // 0                   1                   2                   3
                // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                //     +-+-+-+-+-+-+-+-+
                //     |    Version    |
                //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                //     |     My Autonomous System      |
                //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                //     |           Hold Time           |
                //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                //     |                         BGP Identifier                        |
                //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                //     |Non-Ext OP Len.|Non-Ext OP Type|  Extended Opt. Parm. Length   |
                //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                //     |                                                               |
                //     |             Optional Parameters (variable)                    |
                //     |                                                               |
                //         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                //
                //         Figure 1: Extended Encoding OPEN Format
                extended_length = true;
                opt_params_len = input.read_u16()?;
                if opt_params_len == 0 {
                    break;
                }
                // let pos_end = input.position() + opt_params_len as u64;
                if input.remaining() != opt_params_len as usize {
                    warn!(
                        "BGP open message length {} does not match the actual length {}",
                        opt_params_len,
                        input.remaining()
                    );
                }

                param_type = input.read_u8()?;
            }
            first = false;
        }
        // reaching here means all the remain params are regular non-extended-length parameters

        let param_len = match extended_length {
            true => input.read_u16()?,
            false => input.read_u8()? as u16,
        };
        // https://tools.ietf.org/html/rfc3392
        // https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11

        let param_value = match param_type {
            2 => {
                // capability codes:
                // https://www.iana.org/assignments/capability-codes/capability-codes.xhtml#capability-codes-2
                let code = input.read_u8()?;
                let len = match extended_length {
                    true => input.read_u16()?,
                    false => input.read_u8()? as u16,
                };

                ParamValue::Capability(Capability {
                    ty: BgpCapabilityType::from(code),
                    value: input.read_n_bytes(len as usize)?,
                })
            }
            _ => {
                // unsupported param, read as raw bytes
                let bytes = input.read_n_bytes(param_len as usize)?;
                ParamValue::Raw(bytes)
            }
        };
        params.push(OptParam {
            param_type,
            param_len,
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
        buf.put_u16(self.asn.into());
        buf.put_u16(self.hold_time);
        buf.extend(encode_ipaddr(&self.sender_ip.into()));
        buf.put_u8(self.opt_params.len() as u8);
        for param in &self.opt_params {
            buf.put_u8(param.param_type);
            buf.put_u8(param.param_len as u8);
            match &param.param_value {
                ParamValue::Capability(cap) => {
                    buf.put_u8(cap.ty.into());
                    buf.put_u8(cap.value.len() as u8);
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
/// RFC: <https://tools.ietf.org/html/rfc4271#section-4.3>
pub fn parse_bgp_update_message(
    mut input: Bytes,
    add_path: bool,
    asn_len: &AsnLength,
) -> Result<BgpUpdateMessage, ParserError> {
    // NOTE: AFI for routes outside attributes are IPv4 ONLY.
    let afi = Afi::Ipv4;

    // parse withdrawn prefixes NLRI
    let withdrawn_bytes_length = input.read_u16()? as usize;
    input.has_n_remaining(withdrawn_bytes_length)?;
    let withdrawn_bytes = input.split_to(withdrawn_bytes_length);
    let withdrawn_prefixes = read_nlri(withdrawn_bytes, &afi, add_path)?;

    // parse attributes
    let attribute_length = input.read_u16()? as usize;

    input.has_n_remaining(attribute_length)?;
    let attr_data_slice = input.split_to(attribute_length);
    let attributes = parse_attributes(attr_data_slice, asn_len, add_path, None, None, None)?;

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
        let attr_bytes = self.attributes.encode(add_path, asn_len);

        bytes.put_u16(attr_bytes.len() as u16);
        bytes.put_slice(&attr_bytes);

        bytes.extend(encode_nlri_prefixes(&self.announced_prefixes, add_path));
        bytes.freeze()
    }

    /// Check if this is an end-of-rib message.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc4724#section-2>
    /// End-of-rib message is a special update message that contains no NLRI or withdrawal NLRI prefixes.
    pub fn is_end_of_rib(&self) -> bool {
        // there are two cases for end-of-rib message:
        // 1. IPv4 unicast address family: no announced, no withdrawn, no attributes
        // 2. Other cases: no announced, no withdrawal, only MP_UNREACH_NRLI with no prefixes

        if !self.announced_prefixes.is_empty() || !self.withdrawn_prefixes.is_empty() {
            // has announced or withdrawal IPv4 unicast prefixes:
            // definitely not end-of-rib

            return false;
        }

        if self.attributes.inner.is_empty() {
            // no attributes, no prefixes:
            // case 1 end-of-rib
            return true;
        }

        // has some attributes, it can only be withdrawal with no prefixes

        if self.attributes.inner.len() > 1 {
            // has more than one attributes, not end-of-rib
            return false;
        }

        // has only one attribute, check if it is withdrawal attribute
        if let AttributeValue::MpUnreachNlri(nlri) = &self.attributes.inner.first().unwrap().value {
            if nlri.prefixes.is_empty() {
                // the only attribute is MP_UNREACH_NLRI with no prefixes:
                // case 2 end-of-rib
                return true;
            }
        }

        // all other cases: not end-of-rib
        false
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
            BgpMessage::KeepAlive => (BgpMessageType::KEEPALIVE, Bytes::new()),
        };

        // msg total bytes length = msg bytes + 16 bytes marker + 2 bytes length + 1 byte type
        bytes.put_u16(msg_bytes.len() as u16 + 16 + 2 + 1);
        bytes.put_u8(msg_type as u8);
        bytes.put_slice(&msg_bytes);
        bytes.freeze()
    }
}

impl From<&BgpElem> for BgpUpdateMessage {
    fn from(elem: &BgpElem) -> Self {
        BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: Attributes::from(elem),
            announced_prefixes: vec![],
        }
    }
}

impl From<BgpUpdateMessage> for BgpMessage {
    fn from(value: BgpUpdateMessage) -> Self {
        BgpMessage::Update(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_end_of_rib() {
        // No prefixes and empty attributes: end-of-rib
        let attrs = Attributes::default();
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(msg.is_end_of_rib());

        // single MP_UNREACH_NLRI attribute with no prefixes: end-of-rib
        let attrs = Attributes::from_iter(vec![AttributeValue::MpUnreachNlri(Nlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: None,
            prefixes: vec![],
        })]);
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(msg.is_end_of_rib());

        // message with announced prefixes
        let prefix = NetworkPrefix::from_str("192.168.1.0/24").unwrap();
        let attrs = Attributes::default();
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![prefix],
        };
        assert!(!msg.is_end_of_rib());

        // message with withdrawn prefixes
        let prefix = NetworkPrefix::from_str("192.168.1.0/24").unwrap();
        let attrs = Attributes::default();
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![prefix],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(!msg.is_end_of_rib());

        // NLRI attribute with empty prefixes: NOT end-of-rib
        let attrs = Attributes::from_iter(vec![AttributeValue::MpReachNlri(Nlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: None,
            prefixes: vec![],
        })]);
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(!msg.is_end_of_rib());

        // NLRI attribute with non-empty prefixes
        let attrs = Attributes::from_iter(vec![AttributeValue::MpReachNlri(Nlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: None,
            prefixes: vec![prefix],
        })]);
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(!msg.is_end_of_rib());

        // Unreachable NLRI attribute with non-empty prefixes
        let attrs = Attributes::from_iter(vec![AttributeValue::MpUnreachNlri(Nlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: None,
            prefixes: vec![prefix],
        })]);
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(!msg.is_end_of_rib());

        // message with more than one attributes
        let attrs = Attributes::from_iter(vec![
            AttributeValue::MpUnreachNlri(Nlri {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                next_hop: None,
                prefixes: vec![],
            }),
            AttributeValue::AtomicAggregate,
        ]);
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(!msg.is_end_of_rib());
    }

    #[test]
    fn test_invlaid_length() {
        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, // length
            0x05, // type
        ]);
        let mut data = bytes.clone();
        assert!(parse_bgp_message(&mut data, false, &AsnLength::Bits16).is_err());

        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x28, // length
            0x05, // type
        ]);
        let mut data = bytes.clone();
        assert!(parse_bgp_message(&mut data, false, &AsnLength::Bits16).is_err());
    }

    #[test]
    fn test_invlaid_type() {
        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x28, // length
            0x05, // type
        ]);
        let mut data = bytes.clone();
        assert!(parse_bgp_message(&mut data, false, &AsnLength::Bits16).is_err());
    }

    #[test]
    fn test_parse_bgp_notification_message() {
        let bytes = Bytes::from_static(&[
            0x01, // error code
            0x02, // error subcode
            0x00, 0x00, // data
        ]);
        let msg = parse_bgp_notification_message(bytes).unwrap();
        matches!(
            msg.error,
            BgpError::MessageHeaderError(MessageHeaderError::BAD_MESSAGE_LENGTH)
        );
        assert_eq!(msg.data, Bytes::from_static(&[0x00, 0x00]));
    }

    #[test]
    fn test_encode_bgp_notification_messsage() {
        let msg = BgpNotificationMessage {
            error: BgpError::MessageHeaderError(MessageHeaderError::BAD_MESSAGE_LENGTH),
            data: vec![0x00, 0x00],
        };
        let bytes = msg.encode();
        assert_eq!(bytes, Bytes::from_static(&[0x01, 0x02, 0x00, 0x00]));
    }

    #[test]
    fn test_parse_bgp_open_message() {
        let bytes = Bytes::from_static(&[
            0x04, // version
            0x00, 0x01, // asn
            0x00, 0xb4, // hold time
            0xc0, 0x00, 0x02, 0x01, // sender ip
            0x00, // opt params length
        ]);
        let msg = parse_bgp_open_message(&mut bytes.clone()).unwrap();
        assert_eq!(msg.version, 4);
        assert_eq!(msg.asn, Asn::new_16bit(1));
        assert_eq!(msg.hold_time, 180);
        assert_eq!(msg.sender_ip, Ipv4Addr::new(192, 0, 2, 1));
        assert!(!msg.extended_length);
        assert_eq!(msg.opt_params.len(), 0);
    }

    #[test]
    fn test_encode_bgp_open_message() {
        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_16bit(1),
            hold_time: 180,
            sender_ip: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![],
        };
        let bytes = msg.encode();
        assert_eq!(
            bytes,
            Bytes::from_static(&[
                0x04, // version
                0x00, 0x01, // asn
                0x00, 0xb4, // hold time
                0xc0, 0x00, 0x02, 0x01, // sender ip
                0x00, // opt params length
            ])
        );
    }

    #[test]
    fn test_encode_bgp_notification_message() {
        let bgp_message = BgpMessage::Notification(BgpNotificationMessage {
            error: BgpError::MessageHeaderError(MessageHeaderError::BAD_MESSAGE_LENGTH),
            data: vec![0x00, 0x00],
        });
        let bytes = bgp_message.encode(false, AsnLength::Bits16);
        assert_eq!(
            bytes,
            Bytes::from_static(&[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x17, 0x03, 0x01, 0x02, 0x00, 0x00
            ])
        );
    }

    #[test]
    fn test_bgp_message_from_bgp_update_message() {
        let msg = BgpMessage::from(BgpUpdateMessage::default());
        assert!(matches!(msg, BgpMessage::Update(_)));
    }
}
