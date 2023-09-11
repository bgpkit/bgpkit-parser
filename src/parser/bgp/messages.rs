use crate::models::*;
use std::convert::TryFrom;

use crate::error::ParserError;
use crate::models::capabilities::BgpCapabilityType;
use crate::models::error::BgpError;
use crate::parser::{parse_nlri_list, AttributeParser, ReadUtils};
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
    data: &mut &[u8],
    add_path: bool,
    asn_len: AsnLength,
) -> Result<BgpMessage, ParserError> {
    let total_size = data.len();
    data.require_n_remaining(19, "BGP message marker")?;
    data.advance(16)?;
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
    let length = data.read_u16()?;
    if !(19..=4096).contains(&length) {
        return Err(ParserError::InvalidBgpMessageLength(length));
    }

    // TODO: Why do we sometimes change our length estimate?
    let bgp_msg_length = if (length as usize) > total_size {
        total_size - 19
    } else {
        length as usize - 19
    };

    let msg_type: BgpMessageType = BgpMessageType::try_from(data.read_u8()?)?;

    if data.remaining() != bgp_msg_length {
        // TODO: Why is this not a hard error?
        warn!(
            "BGP message length {} does not match the actual length {}",
            bgp_msg_length,
            data.remaining()
        );
    }
    let mut msg_data = data.split_to(bgp_msg_length)?;

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

/// Parse BGP NOTIFICATION messages.
///
/// The BGP NOTIFICATION messages contains BGP error codes received from a connected BGP router. The
/// error code is parsed into [BgpError](crate::models::error::BgpError) data structure and any unknown codes will produce warning
/// messages, but not critical errors.
///
pub fn parse_bgp_notification_message(
    mut input: &[u8],
) -> Result<BgpNotificationMessage, ParserError> {
    let error_code = input.read_u8()?;
    let error_subcode = input.read_u8()?;

    Ok(BgpNotificationMessage {
        error: BgpError::new(error_code, error_subcode),
        data: input.read_n_bytes(input.len() - 2)?,
    })
}

/// Parse BGP OPEN messages.
///
/// The parsing of BGP OPEN messages also includes decoding the BGP capabilities.
pub fn parse_bgp_open_message(input: &mut &[u8]) -> Result<BgpOpenMessage, ParserError> {
    input.require_n_remaining(10, "BGP open message header")?;
    let version = input.read_u8()?;
    let asn = Asn::new_16bit(input.read_u16()?);
    let hold_time = input.read_u16()?;

    let sender_ip = input.read_ipv4_address()?;
    let opt_params_len = input.read_u8()?;

    // let pos_end = input.position() + opt_params_len as u64;
    if input.remaining() != opt_params_len as usize {
        // TODO: This seems like it should become a hard error
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
        let param_type = input.read_u8()?;
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

        let parm_length = input.read_u8()?;
        // https://tools.ietf.org/html/rfc3392
        // https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11

        let param_value = match param_type {
            2 => {
                // capability codes:
                // https://www.iana.org/assignments/capability-codes/capability-codes.xhtml#capability-codes-2
                let code = input.read_u8()?;
                let len = input.read_u8()?;

                ParamValue::Capability(Capability {
                    ty: BgpCapabilityType::from(code),
                    value: input.read_n_bytes(len as usize)?,
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

/// read nlri portion of a bgp update message.
fn read_nlri(mut input: &[u8], afi: &Afi, add_path: bool) -> Result<PrefixList, ParserError> {
    let length = input.len();
    if length == 0 {
        return Ok(PrefixList::new());
    }
    if length == 1 {
        // TODO: Should this become a hard error?
        // 1 byte does not make sense
        warn!("seeing strange one-byte NLRI field");
        input.advance(1)?; // skip the byte
        return Ok(PrefixList::new());
    }

    parse_nlri_list(input, add_path, *afi)
}

/// read bgp update message.
///
/// RFC: <https://tools.ietf.org/html/rfc4271#section-4.3>
pub fn parse_bgp_update_message(
    mut input: &[u8],
    add_path: bool,
    asn_len: AsnLength,
) -> Result<BgpUpdateMessage, ParserError> {
    // AFI for routes out side attributes are IPv4 ONLY.
    let afi = Afi::Ipv4;

    // parse withdrawn prefixes nlri
    let withdrawn_bytes_length = input.read_u16()? as usize;
    let withdrawn_bytes = input.split_to(withdrawn_bytes_length)?;
    let withdrawn_prefixes = read_nlri(withdrawn_bytes, &afi, add_path)?;

    // parse attributes
    let attribute_length = input.read_u16()? as usize;
    let attr_parser = AttributeParser::new(add_path);

    input.require_n_remaining(attribute_length, "update attributes")?;
    let attr_data_slice = input.split_to(attribute_length)?;
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
