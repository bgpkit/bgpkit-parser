use std::io::Read;

use bgp_models::bgp::*;
use bgp_models::network::*;
use num_traits::FromPrimitive;

use crate::error::ParserError;
use crate::parser::{AttributeParser, ReadUtils};

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
pub fn parse_bgp_message<T: Read>(input: &mut T, add_path: bool, afi: &Afi, asn_len: &AsnLength, total_size: usize) -> Result<BgpMessage, ParserError> {
    // https://tools.ietf.org/html/rfc4271#section-4
    // 16 (4 x 4 bytes) octets marker
    input.read_32b()?;
    input.read_32b()?;
    input.read_32b()?;
    input.read_32b()?;
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
    let length = input.read_16b()?;
    if !(length >= 19 && length <= 4096) {
        return Err(ParserError::ParseError(format!("invalid BGP message length {}", length)))
    }

    let bgp_msg_length =
        if (length as usize) > total_size {
            // return Err(ParserError::TruncatedMsg(format!("Truncated message: {} bytes available, {} bytes to read", total_size, length)))
            (total_size-19) as u64
        } else {
            (length - 19) as u64
        };

    let msg_type: BgpMessageType = match BgpMessageType::from_u8(input.read_8b()?){
        Some(t) => t,
        None => {
            return Err(ParserError::ParseError(format!("Unknown BGP Message Type")))
        }
    };

    // make sure we don't read over the bound
    let mut bgp_msg_input = input.take(bgp_msg_length);

    Ok(
        match msg_type{
            BgpMessageType::OPEN => {
                BgpMessage::Open(parse_bgp_open_message(&mut bgp_msg_input)?)
            }
            BgpMessageType::UPDATE => {
                BgpMessage::Update(parse_bgp_update_message(&mut bgp_msg_input, add_path, afi, asn_len, bgp_msg_length)?)
            }
            BgpMessageType::NOTIFICATION => {
                BgpMessage::Notification(parse_bgp_notification_message(input, bgp_msg_length - 2)?)
            }
            BgpMessageType::KEEPALIVE => {
                BgpMessage::KeepAlive(BgpKeepAliveMessage{})
            }
        }
    )
}

pub fn parse_bgp_notification_message<T: Read>(input: &mut T, bgp_msg_length: u64) -> Result<BgpNotificationMessage, ParserError> {
    let error_code = input.read_8b()?;
    let error_subcode = input.read_8b()?;
    let mut data = Vec::with_capacity((bgp_msg_length - 2) as usize);
    input.read_to_end(&mut data)?;
    Ok(
        BgpNotificationMessage{
            error_code,
            error_subcode,
            data
        })
}

pub fn parse_bgp_open_message<T: Read>(input: &mut T, ) -> Result<BgpOpenMessage, ParserError> {
    let version = input.read_8b()?;
    let asn = input.read_16b()? as Asn;
    let hold_time = input.read_16b()?;
    let sender_ip = input.read_ipv4_address()?;
    let opt_parm_len = input.read_8b()?;
    let mut opt_bytes = input.take(opt_parm_len as u64);
    while opt_bytes.limit()>0 {
        let _parm_type = opt_bytes.read_8b()?;
        let parm_length = opt_bytes.read_8b()?;
        // https://tools.ietf.org/html/rfc3392
        // TODO: process capability
        drop_n!(opt_bytes, parm_length);
    }

    Ok(
        BgpOpenMessage{
            version,
            asn,
            hold_time,
            sender_ip,
            opt_params: vec!()
        })
}

pub fn parse_bgp_update_message<T: Read>(input: &mut T, add_path:bool, afi: &Afi, asn_len: &AsnLength, bgp_msg_length: u64) -> Result<BgpUpdateMessage, ParserError> {
    let withdrawn_length = input.read_16b()? as u64;
    let mut withdarwn_input = input.take(withdrawn_length);
    let mut withdrawn_prefixes = vec!();
    while withdarwn_input.limit()>0 {
        withdrawn_prefixes.push(withdarwn_input.read_nlri_prefix(afi, 0)?);
    }

    let attribute_length = input.read_16b()? as u64;
    let attr_parser = AttributeParser::new(add_path);
    let mut attr_input = input.take(attribute_length);
    let attributes = attr_parser.parse_attributes(&mut attr_input, asn_len, None, None, None)?;
    let mut announced_prefixes = vec!();

    let nlri_length = bgp_msg_length - 4 - withdrawn_length - attribute_length;
    let mut nlri_input = input.take(nlri_length);
    while nlri_input.limit()>0 {
        announced_prefixes.push(nlri_input.read_nlri_prefix(afi, 0)?);
    }
    Ok(
        BgpUpdateMessage{
            withdrawn_prefixes,
            attributes,
            announced_prefixes
        }
    )
}
