use crate::error::ParserError;
use crate::parser::bgp::messages::parse_bgp_message;
use crate::parser::ReadUtils;
use bgp_models::prelude::*;
use byteorder::{ReadBytesExt, BE};
use num_traits::FromPrimitive;
use std::io::Cursor;

/// Parse MRT BGP4MP type
///
/// RFC: https://www.rfc-editor.org/rfc/rfc6396#section-4.4
///
pub fn parse_bgp4mp(sub_type: u16, input: &[u8]) -> Result<Bgp4Mp, ParserError> {
    let bgp4mp_type: Bgp4MpType = match Bgp4MpType::from_u16(sub_type) {
        Some(t) => t,
        None => {
            return Err(ParserError::ParseError(format!(
                "cannot parse bgp4mp subtype: {}",
                sub_type
            )))
        }
    };
    let msg: Bgp4Mp = match bgp4mp_type {
        Bgp4MpType::Bgp4MpStateChange => Bgp4Mp::Bgp4MpStateChange(parse_bgp4mp_state_change(
            input,
            AsnLength::Bits16,
            &bgp4mp_type,
        )?),
        Bgp4MpType::Bgp4MpStateChangeAs4 => Bgp4Mp::Bgp4MpStateChangeAs4(
            parse_bgp4mp_state_change(input, AsnLength::Bits32, &bgp4mp_type)?,
        ),
        Bgp4MpType::Bgp4MpMessage | Bgp4MpType::Bgp4MpMessageLocal => Bgp4Mp::Bgp4MpMessage(
            parse_bgp4mp_message(input, false, AsnLength::Bits16, &bgp4mp_type)?,
        ),
        Bgp4MpType::Bgp4MpMessageAs4 | Bgp4MpType::Bgp4MpMessageAs4Local => Bgp4Mp::Bgp4MpMessage(
            parse_bgp4mp_message(input, false, AsnLength::Bits32, &bgp4mp_type)?,
        ),
        Bgp4MpType::Bgp4MpMessageAddpath | Bgp4MpType::Bgp4MpMessageLocalAddpath => {
            Bgp4Mp::Bgp4MpMessage(parse_bgp4mp_message(
                input,
                true,
                AsnLength::Bits16,
                &bgp4mp_type,
            )?)
        }
        Bgp4MpType::Bgp4MpMessageAs4Addpath | Bgp4MpType::Bgp4MpMessageLocalAs4Addpath => {
            Bgp4Mp::Bgp4MpMessage(parse_bgp4mp_message(
                input,
                true,
                AsnLength::Bits32,
                &bgp4mp_type,
            )?)
        }
    };

    Ok(msg)
}

fn total_should_read(afi: &Afi, asn_len: &AsnLength, total_size: usize) -> usize {
    let ip_size = match afi {
        Afi::Ipv4 => 4 * 2,
        Afi::Ipv6 => 16 * 2,
    };
    let asn_size = match asn_len {
        AsnLength::Bits16 => 2 * 2,
        AsnLength::Bits32 => 2 * 4,
    };
    total_size - asn_size - 2 - 2 - ip_size
}
/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Peer AS Number        |        Local AS Number        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |        Interface Index        |        Address Family         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      Peer IP Address (variable)               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      Local IP Address (variable)              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    BGP Message... (variable)
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
pub fn parse_bgp4mp_message(
    data: &[u8],
    add_path: bool,
    asn_len: AsnLength,
    msg_type: &Bgp4MpType,
) -> Result<Bgp4MpMessage, ParserError> {
    let total_size = data.len();
    let mut input = Cursor::new(data);

    let peer_asn: Asn = input.read_asn(&asn_len)?;
    let local_asn: Asn = input.read_asn(&asn_len)?;
    let interface_index: u16 = input.read_u16::<BE>()?;
    let afi: Afi = input.read_afi()?;
    let peer_ip = input.read_address(&afi)?;
    let local_ip = input.read_address(&afi)?;

    let should_read = total_should_read(&afi, &asn_len, total_size);
    let current_position = input.position() as usize;
    let data_slice = &input.into_inner()[current_position..];
    if should_read != data_slice.len() {
        return Err(ParserError::TruncatedMsg(format!(
            "truncated bgp4mp message: should read {} bytes, have {} bytes available",
            should_read,
            data_slice.len()
        )));
    }
    let bgp_message: BgpMessage = parse_bgp_message(data_slice, add_path, &asn_len)?;

    Ok(Bgp4MpMessage {
        msg_type: *msg_type,
        peer_asn,
        local_asn,
        interface_index,
        afi,
        peer_ip,
        local_ip,
        bgp_message,
    })
}

/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Peer AS Number        |        Local AS Number        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |        Interface Index        |        Address Family         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      Peer IP Address (variable)               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      Local IP Address (variable)              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |            Old State          |          New State            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Peer AS Number                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Local AS Number                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |        Interface Index        |        Address Family         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      Peer IP Address (variable)               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      Local IP Address (variable)              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |            Old State          |          New State            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
pub fn parse_bgp4mp_state_change(
    data: &[u8],
    asn_len: AsnLength,
    msg_type: &Bgp4MpType,
) -> Result<Bgp4MpStateChange, ParserError> {
    let mut input = Cursor::new(data);
    let peer_asn: Asn = input.read_asn(&asn_len)?;
    let local_asn: Asn = input.read_asn(&asn_len)?;
    let interface_index: u16 = input.read_u16::<BE>()?;
    let address_family: Afi = input.read_afi()?;
    let peer_addr = input.read_address(&address_family)?;
    let local_addr = input.read_address(&address_family)?;
    let old_state = match BgpState::from_u16(input.read_u16::<BE>()?) {
        Some(t) => t,
        None => {
            return Err(ParserError::ParseError(
                "cannot parse bgp4mp old_state".to_string(),
            ))
        }
    };
    let new_state = match BgpState::from_u16(input.read_u16::<BE>()?) {
        Some(t) => t,
        None => {
            return Err(ParserError::ParseError(
                "cannot parse bgp4mp new_state".to_string(),
            ))
        }
    };
    Ok(Bgp4MpStateChange {
        msg_type: *msg_type,
        peer_asn,
        local_asn,
        interface_index,
        address_family,
        peer_addr,
        local_addr,
        old_state,
        new_state,
    })
}
