use crate::error::{EncodingError, ParserError};
use crate::models::*;
use crate::parser::bgp::messages::parse_bgp_message;
use crate::parser::{encode_asn, encode_ipaddr, ReadUtils};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr};

pub(crate) fn is_short_zebra_open(data: &Bytes, asn_len: &AsnLength) -> bool {
    if !matches!(asn_len, AsnLength::Bits16) {
        return false;
    }

    let asn_bytes = asn_len.bytes() * 2;
    data.len() >= asn_bytes + 19
        && data[asn_bytes..asn_bytes + 16] == [0xff; 16]
        && data[asn_bytes + 18] == BgpMessageType::OPEN as u8
}

pub(crate) fn uses_zebra_compat(sub_type: u16, data: &Bytes) -> bool {
    match Bgp4MpType::try_from(sub_type) {
        Ok(Bgp4MpType::StateChange) => data.len() == 8,
        Ok(
            Bgp4MpType::Message
            | Bgp4MpType::MessageLocal
            | Bgp4MpType::MessageAddpath
            | Bgp4MpType::MessageLocalAddpath,
        ) => is_short_zebra_open(data, &AsnLength::Bits16),
        _ => false,
    }
}

/// Parse MRT BGP4MP type
///
/// RFC: <https://www.rfc-editor.org/rfc/rfc6396#section-4.4>
///
pub fn parse_bgp4mp(sub_type: u16, input: Bytes) -> Result<Bgp4MpEnum, ParserError> {
    let bgp4mp_type: Bgp4MpType = Bgp4MpType::try_from(sub_type)?;
    let msg: Bgp4MpEnum = match bgp4mp_type {
        Bgp4MpType::StateChange => Bgp4MpEnum::StateChange(parse_bgp4mp_state_change(
            input,
            AsnLength::Bits16,
            &bgp4mp_type,
        )?),
        Bgp4MpType::StateChangeAs4 => Bgp4MpEnum::StateChange(parse_bgp4mp_state_change(
            input,
            AsnLength::Bits32,
            &bgp4mp_type,
        )?),
        Bgp4MpType::Message | Bgp4MpType::MessageLocal => Bgp4MpEnum::Message(
            parse_bgp4mp_message(input, false, AsnLength::Bits16, &bgp4mp_type)?,
        ),
        Bgp4MpType::MessageAs4 | Bgp4MpType::MessageAs4Local => Bgp4MpEnum::Message(
            parse_bgp4mp_message(input, false, AsnLength::Bits32, &bgp4mp_type)?,
        ),
        Bgp4MpType::MessageAddpath | Bgp4MpType::MessageLocalAddpath => Bgp4MpEnum::Message(
            parse_bgp4mp_message(input, true, AsnLength::Bits16, &bgp4mp_type)?,
        ),
        Bgp4MpType::MessageAs4Addpath | Bgp4MpType::MessageLocalAs4Addpath => Bgp4MpEnum::Message(
            parse_bgp4mp_message(input, true, AsnLength::Bits32, &bgp4mp_type)?,
        ),
    };

    Ok(msg)
}

/// Return the embedded BGP message length in a BGP4MP message body.
///
/// The BGP4MP envelope is defined by RFC 6396 Section 4.4.2 for 16-bit ASNs
/// and Section 4.4.3 for AS4 variants:
/// <https://www.rfc-editor.org/rfc/rfc6396#section-4.4.2>
/// <https://www.rfc-editor.org/rfc/rfc6396#section-4.4.3>
///
/// RFC 8050 Section 3 defines the ADDPATH BGP4MP subtypes that reuse the same
/// envelope before the encapsulated BGP message:
/// <https://www.rfc-editor.org/rfc/rfc8050#section-3>
///
/// `total_size` is the MRT message body length. Subtracting the peer/local ASNs,
/// interface index, AFI, and peer/local IP addresses leaves the encapsulated BGP
/// message length.
/*
4.4.2.  BGP4MP_MESSAGE Subtype:
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

4.4.3.  BGP4MP_MESSAGE_AS4 Subtype
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
  |                    BGP Message... (variable)
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
pub(crate) fn validate_bgp4mp_afi(afi: &Afi) -> Result<(), ParserError> {
    match afi {
        Afi::Ipv4 | Afi::Ipv6 => Ok(()),
        Afi::LinkState => Err(ParserError::ParseError(
            "Link-State AFI is invalid in a BGP4MP envelope".to_string(),
        )),
    }
}

pub(crate) fn bgp4mp_message_payload_len(
    afi: &Afi,
    asn_len: &AsnLength,
    total_size: usize,
) -> Result<usize, ParserError> {
    validate_bgp4mp_afi(afi)?;
    let ip_size = if matches!(afi, Afi::Ipv4) {
        4 * 2
    } else {
        16 * 2
    };
    let asn_size = match asn_len {
        AsnLength::Bits16 => 2 * 2,
        AsnLength::Bits32 => 2 * 4,
    };
    // Saturating: on a truncated/inconsistent record the caller compares the
    // result against `data.remaining()` and rejects the mismatch, so a
    // saturated 0 simply fails that check instead of underflowing.
    Ok(total_size
        .saturating_sub(asn_size)
        .saturating_sub(2)
        .saturating_sub(2)
        .saturating_sub(ip_size))
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
    mut data: Bytes,
    add_path: bool,
    asn_len: AsnLength,
    msg_type: &Bgp4MpType,
) -> Result<Bgp4MpMessage, ParserError> {
    let total_size = data.len();
    let is_short_zebra_open = is_short_zebra_open(&data, &asn_len);

    let peer_asn: Asn = data.read_asn(asn_len)?;
    let local_asn: Asn = data.read_asn(asn_len)?;

    // Old Zebra versions omitted the interface index, AFI, and peer/local IP
    // addresses from some BGP OPEN records. The BGP marker therefore follows
    // the two 16-bit ASNs immediately. Limit this compatibility path to that
    // exact signature so other malformed envelopes still fail normally.
    if is_short_zebra_open {
        let bgp_message = parse_bgp_message(&mut data, add_path, &asn_len)?;
        return Ok(Bgp4MpMessage {
            msg_type: *msg_type,
            peer_asn,
            local_asn,
            interface_index: 0,
            peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bgp_message,
        });
    }

    let interface_index: u16 = data.read_u16()?;
    let afi: Afi = data.read_afi()?;
    let should_read = bgp4mp_message_payload_len(&afi, &asn_len, total_size)?;
    let peer_ip = data.read_address(&afi)?;
    let local_ip = data.read_address(&afi)?;

    if should_read != data.remaining() {
        return Err(ParserError::TruncatedMsg(format!(
            "truncated bgp4mp message: should read {} bytes, have {} bytes available",
            should_read,
            data.remaining()
        )));
    }
    let bgp_message: BgpMessage = parse_bgp_message(&mut data, add_path, &asn_len)?;

    Ok(Bgp4MpMessage {
        msg_type: *msg_type,
        peer_asn,
        local_asn,
        interface_index,
        peer_ip,
        local_ip,
        bgp_message,
    })
}

impl Bgp4MpMessage {
    pub fn encode(&self, asn_len: AsnLength) -> Result<Bytes, EncodingError> {
        let mut bytes = BytesMut::new();
        bytes.extend(encode_asn(&self.peer_asn, &asn_len));
        bytes.extend(encode_asn(&self.local_asn, &asn_len));
        bytes.put_u16(self.interface_index);
        bytes.put_u16(address_family(&self.peer_ip));
        bytes.extend(encode_ipaddr(&self.peer_ip));
        bytes.extend(encode_ipaddr(&self.local_ip));
        bytes.put_slice(&self.bgp_message.encode(asn_len)?);
        Ok(bytes.freeze())
    }
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
    mut input: Bytes,
    asn_len: AsnLength,
    msg_type: &Bgp4MpType,
) -> Result<Bgp4MpStateChange, ParserError> {
    let is_short_zebra_state_change = matches!(asn_len, AsnLength::Bits16) && input.len() == 8;
    let peer_asn: Asn = input.read_asn(asn_len)?;
    let local_asn: Asn = input.read_asn(asn_len)?;

    // Work around a historical Zebra corruption where an 8-byte state-change
    // record contains only the two ASNs and the old/new FSM states.
    if is_short_zebra_state_change {
        let old_state = BgpState::try_from(input.read_u16()?)?;
        let new_state = BgpState::try_from(input.read_u16()?)?;
        return Ok(Bgp4MpStateChange {
            msg_type: *msg_type,
            peer_asn,
            local_asn,
            interface_index: 0,
            peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            old_state,
            new_state,
        });
    }

    let interface_index: u16 = input.read_u16()?;
    let address_family: Afi = input.read_afi()?;
    validate_bgp4mp_afi(&address_family)?;
    let peer_ip = input.read_address(&address_family)?;
    let local_addr = input.read_address(&address_family)?;
    let old_state = BgpState::try_from(input.read_u16()?)?;
    let new_state = BgpState::try_from(input.read_u16()?)?;
    Ok(Bgp4MpStateChange {
        msg_type: *msg_type,
        peer_asn,
        local_asn,
        interface_index,
        peer_ip,
        local_addr,
        old_state,
        new_state,
    })
}

impl Bgp4MpStateChange {
    pub fn encode(&self, asn_len: AsnLength) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.extend(encode_asn(&self.peer_asn, &asn_len));
        bytes.extend(encode_asn(&self.local_asn, &asn_len));
        bytes.put_u16(self.interface_index);
        bytes.put_u16(address_family(&self.peer_ip));
        bytes.extend(encode_ipaddr(&self.peer_ip));
        bytes.extend(encode_ipaddr(&self.local_addr));
        bytes.put_u16(self.old_state as u16);
        bytes.put_u16(self.new_state as u16);
        bytes.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_bgp4mp_message_encode_uses_subtype_asn_width() {
        let message = Bgp4MpMessage {
            msg_type: Bgp4MpType::Message,
            peer_asn: Asn::new_32bit(65000),
            local_asn: Asn::new_32bit(65001),
            interface_index: 1,
            peer_ip: IpAddr::from_str("10.0.0.1").unwrap(),
            local_ip: IpAddr::from_str("10.0.0.2").unwrap(),
            bgp_message: BgpMessage::KeepAlive,
        };

        let encoded = message.encode(AsnLength::Bits16).unwrap();
        let parsed = parse_bgp4mp(Bgp4MpType::Message as u16, encoded).unwrap();

        match parsed {
            Bgp4MpEnum::Message(parsed) => {
                assert_eq!(parsed.peer_asn, Asn::new_16bit(65000));
                assert_eq!(parsed.local_asn, Asn::new_16bit(65001));
                assert_eq!(parsed.interface_index, 1);
                assert_eq!(parsed.peer_ip, message.peer_ip);
                assert_eq!(parsed.local_ip, message.local_ip);
                assert_eq!(parsed.bgp_message, BgpMessage::KeepAlive);
            }
            other => panic!("unexpected BGP4MP message: {other:?}"),
        }
    }

    #[test]
    fn test_bgp4mp_message_rejects_link_state_envelope_afi() {
        let mut data = BytesMut::new();
        data.put_u16(65000);
        data.put_u16(65001);
        data.put_u16(0);
        data.put_u16(Afi::LinkState as u16);
        data.put_slice(&BgpMessage::KeepAlive.encode(AsnLength::Bits16).unwrap());

        let error = match parse_bgp4mp(Bgp4MpType::Message as u16, data.freeze()) {
            Err(error) => error,
            Ok(message) => panic!("unexpectedly parsed BGP4MP message: {message:?}"),
        };
        assert!(matches!(
            error,
            ParserError::ParseError(message)
                if message == "Link-State AFI is invalid in a BGP4MP envelope"
        ));
    }

    #[test]
    fn test_bgp4mp_state_change_rejects_link_state_envelope_afi() {
        let mut data = BytesMut::new();
        data.put_u16(65000);
        data.put_u16(65001);
        data.put_u16(0);
        data.put_u16(Afi::LinkState as u16);
        data.put_u16(BgpState::Idle as u16);
        data.put_u16(BgpState::Connect as u16);

        let error = match parse_bgp4mp(Bgp4MpType::StateChange as u16, data.freeze()) {
            Err(error) => error,
            Ok(message) => panic!("unexpectedly parsed BGP4MP state change: {message:?}"),
        };
        assert!(matches!(
            error,
            ParserError::ParseError(message)
                if message == "Link-State AFI is invalid in a BGP4MP envelope"
        ));
    }
}
