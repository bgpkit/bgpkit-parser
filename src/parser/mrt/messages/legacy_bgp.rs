//! Parser and encoder for the deprecated MRT Type 5 BGP format.

use crate::error::{EncodingError, ParserError};
use crate::models::{
    Asn, AsnLength, BgpMessage, BgpState, LegacyBgp, LegacyBgpMessage, LegacyBgpStateChange,
};
use crate::parser::bgp::messages::{
    parse_bgp_notification_message, parse_bgp_open_message, parse_bgp_update_message,
};
use crate::parser::ReadUtils;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr};

// Deprecated BGP subtype codes for MRT type 5 records, from the IANA registry:
//
// https://www.iana.org/assignments/mrt/mrt.xhtml#bgp-subtype-codes
pub const BGP_UPDATE: u16 = 1;
pub const BGP_STATE_CHANGE: u16 = 3;
pub const BGP_OPEN: u16 = 5;
pub const BGP_NOTIFY: u16 = 6;
pub const BGP_KEEPALIVE: u16 = 7;

/// Parse a deprecated MRT Type 5 BGP message as defined in
/// [RFC 6396, Appendix B.2.1].
///
/// [RFC 6396, Appendix B.2.1]: https://www.rfc-editor.org/rfc/rfc6396.html#appendix-B.2.1
pub fn parse_legacy_bgp(sub_type: u16, mut data: Bytes) -> Result<LegacyBgp, ParserError> {
    match sub_type {
        BGP_UPDATE | BGP_OPEN | BGP_NOTIFY | BGP_KEEPALIVE => {
            let peer_asn = Asn::new_16bit(data.read_u16()?);
            let peer_ip = IpAddr::V4(data.read_ipv4_address()?);
            let local_asn = Asn::new_16bit(data.read_u16()?);
            let local_ip = IpAddr::V4(data.read_ipv4_address()?);

            let bgp_message = match sub_type {
                BGP_UPDATE => {
                    BgpMessage::Update(parse_bgp_update_message(data, false, &AsnLength::Bits16)?)
                }
                BGP_OPEN => BgpMessage::Open(parse_bgp_open_message(&mut data)?),
                BGP_NOTIFY => BgpMessage::Notification(parse_bgp_notification_message(data)?),
                BGP_KEEPALIVE => {
                    if data.has_remaining() {
                        return Err(ParserError::ParseError(format!(
                            "legacy BGP KEEPALIVE has {} trailing bytes",
                            data.remaining()
                        )));
                    }
                    BgpMessage::KeepAlive
                }
                _ => unreachable!("matched legacy BGP message subtype"),
            };

            Ok(LegacyBgp::Message(LegacyBgpMessage {
                peer_asn,
                peer_ip,
                local_asn,
                local_ip,
                bgp_message,
            }))
        }
        BGP_STATE_CHANGE => {
            let peer_asn = Asn::new_16bit(data.read_u16()?);
            let peer_ip = IpAddr::V4(data.read_ipv4_address()?);
            let old_state = BgpState::try_from(data.read_u16()?)?;
            let new_state = BgpState::try_from(data.read_u16()?)?;
            if data.has_remaining() {
                return Err(ParserError::ParseError(format!(
                    "legacy BGP STATE_CHANGE has {} trailing bytes",
                    data.remaining()
                )));
            }
            Ok(LegacyBgp::StateChange(LegacyBgpStateChange {
                peer_asn,
                peer_ip,
                old_state,
                new_state,
            }))
        }
        _ => Err(ParserError::Unsupported(format!(
            "unsupported legacy BGP subtype: {sub_type}"
        ))),
    }
}

pub fn encode_legacy_bgp(message: &LegacyBgp, sub_type: u16) -> Result<Bytes, EncodingError> {
    let mut bytes = BytesMut::new();
    match (sub_type, message) {
        (BGP_UPDATE, LegacyBgp::Message(message)) => {
            encode_peer_envelope(message, &mut bytes)?;
            match &message.bgp_message {
                BgpMessage::Update(update) => {
                    bytes.put_slice(&update.encode(AsnLength::Bits16)?);
                }
                _ => {
                    return Err(EncodingError::unencodable(
                        "legacy BGP UPDATE",
                        "message payload is not an UPDATE",
                    ));
                }
            }
        }
        (BGP_OPEN, LegacyBgp::Message(message)) => {
            encode_peer_envelope(message, &mut bytes)?;
            match &message.bgp_message {
                BgpMessage::Open(open) => bytes.put_slice(&open.encode()?),
                _ => {
                    return Err(EncodingError::unencodable(
                        "legacy BGP OPEN",
                        "message payload is not an OPEN",
                    ));
                }
            }
        }
        (BGP_NOTIFY, LegacyBgp::Message(message)) => {
            encode_peer_envelope(message, &mut bytes)?;
            match &message.bgp_message {
                BgpMessage::Notification(notification) => {
                    bytes.put_slice(&notification.encode());
                }
                _ => {
                    return Err(EncodingError::unencodable(
                        "legacy BGP NOTIFY",
                        "message payload is not a NOTIFICATION",
                    ));
                }
            }
        }
        (BGP_KEEPALIVE, LegacyBgp::Message(message)) => {
            encode_peer_envelope(message, &mut bytes)?;
            if !matches!(message.bgp_message, BgpMessage::KeepAlive) {
                return Err(EncodingError::unencodable(
                    "legacy BGP KEEPALIVE",
                    "message payload is not a KEEPALIVE",
                ));
            }
        }
        (BGP_STATE_CHANGE, LegacyBgp::StateChange(change)) => {
            bytes.put_u16(asn16(&change.peer_asn, "legacy BGP peer ASN")?);
            bytes.put_u32(ipv4(&change.peer_ip, "legacy BGP peer IP")?.into());
            bytes.put_u16(change.old_state as u16);
            bytes.put_u16(change.new_state as u16);
        }
        _ => {
            return Err(EncodingError::unencodable(
                "legacy BGP message",
                format!("message does not match subtype {sub_type}"),
            ));
        }
    }
    Ok(bytes.freeze())
}

fn encode_peer_envelope(
    message: &LegacyBgpMessage,
    bytes: &mut BytesMut,
) -> Result<(), EncodingError> {
    bytes.put_u16(asn16(&message.peer_asn, "legacy BGP peer ASN")?);
    bytes.put_u32(ipv4(&message.peer_ip, "legacy BGP peer IP")?.into());
    bytes.put_u16(asn16(&message.local_asn, "legacy BGP local ASN")?);
    bytes.put_u32(ipv4(&message.local_ip, "legacy BGP local IP")?.into());
    Ok(())
}

fn asn16(asn: &Asn, field: &'static str) -> Result<u16, EncodingError> {
    let value: u32 = (*asn).into();
    u16::try_from(value)
        .map_err(|_| EncodingError::too_large(field, value as usize, u16::MAX as usize))
}

fn ipv4(ip: &IpAddr, field: &'static str) -> Result<Ipv4Addr, EncodingError> {
    match ip {
        IpAddr::V4(ip) => Ok(*ip),
        IpAddr::V6(_) => Err(EncodingError::unencodable(
            field,
            "deprecated MRT Type 5 supports IPv4 only",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_envelope() -> BytesMut {
        let mut bytes = BytesMut::new();
        bytes.put_u16(64512);
        bytes.put_u32(u32::from(Ipv4Addr::new(192, 0, 2, 1)));
        bytes.put_u16(64513);
        bytes.put_u32(u32::from(Ipv4Addr::new(192, 0, 2, 2)));
        bytes
    }

    #[test]
    fn legacy_update_round_trips() {
        let mut bytes = peer_envelope();
        bytes.put_u16(0);
        bytes.put_u16(0);
        let wire = bytes.freeze();
        let message = parse_legacy_bgp(BGP_UPDATE, wire.clone()).unwrap();
        assert!(matches!(
            &message,
            LegacyBgp::Message(LegacyBgpMessage {
                bgp_message: BgpMessage::Update(_),
                ..
            })
        ));
        assert_eq!(encode_legacy_bgp(&message, BGP_UPDATE).unwrap(), wire);
    }

    #[test]
    fn legacy_keepalive_round_trips() {
        let wire = peer_envelope().freeze();
        let message = parse_legacy_bgp(BGP_KEEPALIVE, wire.clone()).unwrap();
        assert!(matches!(
            &message,
            LegacyBgp::Message(LegacyBgpMessage {
                bgp_message: BgpMessage::KeepAlive,
                ..
            })
        ));
        assert_eq!(encode_legacy_bgp(&message, BGP_KEEPALIVE).unwrap(), wire);
    }

    #[test]
    fn legacy_open_round_trips() {
        let mut bytes = peer_envelope();
        bytes.put_u8(4);
        bytes.put_u16(64512);
        bytes.put_u16(180);
        bytes.put_u32(u32::from(Ipv4Addr::new(192, 0, 2, 1)));
        bytes.put_u8(0);
        let wire = bytes.freeze();

        let message = parse_legacy_bgp(BGP_OPEN, wire.clone()).unwrap();
        assert!(matches!(
            &message,
            LegacyBgp::Message(LegacyBgpMessage {
                bgp_message: BgpMessage::Open(_),
                ..
            })
        ));
        assert_eq!(encode_legacy_bgp(&message, BGP_OPEN).unwrap(), wire);
    }

    #[test]
    fn legacy_notify_round_trips() {
        let mut bytes = peer_envelope();
        bytes.put_u8(4);
        bytes.put_u8(0);
        bytes.put_slice(&[1, 2, 3]);
        let wire = bytes.freeze();

        let message = parse_legacy_bgp(BGP_NOTIFY, wire.clone()).unwrap();
        assert!(matches!(
            &message,
            LegacyBgp::Message(LegacyBgpMessage {
                bgp_message: BgpMessage::Notification(_),
                ..
            })
        ));
        assert_eq!(encode_legacy_bgp(&message, BGP_NOTIFY).unwrap(), wire);
    }

    #[test]
    fn legacy_state_change_round_trips() {
        let mut bytes = BytesMut::new();
        bytes.put_u16(64512);
        bytes.put_u32(u32::from(Ipv4Addr::new(192, 0, 2, 1)));
        bytes.put_u16(BgpState::Active as u16);
        bytes.put_u16(BgpState::Connect as u16);
        let wire = bytes.freeze();
        let message = parse_legacy_bgp(BGP_STATE_CHANGE, wire.clone()).unwrap();
        assert!(matches!(&message, LegacyBgp::StateChange(_)));
        assert_eq!(encode_legacy_bgp(&message, BGP_STATE_CHANGE).unwrap(), wire);
    }

    #[test]
    fn rejects_trailing_keepalive_bytes_and_unknown_subtypes() {
        let mut bytes = peer_envelope();
        bytes.put_u8(0);
        assert!(parse_legacy_bgp(BGP_KEEPALIVE, bytes.freeze()).is_err());
        assert!(matches!(
            parse_legacy_bgp(2, Bytes::new()),
            Err(ParserError::Unsupported(_))
        ));

        let keepalive = parse_legacy_bgp(BGP_KEEPALIVE, peer_envelope().freeze()).unwrap();
        assert!(encode_legacy_bgp(&keepalive, BGP_OPEN).is_err());
        assert!(encode_legacy_bgp(&keepalive, BGP_NOTIFY).is_err());
    }
}
