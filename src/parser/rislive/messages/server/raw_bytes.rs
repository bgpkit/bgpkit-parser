use crate::models::*;
use crate::parser::bgp::parse_bgp_message;
use crate::parser::rislive::error::ParserRisliveError;
use crate::parser::rislive::messages::RisLiveMessage;
use crate::Elementor;
use bytes::Bytes;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parse a RIS Live JSON message using the `data.raw` BGP message bytes.
///
/// RIS Live includes `raw` only when subscribing with
/// `socketOptions.includeRaw=true`. The field is hex-encoded BGP wire data.
/// Parsing from raw bytes exposes attributes that RIS Live's JSON projection
/// omits, while still returning the same [`BgpElem`] interface as the JSON
/// parser.
pub fn parse_raw_bytes(msg_str: &str) -> Result<Vec<BgpElem>, ParserRisliveError> {
    parse_ris_live_message_raw(msg_str)
}

/// Parse a RIS Live JSON message using the hex-encoded `data.raw` BGP message.
pub fn parse_ris_live_message_raw(msg_str: &str) -> Result<Vec<BgpElem>, ParserRisliveError> {
    let msg: RisLiveMessage = serde_json::from_str(msg_str)
        .map_err(|_| ParserRisliveError::IncorrectJson(msg_str.to_string()))?;

    let ris_msg = match msg {
        RisLiveMessage::RisMessage(ris_msg) => ris_msg,
        RisLiveMessage::RisError(_)
        | RisLiveMessage::RisRrcList(_)
        | RisLiveMessage::RisSubscribeOk(_)
        | RisLiveMessage::Pong(_) => return Err(ParserRisliveError::UnsupportedMessage),
    };

    let raw = ris_msg.raw.ok_or(ParserRisliveError::IncorrectRawBytes)?;
    let raw_bytes = hex::decode(raw).map_err(|_| ParserRisliveError::IncorrectRawBytes)?;

    parse_ris_live_raw_bgp_message(raw_bytes, ris_msg.timestamp, ris_msg.peer, ris_msg.peer_asn)
}

fn parse_ris_live_raw_bgp_message(
    raw_bytes: Vec<u8>,
    timestamp: f64,
    peer_ip: IpAddr,
    peer_asn: Asn,
) -> Result<Vec<BgpElem>, ParserRisliveError> {
    let bytes = Bytes::from(raw_bytes);

    let bgp_msg = parse_bgp_message(&mut bytes.clone(), false, &AsnLength::Bits32)
        .or_else(|_| parse_bgp_message(&mut bytes.clone(), false, &AsnLength::Bits16))
        .map_err(|_| ParserRisliveError::IncorrectRawBytes)?;

    let local_ip = match peer_ip.is_ipv4() {
        true => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        false => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };

    let header = CommonHeader {
        timestamp: timestamp as u32,
        microsecond_timestamp: Some(get_micro_seconds(timestamp)),
        entry_type: EntryType::BGP4MP,
        entry_subtype: Bgp4MpType::MessageAs4 as u16,
        length: 0,
    };

    let record = MrtRecord {
        common_header: header,
        message: MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(Bgp4MpMessage {
            msg_type: Bgp4MpType::MessageAs4,
            peer_asn,
            local_asn: Asn::RESERVED,
            interface_index: 0,
            peer_ip,
            local_ip,
            bgp_message: bgp_msg,
        })),
    };
    Ok(Elementor::new().record_to_elems(record))
}

fn get_micro_seconds(sec: f64) -> u32 {
    ((sec.fract().abs() * 1_000_000.0).round() as u32).min(999_999)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ris_live_message() {
        let message = r#"
        {
  "type": "ris_message",
  "data": {
    "timestamp": 1636245154.8,
    "peer": "2001:7f8:b:100:1d1:a520:1333:74",
    "peer_asn": "201333",
    "id": "10-183678-175313836",
    "host": "rrc10",
    "type": "UPDATE",
    "path": [
      201333,
      6762,
      174,
      20473
    ],
    "community": [
      [
        6762,
        30
      ],
      [
        6762,
        14400
      ]
    ],
    "origin": "igp",
    "announcements": [
      {
        "next_hop": "2001:7f8:b:100:1d1:a520:1333:74",
        "prefixes": [
          "2a0e:97c7::/48",
          "2a0e:97c6:fe::/48",
          "2a10:cc42:17b7::/48",
          "2a10:cc42:1feb::/48"
        ]
      },
      {
        "next_hop": "fe80::217:a3ff:fefe:2905",
        "prefixes": [
          "2a0e:97c7::/48",
          "2a0e:97c6:fe::/48",
          "2a10:cc42:17b7::/48",
          "2a10:cc42:1feb::/48"
        ]
      }
    ],
    "raw": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0086020000006F4001010040021202040003127500001A6A000000AE00004FF980040400000000C008081A6A001E1A6A3840800E4100020120200107F8000B010001D1A52013330074FE800000000000000217A3FFFEFE290500302A0E97C70000302A0E97C600FE302A10CC4217B7302A10CC421FEB"
  }
}
        "#;

        let res = parse_raw_bytes(message);
        for elem in res.unwrap() {
            println!("{elem}");
        }
    }

    fn ris_message_with_raw(raw: Option<&str>) -> String {
        let raw_field = raw
            .map(|raw| format!(r#", "raw": "{raw}""#))
            .unwrap_or_default();
        format!(
            r#"{{
                "type": "ris_message",
                "data": {{
                    "timestamp": 1636245154.8,
                    "peer": "192.0.2.1",
                    "peer_asn": "64496",
                    "id": "00-192-0-2-1-1",
                    "host": "rrc00",
                    "type": "UPDATE"{raw_field}
                }}
            }}"#
        )
    }

    #[test]
    fn ris_live_message_missing_raw_returns_incorrect_raw_bytes() {
        let err = parse_raw_bytes(&ris_message_with_raw(None)).unwrap_err();
        assert!(matches!(err, ParserRisliveError::IncorrectRawBytes));
    }

    #[test]
    fn ris_live_message_malformed_hex_returns_incorrect_raw_bytes() {
        let err = parse_raw_bytes(&ris_message_with_raw(Some("not-hex"))).unwrap_err();
        assert!(matches!(err, ParserRisliveError::IncorrectRawBytes));
    }

    #[test]
    fn ris_live_message_invalid_bgp_raw_returns_incorrect_raw_bytes() {
        let err = parse_raw_bytes(&ris_message_with_raw(Some("00"))).unwrap_err();
        assert!(matches!(err, ParserRisliveError::IncorrectRawBytes));
    }

    #[test]
    fn non_ris_message_returns_unsupported_message() {
        let err = parse_raw_bytes(r#"{"type":"pong","data":null}"#).unwrap_err();
        assert!(matches!(err, ParserRisliveError::UnsupportedMessage));
    }

    #[test]
    fn ris_live_message_missing_required_id_or_host_returns_incorrect_json() {
        let err = parse_raw_bytes(
            r#"{
                "type": "ris_message",
                "data": {
                    "timestamp": 1636245154.8,
                    "peer": "192.0.2.1",
                    "peer_asn": "64496",
                    "type": "UPDATE",
                    "raw": "00"
                }
            }"#,
        )
        .unwrap_err();
        assert!(matches!(err, ParserRisliveError::IncorrectJson(_)));
    }
}
