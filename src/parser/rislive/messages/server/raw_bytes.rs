use crate::error::BgpValidationWarning;
use crate::models::*;
use crate::parser::bgp::parse_bgp_message;
use crate::parser::rislive::error::ParserRisliveError;
use crate::parser::rislive::messages::{RisLiveMessage, RisMessage};
use crate::Elementor;
use bytes::Bytes;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parse a RIS Live JSON `ris_message` envelope using the `data.raw` BGP message bytes.
///
/// RIS Live includes `raw` only when subscribing with
/// `socketOptions.includeRaw=true`. The field is hex-encoded BGP wire data.
/// Parsing from raw bytes exposes attributes that RIS Live's JSON projection
/// omits, while still returning the same [`BgpElem`] interface as the JSON
/// parser.
///
/// This function expects the full RIS Live `ris_message` envelope, including
/// the standard required fields such as `id`, `host`, `timestamp`, `peer`, and
/// `peer_asn`, plus a present `raw` field.
pub fn parse_raw_bytes(msg_str: &str) -> Result<Vec<BgpElem>, ParserRisliveError> {
    parse_ris_live_message_raw(msg_str)
}

/// Parse a RIS Live JSON `ris_message` envelope using the hex-encoded `data.raw` BGP message.
pub fn parse_ris_live_message_raw(msg_str: &str) -> Result<Vec<BgpElem>, ParserRisliveError> {
    let (ris_msg, raw_bytes) = decode_ris_live_raw(msg_str)?;
    parse_ris_live_raw_bgp_message(raw_bytes, ris_msg.timestamp, ris_msg.peer, ris_msg.peer_asn)
}

/// Envelope metadata carried by every RIS Live `ris_message`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RisLiveMeta {
    /// RRC collector hostname (e.g. `rrc21`).
    pub host: String,
    /// Message id, unique and sequentially sortable per peering session.
    pub id: String,
    /// IP address of the BGP peer.
    pub peer: IpAddr,
    /// ASN of the BGP peer.
    pub peer_asn: Asn,
    /// Time the RIS collector received the message, as fractional Unix seconds.
    pub timestamp: f64,
}

/// Full-fidelity result of parsing a RIS Live message from its raw BGP wire bytes.
///
/// Unlike [`parse_ris_live_message_raw`], which returns only per-prefix
/// [`BgpElem`]s, this also exposes the complete parsed [`Attributes`] — including
/// attributes that the elem conversion drops (e.g. Originator ID, Cluster List,
/// AIGP, BGP Prefix-SID, and raw-retained ones such as BGPSEC_PATH and
/// ATTR_SET) — plus the RFC 7606 validation warnings collected during parsing.
/// `elems` are identical to those of [`parse_ris_live_message_raw`].
///
/// For non-UPDATE messages (KEEPALIVE, OPEN, NOTIFICATION), `elems`,
/// `attributes`, and `validation_warnings` are empty and only `meta` is set.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RisLiveRawFull {
    /// Envelope metadata from the RIS Live message.
    pub meta: RisLiveMeta,
    /// Per-prefix elements (same interface as the JSON parser).
    pub elems: Vec<BgpElem>,
    /// All path attributes of the BGP UPDATE message.
    pub attributes: Attributes,
    /// RFC 7606 validation warnings collected during parsing.
    pub validation_warnings: Vec<BgpValidationWarning>,
}

/// Parse a RIS Live JSON `ris_message` envelope with full fidelity from `data.raw`.
///
/// See [`RisLiveRawFull`] for what this preserves beyond
/// [`parse_ris_live_message_raw`].
pub fn parse_ris_live_message_raw_full(
    msg_str: &str,
) -> Result<RisLiveRawFull, ParserRisliveError> {
    let (ris_msg, raw_bytes) = decode_ris_live_raw(msg_str)?;
    let bgp_msg = parse_raw_bgp_message_with_asn_fallback(Bytes::from(raw_bytes.clone()))?;

    let (attributes, validation_warnings) = match &bgp_msg {
        BgpMessage::Update(update) => (
            update.attributes.clone(),
            update.attributes.validation_warnings().to_vec(),
        ),
        _ => (Attributes::default(), vec![]),
    };

    // Reuse the shared elem conversion (synthetic BGP4MP record) so elem output
    // stays identical with `parse_ris_live_message_raw`.
    let elems = parse_ris_live_raw_bgp_message(
        raw_bytes,
        ris_msg.timestamp,
        ris_msg.peer,
        ris_msg.peer_asn,
    )?;

    Ok(RisLiveRawFull {
        meta: RisLiveMeta {
            host: ris_msg.host,
            id: ris_msg.id,
            peer: ris_msg.peer,
            peer_asn: ris_msg.peer_asn,
            timestamp: ris_msg.timestamp,
        },
        elems,
        attributes,
        validation_warnings,
    })
}

/// Decode a RIS Live envelope into its message fields and raw BGP wire bytes.
fn decode_ris_live_raw(msg_str: &str) -> Result<(RisMessage, Vec<u8>), ParserRisliveError> {
    let msg: RisLiveMessage = serde_json::from_str(msg_str)
        .map_err(|e| ParserRisliveError::IncorrectJson(e.to_string()))?;

    let mut ris_msg = match msg {
        RisLiveMessage::RisMessage(ris_msg) => ris_msg,
        RisLiveMessage::RisError(_)
        | RisLiveMessage::RisRrcList(_)
        | RisLiveMessage::RisSubscribeOk(_)
        | RisLiveMessage::Pong(_) => return Err(ParserRisliveError::UnsupportedMessage),
    };

    let raw = ris_msg
        .raw
        .take()
        .ok_or(ParserRisliveError::IncorrectRawBytes)?;
    let raw_bytes = hex::decode(raw).map_err(|_| ParserRisliveError::IncorrectRawBytes)?;
    Ok((ris_msg, raw_bytes))
}

/// Parse a raw BGP message, trying 4-byte then 2-byte ASN encoding.
fn parse_raw_bgp_message_with_asn_fallback(bytes: Bytes) -> Result<BgpMessage, ParserRisliveError> {
    let mut bytes_32bit_asn = bytes.clone();
    let mut bytes_16bit_asn = bytes;
    parse_bgp_message(&mut bytes_32bit_asn, false, &AsnLength::Bits32)
        .or_else(|_| parse_bgp_message(&mut bytes_16bit_asn, false, &AsnLength::Bits16))
        .map_err(|_| ParserRisliveError::IncorrectRawBytes)
}

fn parse_ris_live_raw_bgp_message(
    raw_bytes: Vec<u8>,
    timestamp: f64,
    peer_ip: IpAddr,
    peer_asn: Asn,
) -> Result<Vec<BgpElem>, ParserRisliveError> {
    let bgp_msg = parse_raw_bgp_message_with_asn_fallback(Bytes::from(raw_bytes))?;

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

    /// UPDATE announcing 198.51.100.0/24 with ORIGIN, AS_PATH, NEXT_HOP,
    /// ORIGINATOR_ID, and CLUSTER_LIST. The last two are dropped by the elem
    /// conversion and are only visible in the full-fidelity attributes.
    const TIER2_UPDATE_RAW: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF004102000000264001010040020602010000FC00400304C00002018009040A000001800A080A0000010A00000218C63364";

    /// UPDATE announcing 198.51.100.0/24 with no path attributes at all,
    /// which must trigger RFC 7606 missing-mandatory-attribute warnings.
    const MISSING_MANDATORY_RAW: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF001B020000000018C63364";

    /// KEEPALIVE message.
    const KEEPALIVE_RAW: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF001304";

    #[test]
    fn raw_full_exposes_tier2_attributes() {
        let full =
            parse_ris_live_message_raw_full(&ris_message_with_raw(Some(TIER2_UPDATE_RAW))).unwrap();

        assert_eq!(full.meta.host, "rrc00");
        assert_eq!(full.meta.id, "00-192-0-2-1-1");
        assert_eq!(full.meta.peer.to_string(), "192.0.2.1");
        assert_eq!(full.meta.peer_asn, Asn::new_32bit(64496));
        assert_eq!(full.meta.timestamp, 1636245154.8);

        assert_eq!(full.elems.len(), 1);
        assert_eq!(full.elems[0].prefix.to_string(), "198.51.100.0/24");

        assert!(full.attributes.get_attr(AttrType::ORIGIN).is_some());
        assert!(full.attributes.get_attr(AttrType::AS_PATH).is_some());
        assert!(full.attributes.get_attr(AttrType::ORIGINATOR_ID).is_some());
        assert!(full.attributes.get_attr(AttrType::CLUSTER_LIST).is_some());
    }

    #[test]
    fn raw_full_elems_match_legacy_raw_parser() {
        let message = ris_message_with_raw(Some(TIER2_UPDATE_RAW));
        let legacy = parse_ris_live_message_raw(&message).unwrap();
        let full = parse_ris_live_message_raw_full(&message).unwrap();
        assert_eq!(full.elems, legacy);
    }

    #[test]
    fn raw_full_collects_validation_warnings() {
        let full =
            parse_ris_live_message_raw_full(&ris_message_with_raw(Some(MISSING_MANDATORY_RAW)))
                .unwrap();

        assert!(!full.validation_warnings.is_empty());
        assert!(
            full.validation_warnings
                .iter()
                .any(|w| matches!(w, BgpValidationWarning::MissingWellKnownAttribute { .. })),
            "expected a MissingWellKnownAttribute warning, got: {:?}",
            full.validation_warnings
        );
    }

    #[test]
    fn raw_full_non_update_returns_empty_payloads() {
        let message = format!(
            r#"{{"type": "ris_message", "data": {{
                "timestamp": 1636245154.8,
                "peer": "192.0.2.1",
                "peer_asn": "64496",
                "id": "00-192-0-2-1-1",
                "host": "rrc00",
                "type": "KEEPALIVE",
                "raw": "{KEEPALIVE_RAW}"
            }}}}"#
        );
        let full = parse_ris_live_message_raw_full(&message).unwrap();
        assert!(full.elems.is_empty());
        assert!(full.validation_warnings.is_empty());
        // `Attributes` serializes as an empty attribute list.
        assert!(serde_json::to_value(&full.attributes)
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn raw_full_missing_raw_returns_incorrect_raw_bytes() {
        let err = parse_ris_live_message_raw_full(&ris_message_with_raw(None)).unwrap_err();
        assert!(matches!(err, ParserRisliveError::IncorrectRawBytes));
    }
}
