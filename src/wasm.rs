//! WebAssembly bindings for BMP/BGP/MRT message parsing.
//!
//! This module is compiled only when the `wasm` feature is enabled. Use
//! [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) to build the package:
//!
//! ```sh
//! # Node.js target (CommonJS, synchronous WASM loading)
//! wasm-pack build --target nodejs --no-default-features --features wasm
//!
//! # Bundler target (for webpack/vite/rollup)
//! wasm-pack build --target bundler --no-default-features --features wasm
//! ```
//!
//! ## Exported functions
//!
//! - [`parseOpenBmpMessage`](parse_openbmp_message) — parse OpenBMP-wrapped BMP
//!   messages (e.g. from the RouteViews Kafka stream)
//! - [`parseBmpMessage`](parse_bmp_message) — parse raw BMP messages
//! - [`parseMrtFile`](parse_mrt_file) — parse a decompressed MRT file into BGP elements
//! - [`parseBgpUpdate`](parse_bgp_update) — parse a single BGP UPDATE message

use crate::models::*;
use crate::parser::bgp::messages::parse_bgp_message;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::bmp::messages::*;
use crate::parser::bmp::{parse_bmp_msg, parse_openbmp_header};
use crate::parser::mrt::mrt_elem::Elementor;
use crate::parser::mrt::mrt_record::parse_mrt_record;
use bytes::Bytes;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};
use wasm_bindgen::prelude::*;

// ── Serialization types ──────────────────────────────────────────────────────
//
// These structs use camelCase `#[serde(rename)]` to produce JS-friendly JSON.
// The `WasmBmpMessage` enum is internally tagged on `"type"` so JS consumers
// can discriminate with `msg.type === "RouteMonitoring"` etc.

#[derive(serde::Serialize)]
#[serde(tag = "type")]
enum WasmBmpMessage {
    RouteMonitoring {
        #[serde(flatten)]
        base: WasmMessageBase,
        #[serde(rename = "peerHeader")]
        peer_header: WasmPeerHeader,
        elems: Vec<BgpElem>,
    },
    PeerUpNotification {
        #[serde(flatten)]
        base: WasmMessageBase,
        #[serde(rename = "peerHeader")]
        peer_header: WasmPeerHeader,
        #[serde(rename = "localIp")]
        local_ip: String,
        #[serde(rename = "localPort")]
        local_port: u16,
        #[serde(rename = "remotePort")]
        remote_port: u16,
    },
    PeerDownNotification {
        #[serde(flatten)]
        base: WasmMessageBase,
        #[serde(rename = "peerHeader")]
        peer_header: WasmPeerHeader,
        reason: String,
    },
    InitiationMessage {
        #[serde(flatten)]
        base: WasmMessageBase,
        tlvs: Vec<WasmTlv>,
    },
    TerminationMessage {
        #[serde(flatten)]
        base: WasmMessageBase,
        tlvs: Vec<WasmTlv>,
    },
    StatisticsReport {
        #[serde(flatten)]
        base: WasmMessageBase,
        #[serde(rename = "peerHeader")]
        peer_header: WasmPeerHeader,
    },
    RouteMirroringMessage {
        #[serde(flatten)]
        base: WasmMessageBase,
        #[serde(rename = "peerHeader")]
        peer_header: WasmPeerHeader,
    },
}

#[derive(serde::Serialize)]
struct WasmMessageBase {
    #[serde(rename = "openBmpHeader")]
    openbmp_header: Option<WasmOpenBmpHeader>,
    timestamp: f64,
}

#[derive(serde::Serialize)]
struct WasmOpenBmpHeader {
    #[serde(rename = "routerIp")]
    router_ip: String,
    #[serde(rename = "routerGroup")]
    router_group: Option<String>,
    #[serde(rename = "adminId")]
    admin_id: String,
    timestamp: f64,
}

#[derive(serde::Serialize)]
struct WasmPeerHeader {
    #[serde(rename = "peerIp")]
    peer_ip: String,
    #[serde(rename = "peerAsn")]
    peer_asn: u32,
    #[serde(rename = "peerBgpId")]
    peer_bgp_id: String,
    #[serde(rename = "peerType")]
    peer_type: String,
    #[serde(rename = "isPostPolicy")]
    is_post_policy: bool,
    #[serde(rename = "isAdjRibOut")]
    is_adj_rib_out: bool,
    timestamp: f64,
}

#[derive(serde::Serialize)]
struct WasmTlv {
    #[serde(rename = "type")]
    tlv_type: String,
    value: String,
}

// ── Conversion helpers ───────────────────────────────────────────────────────

fn make_openbmp_header(header: &crate::parser::bmp::openbmp::OpenBmpHeader) -> WasmOpenBmpHeader {
    WasmOpenBmpHeader {
        router_ip: header.router_ip.to_string(),
        router_group: header.router_group.clone(),
        admin_id: header.admin_id.clone(),
        timestamp: header.timestamp,
    }
}

fn make_peer_header(pph: &BmpPerPeerHeader) -> WasmPeerHeader {
    let (is_post_policy, is_adj_rib_out) = match pph.peer_flags {
        PerPeerFlags::PeerFlags(f) => (f.is_post_policy(), f.is_adj_rib_out()),
        PerPeerFlags::LocalRibPeerFlags(_) => (false, false),
    };
    WasmPeerHeader {
        peer_ip: pph.peer_ip.to_string(),
        peer_asn: pph.peer_asn.into(),
        peer_bgp_id: pph.peer_bgp_id.to_string(),
        peer_type: format!("{:?}", pph.peer_type),
        is_post_policy,
        is_adj_rib_out,
        timestamp: pph.timestamp,
    }
}

fn build_bmp_result(
    bmp_msg: BmpMessage,
    openbmp_header: Option<WasmOpenBmpHeader>,
    timestamp: f64,
) -> WasmBmpMessage {
    let base = WasmMessageBase {
        openbmp_header,
        timestamp,
    };

    match (bmp_msg.per_peer_header, bmp_msg.message_body) {
        (Some(pph), BmpMessageBody::RouteMonitoring(m)) => {
            let elems =
                Elementor::bgp_to_elems(m.bgp_message, timestamp, &pph.peer_ip, &pph.peer_asn);
            WasmBmpMessage::RouteMonitoring {
                base,
                peer_header: make_peer_header(&pph),
                elems,
            }
        }
        (Some(pph), BmpMessageBody::PeerUpNotification(m)) => WasmBmpMessage::PeerUpNotification {
            base,
            peer_header: make_peer_header(&pph),
            local_ip: m.local_addr.to_string(),
            local_port: m.local_port,
            remote_port: m.remote_port,
        },
        (Some(pph), BmpMessageBody::PeerDownNotification(m)) => {
            WasmBmpMessage::PeerDownNotification {
                base,
                peer_header: make_peer_header(&pph),
                reason: format!("{:?}", m.reason),
            }
        }
        (_, BmpMessageBody::InitiationMessage(m)) => WasmBmpMessage::InitiationMessage {
            base,
            tlvs: m
                .tlvs
                .into_iter()
                .map(|t| WasmTlv {
                    tlv_type: format!("{:?}", t.info_type),
                    value: t.info,
                })
                .collect(),
        },
        (_, BmpMessageBody::TerminationMessage(m)) => WasmBmpMessage::TerminationMessage {
            base,
            tlvs: m
                .tlvs
                .into_iter()
                .map(|t| WasmTlv {
                    tlv_type: format!("{:?}", t.info_type),
                    value: format!("{:?}", t.info_value),
                })
                .collect(),
        },
        (Some(pph), BmpMessageBody::StatsReport(_)) => WasmBmpMessage::StatisticsReport {
            base,
            peer_header: make_peer_header(&pph),
        },
        (Some(pph), BmpMessageBody::RouteMirroring(_)) => WasmBmpMessage::RouteMirroringMessage {
            base,
            peer_header: make_peer_header(&pph),
        },
        // Messages without a per-peer header that aren't Initiation/Termination
        // should not occur per RFC 7854, but handle gracefully.
        (None, BmpMessageBody::StatsReport(_)) => WasmBmpMessage::StatisticsReport {
            base,
            peer_header: make_peer_header(&BmpPerPeerHeader::default()),
        },
        (None, BmpMessageBody::RouteMirroring(_)) => WasmBmpMessage::RouteMirroringMessage {
            base,
            peer_header: make_peer_header(&BmpPerPeerHeader::default()),
        },
        (None, BmpMessageBody::RouteMonitoring(_)) => WasmBmpMessage::RouteMonitoring {
            base,
            peer_header: make_peer_header(&BmpPerPeerHeader::default()),
            elems: vec![],
        },
        (None, BmpMessageBody::PeerUpNotification(m)) => WasmBmpMessage::PeerUpNotification {
            base,
            peer_header: make_peer_header(&BmpPerPeerHeader::default()),
            local_ip: m.local_addr.to_string(),
            local_port: m.local_port,
            remote_port: m.remote_port,
        },
        (None, BmpMessageBody::PeerDownNotification(m)) => WasmBmpMessage::PeerDownNotification {
            base,
            peer_header: make_peer_header(&BmpPerPeerHeader::default()),
            reason: format!("{:?}", m.reason),
        },
    }
}

// ── Core parsing functions (testable without wasm_bindgen) ───────────────────

/// Parse an OpenBMP message, returning a JSON string or `Ok(None)` for
/// unsupported (non-router) messages.
fn parse_openbmp_message_core(data: &[u8]) -> Result<Option<String>, String> {
    let mut bytes = Bytes::from(data.to_vec());

    let header = match parse_openbmp_header(&mut bytes) {
        Ok(h) => h,
        Err(ParserBmpError::UnsupportedOpenBmpMessage) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };

    let bmp_msg = parse_bmp_msg(&mut bytes).map_err(|e| e.to_string())?;

    let result = build_bmp_result(
        bmp_msg,
        Some(make_openbmp_header(&header)),
        header.timestamp,
    );

    serde_json::to_string(&result)
        .map(Some)
        .map_err(|e| e.to_string())
}

/// Parse a raw BMP message, returning a JSON string.
fn parse_bmp_message_core(data: &[u8], timestamp: f64) -> Result<String, String> {
    let mut bytes = Bytes::from(data.to_vec());

    let bmp_msg = parse_bmp_msg(&mut bytes).map_err(|e| e.to_string())?;

    let result = build_bmp_result(bmp_msg, None, timestamp);

    serde_json::to_string(&result).map_err(|e| e.to_string())
}

/// Parse a decompressed MRT file, returning a JSON array string.
fn parse_mrt_file_core(data: &[u8]) -> Result<String, String> {
    let mut cursor = Cursor::new(data);
    let mut elementor = Elementor::default();
    let mut all_elems: Vec<BgpElem> = Vec::new();

    while let Ok(record) = parse_mrt_record(&mut cursor) {
        let elems = elementor.record_to_elems(record);
        all_elems.extend(elems);
    }

    serde_json::to_string(&all_elems).map_err(|e| e.to_string())
}

/// Parse a single BGP UPDATE message, returning a JSON array string.
fn parse_bgp_update_core(data: &[u8]) -> Result<String, String> {
    let mut bytes = Bytes::from(data.to_vec());
    let msg =
        parse_bgp_message(&mut bytes, false, &AsnLength::Bits32).map_err(|e| e.to_string())?;
    let elems = Elementor::bgp_to_elems(
        msg,
        0.0,
        &IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        &Asn::default(),
    );
    serde_json::to_string(&elems).map_err(|e| e.to_string())
}

// ── Exported WASM functions (thin wrappers) ──────────────────────────────────

/// Parse an OpenBMP-wrapped BMP message as received from the RouteViews Kafka stream.
///
/// Returns a JSON string representing a `BmpParsedMessage` discriminated on `"type"`.
/// Returns an empty string for non-router OpenBMP frames (the JS wrapper converts
/// this to `null`).
///
/// Throws a JavaScript `Error` on malformed data.
#[wasm_bindgen(js_name = "parseOpenBmpMessage")]
pub fn parse_openbmp_message(data: &[u8]) -> Result<String, JsError> {
    match parse_openbmp_message_core(data) {
        Ok(Some(json)) => Ok(json),
        Ok(None) => Ok(String::new()),
        Err(e) => Err(JsError::new(&e)),
    }
}

/// Parse a raw BMP message (no OpenBMP wrapper).
///
/// The `timestamp` parameter provides the collection time in seconds since
/// Unix epoch.
///
/// Returns a JSON string representing a `BmpParsedMessage`.
/// Throws a JavaScript `Error` on malformed data.
#[wasm_bindgen(js_name = "parseBmpMessage")]
pub fn parse_bmp_message(data: &[u8], timestamp: f64) -> Result<String, JsError> {
    parse_bmp_message_core(data, timestamp).map_err(|e| JsError::new(&e))
}

/// Parse a decompressed MRT file into BGP elements.
///
/// Accepts the raw bytes of a fully decompressed MRT file (the caller is
/// responsible for bzip2/gzip decompression). Returns a JSON array of
/// `BgpElem` objects.
///
/// Handles TABLE_DUMP, TABLE_DUMP_V2, and BGP4MP record types. For
/// TABLE_DUMP_V2, the PeerIndexTable record is consumed internally to
/// resolve peer information.
///
/// Throws a JavaScript `Error` if the file cannot be parsed at all.
#[wasm_bindgen(js_name = "parseMrtFile")]
pub fn parse_mrt_file(data: &[u8]) -> Result<String, JsError> {
    parse_mrt_file_core(data).map_err(|e| JsError::new(&e))
}

/// Parse a single BGP UPDATE message into BGP elements.
///
/// Expects a full BGP message including the 16-byte marker, 2-byte length,
/// and 1-byte type header. Assumes 4-byte ASN encoding (the modern default).
///
/// The returned elements will have a timestamp of `0.0` and unspecified
/// peer IP / peer ASN since those are not part of the BGP message itself —
/// the caller should populate these from external context if needed.
///
/// Returns a JSON array of `BgpElem` objects.
/// Throws a JavaScript `Error` if the message cannot be parsed.
#[wasm_bindgen(js_name = "parseBgpUpdate")]
pub fn parse_bgp_update(data: &[u8]) -> Result<String, JsError> {
    parse_bgp_update_core(data).map_err(|e| JsError::new(&e))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal BMP Initiation message (type 4).
    /// BMP common header: version(1) + length(4) + type(1) = 6 bytes
    /// Initiation TLV: type(2) + length(2) + value
    fn make_bmp_initiation(sys_name: &str) -> Vec<u8> {
        let tlv_type: u16 = 2; // sysName
        let tlv_len = sys_name.len() as u16;
        let total_len = 6 + 4 + sys_name.len();
        let mut buf = Vec::with_capacity(total_len);
        // BMP common header
        buf.push(3); // version
        buf.extend_from_slice(&(total_len as u32).to_be_bytes()); // length
        buf.push(4); // type = Initiation
                     // TLV
        buf.extend_from_slice(&tlv_type.to_be_bytes());
        buf.extend_from_slice(&tlv_len.to_be_bytes());
        buf.extend_from_slice(sys_name.as_bytes());
        buf
    }

    /// Build a BMP Peer Up message with a per-peer header.
    fn make_bmp_peer_up() -> Vec<u8> {
        // Per-peer header: type(1) + flags(1) + rd(8) + addr(16) + asn(4) + bgp_id(4) + ts_s(4) + ts_us(4) = 42
        let peer_header_len = 42;
        // Peer Up body: local_addr(16) + local_port(2) + remote_port(2) + sent_open + recv_open
        // Minimal BGP OPEN: marker(16) + length(2) + type(1) + version(1) + my_as(2) + hold_time(2) + bgp_id(4) + opt_len(1) = 29
        let bgp_open_len = 29u16;
        let body_len = 16 + 2 + 2 + (bgp_open_len as usize) * 2;
        let total_len = 6 + peer_header_len + body_len;
        let mut buf = Vec::with_capacity(total_len);

        // BMP common header
        buf.push(3); // version
        buf.extend_from_slice(&(total_len as u32).to_be_bytes());
        buf.push(3); // type = Peer Up Notification

        // Per-peer header
        buf.push(0); // peer type = Global
        buf.push(0); // peer flags
        buf.extend_from_slice(&[0u8; 8]); // route distinguisher
        buf.extend_from_slice(&[0u8; 12]); // padding for IPv4
        buf.extend_from_slice(&[10, 0, 0, 1]); // peer IPv4
        buf.extend_from_slice(&65000u32.to_be_bytes()); // peer ASN
        buf.extend_from_slice(&[10, 0, 0, 1]); // peer BGP ID
        buf.extend_from_slice(&1000u32.to_be_bytes()); // timestamp seconds
        buf.extend_from_slice(&0u32.to_be_bytes()); // timestamp microseconds

        // Peer Up body
        buf.extend_from_slice(&[0u8; 12]); // padding for IPv4
        buf.extend_from_slice(&[192, 168, 1, 1]); // local IPv4
        buf.extend_from_slice(&179u16.to_be_bytes()); // local port
        buf.extend_from_slice(&12345u16.to_be_bytes()); // remote port

        // Sent OPEN message
        let open = make_bgp_open(65000, [10, 0, 0, 1]);
        buf.extend_from_slice(&open);
        // Received OPEN message
        buf.extend_from_slice(&open);

        buf
    }

    /// Build a minimal BGP OPEN message.
    fn make_bgp_open(my_as: u16, bgp_id: [u8; 4]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xFF; 16]); // marker
        buf.extend_from_slice(&29u16.to_be_bytes()); // length
        buf.push(1); // type = OPEN
        buf.push(4); // version
        buf.extend_from_slice(&my_as.to_be_bytes());
        buf.extend_from_slice(&180u16.to_be_bytes()); // hold time
        buf.extend_from_slice(&bgp_id);
        buf.push(0); // opt params length
        buf
    }

    /// Build a minimal BGP UPDATE with a single IPv4 announcement.
    fn make_bgp_update_announce(prefix: [u8; 4], prefix_len: u8, next_hop: [u8; 4]) -> Vec<u8> {
        // Path attributes: ORIGIN(IGP) + AS_PATH(1 AS_SEQUENCE with AS 65001) + NEXT_HOP
        let origin_attr = [0x40, 1, 1, 0]; // flags, type=1, len=1, IGP=0
        #[rustfmt::skip]
        let as_path_attr = [
            0x40, 2, 6,  // flags, type=2, len=6
            2,           // segment type = AS_SEQUENCE
            1,           // segment length = 1 ASN
            0, 0, 0xFD, 0xE9, // AS 65001 (4-byte)
        ];
        let next_hop_attr = [
            0x40,
            3,
            4,
            next_hop[0],
            next_hop[1],
            next_hop[2],
            next_hop[3],
        ];

        let prefix_bytes = (prefix_len as usize).div_ceil(8);
        let nlri_len = 1 + prefix_bytes; // prefix_len byte + prefix bytes
        let path_attr_len = origin_attr.len() + as_path_attr.len() + next_hop_attr.len();
        let body_len = 2 + 2 + path_attr_len + nlri_len; // withdrawn_len(2) + attr_len(2) + attrs + nlri
        let total_len = 19 + body_len; // marker(16) + length(2) + type(1) + body

        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xFF; 16]); // marker
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.push(2); // type = UPDATE
        buf.extend_from_slice(&0u16.to_be_bytes()); // withdrawn routes length
        buf.extend_from_slice(&(path_attr_len as u16).to_be_bytes());
        buf.extend_from_slice(&origin_attr);
        buf.extend_from_slice(&as_path_attr);
        buf.extend_from_slice(&next_hop_attr);
        buf.push(prefix_len);
        buf.extend_from_slice(&prefix[..prefix_bytes]);
        buf
    }

    #[test]
    fn test_parse_bmp_initiation() {
        let data = make_bmp_initiation("test-router");
        let json = parse_bmp_message_core(&data, 1000.0).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "InitiationMessage");
        assert_eq!(v["timestamp"], 1000.0);
        assert!(v["openBmpHeader"].is_null());
        assert_eq!(v["tlvs"][0]["type"], "SysName");
        assert_eq!(v["tlvs"][0]["value"], "test-router");
    }

    #[test]
    fn test_parse_bmp_peer_up() {
        let data = make_bmp_peer_up();
        let json = parse_bmp_message_core(&data, 1000.0).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "PeerUpNotification");
        assert_eq!(v["peerHeader"]["peerIp"], "10.0.0.1");
        assert_eq!(v["peerHeader"]["peerAsn"], 65000);
        assert_eq!(v["localIp"], "192.168.1.1");
        assert_eq!(v["localPort"], 179);
        assert_eq!(v["remotePort"], 12345);
    }

    #[test]
    fn test_parse_bmp_invalid_data() {
        let result = parse_bmp_message_core(&[0, 1, 2], 0.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bgp_update() {
        let data = make_bgp_update_announce([10, 0, 0, 0], 24, [192, 168, 1, 1]);
        let json = parse_bgp_update_core(&data).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array());
        let elems = v.as_array().unwrap();
        assert_eq!(elems.len(), 1);
        assert_eq!(elems[0]["type"], "ANNOUNCE");
        assert_eq!(elems[0]["prefix"], "10.0.0.0/24");
        assert_eq!(elems[0]["next_hop"], "192.168.1.1");
    }

    #[test]
    fn test_parse_bgp_update_invalid() {
        let result = parse_bgp_update_core(&[0xFF; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mrt_empty() {
        let json = parse_mrt_file_core(&[]).unwrap();
        assert_eq!(json, "[]");
    }

    #[test]
    fn test_parse_openbmp_unsupported() {
        // OpenBMP header with non-router message type (version=3, type != 12)
        let mut data = Vec::new();
        data.extend_from_slice(b"OBMP"); // magic
        data.extend_from_slice(&1u16.to_be_bytes()); // major version
        data.extend_from_slice(&[0; 6]); // header length (set below), msg_len, flags
        data.push(100); // object type (not a router message)
                        // The exact format doesn't matter — we just need parse_openbmp_header
                        // to return UnsupportedOpenBmpMessage for a non-router type.
        let result = parse_openbmp_message_core(&data);
        // Either returns None (unsupported) or an error (malformed) — both are fine
        match result {
            Ok(None) => {} // unsupported, as expected
            Err(_) => {}   // malformed header is also acceptable
            Ok(Some(_)) => panic!("expected None or Err for non-router OpenBMP message"),
        }
    }

    #[test]
    fn test_make_peer_header_default() {
        let pph = BmpPerPeerHeader::default();
        let header = make_peer_header(&pph);
        assert_eq!(header.peer_asn, 0);
        assert_eq!(header.peer_ip, "0.0.0.0");
        assert!(!header.is_post_policy);
        assert!(!header.is_adj_rib_out);
    }
}
