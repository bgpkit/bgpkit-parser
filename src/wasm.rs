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

// ── Exported WASM functions ──────────────────────────────────────────────────

/// Parse an OpenBMP-wrapped BMP message as received from the RouteViews Kafka stream.
///
/// Returns a JSON string representing a `BmpParsedMessage` discriminated on `"type"`.
/// Returns an empty string for non-router OpenBMP frames (the JS wrapper converts
/// this to `null`).
///
/// Throws a JavaScript `Error` on malformed data.
#[wasm_bindgen(js_name = "parseOpenBmpMessage")]
pub fn parse_openbmp_message(data: &[u8]) -> Result<String, JsError> {
    let mut bytes = Bytes::from(data.to_vec());

    let header = match parse_openbmp_header(&mut bytes) {
        Ok(h) => h,
        Err(ParserBmpError::UnsupportedOpenBmpMessage) => return Ok(String::new()),
        Err(e) => return Err(JsError::new(&e.to_string())),
    };

    let bmp_msg = parse_bmp_msg(&mut bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let result = build_bmp_result(
        bmp_msg,
        Some(make_openbmp_header(&header)),
        header.timestamp,
    );

    serde_json::to_string(&result).map_err(|e| JsError::new(&e.to_string()))
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
    let mut bytes = Bytes::from(data.to_vec());

    let bmp_msg = parse_bmp_msg(&mut bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let result = build_bmp_result(bmp_msg, None, timestamp);

    serde_json::to_string(&result).map_err(|e| JsError::new(&e.to_string()))
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
    let mut cursor = Cursor::new(data);
    let mut elementor = Elementor::default();
    let mut all_elems: Vec<BgpElem> = Vec::new();

    while let Ok(record) = parse_mrt_record(&mut cursor) {
        let elems = elementor.record_to_elems(record);
        all_elems.extend(elems);
    }

    serde_json::to_string(&all_elems).map_err(|e| JsError::new(&e.to_string()))
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
    let mut bytes = Bytes::from(data.to_vec());
    let msg = parse_bgp_message(&mut bytes, false, &AsnLength::Bits32)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let elems = Elementor::bgp_to_elems(
        msg,
        0.0,
        &IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        &Asn::default(),
    );
    serde_json::to_string(&elems).map_err(|e| JsError::new(&e.to_string()))
}
