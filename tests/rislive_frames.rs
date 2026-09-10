//! RIS Live regression tests against captured stream frames.
//!
//! The fixture holds real frames, including UPDATEs whose `next_hop` is an
//! RFC 2545 comma-joined global + link-local pair (~20% of UPDATE frames).
//! That form used to fail deserialisation, and the flattened `RisMessage::msg`
//! `Option` surfaced the error as `msg: None` — routes silently dropped.
//!
//! Frames are selected by content, never by line position, so the fixture can
//! be regenerated or extended freely (see its README).
//!
//! Run with: `cargo test --features rislive --test rislive_frames`
#![cfg(feature = "rislive")]

use bgpkit_parser::models::{ElemType, MetaCommunity, NetworkPrefix};
use bgpkit_parser::rislive::messages::{Announcement, RisLiveMessage, RisMessage, RisMessageEnum};
use bgpkit_parser::{parse_ris_live_message, parse_ris_live_message_raw, BgpElem};
use std::collections::HashSet;
use std::net::IpAddr;

const FRAMES: &str = include_str!("fixtures/rislive/ris-live-frames.jsonl");

fn frames() -> impl Iterator<Item = &'static str> {
    FRAMES.lines().filter(|line| !line.trim().is_empty())
}

fn ris_message(frame: &str) -> RisMessage {
    match serde_json::from_str(frame).expect("frame is valid JSON") {
        RisLiveMessage::RisMessage(msg) => msg,
        other => panic!("expected a ris_message, got {other:?}"),
    }
}

/// The frame's announcements and withdrawals, when it is an UPDATE.
fn update_routes(msg: &RisMessage) -> Option<(&[Announcement], &[String])> {
    match &msg.msg {
        Some(RisMessageEnum::UPDATE {
            announcements,
            withdrawals,
            ..
        }) => Some((
            announcements.as_deref().unwrap_or_default(),
            withdrawals.as_deref().unwrap_or_default(),
        )),
        _ => None,
    }
}

fn has_comma_joined_next_hop(msg: &RisMessage) -> bool {
    update_routes(msg)
        .map(|(announcements, _)| announcements.iter().any(|a| a.next_hop.contains(',')))
        .unwrap_or(false)
}

/// One sortable string per elem, over the fields RIS Live projects into JSON.
///
/// Excluded (raw-only): large/extended communities, OTC, local-pref,
/// atomic-aggregate, peer BGP id, origin-ASN derivation. Plain communities
/// are compared, empty normalised to `None`. Absent MED is normalised to 0 —
/// the raw path has always reported a missing MED as `Some(0)`
/// (`get_relevant_attributes` in `src/parser/mrt/mrt_elem.rs`).
fn projected_key(elem: &BgpElem) -> String {
    let communities: Option<Vec<&MetaCommunity>> = elem.communities.as_ref().and_then(|cs| {
        let plain: Vec<&MetaCommunity> = cs
            .iter()
            .filter(|c| matches!(c, MetaCommunity::Plain(_)))
            .collect();
        (!plain.is_empty()).then_some(plain)
    });
    format!(
        "{:?} {} ts={} peer={} asn={} nh={:?} path={:?} origin={:?} med={} communities={:?} aggr={:?}/{:?}",
        elem.elem_type,
        elem.prefix,
        elem.timestamp,
        elem.peer_ip,
        elem.peer_asn,
        elem.next_hop,
        elem.as_path,
        elem.origin,
        elem.med.unwrap_or(0),
        communities,
        elem.aggr_asn,
        elem.aggr_ip,
    )
}

fn sorted_keys(elems: &[BgpElem]) -> Vec<String> {
    let mut keys: Vec<String> = elems.iter().map(projected_key).collect();
    keys.sort();
    keys
}

/// Every captured frame must deserialise into a typed message — a body-level
/// deserialisation failure surfaces as `msg: None` and silently costs all of
/// the frame's routes. Also asserts the fixture keeps covering the message
/// types and the comma-joined form these tests exist for.
#[test]
fn every_captured_frame_deserialises_to_a_typed_message() {
    let mut types = HashSet::new();
    let mut comma_joined_frames = 0;
    for frame in frames() {
        let msg = ris_message(frame);
        let Some(msg_body) = &msg.msg else {
            panic!("frame from {} has no message body: {frame}", msg.host);
        };
        types.insert(match msg_body {
            RisMessageEnum::UPDATE { .. } => "UPDATE",
            RisMessageEnum::KEEPALIVE { .. } => "KEEPALIVE",
            RisMessageEnum::OPEN { .. } => "OPEN",
            RisMessageEnum::NOTIFICATION { .. } => "NOTIFICATION",
            RisMessageEnum::RIS_PEER_STATE { .. } => "STATE",
        });
        if has_comma_joined_next_hop(&msg) {
            comma_joined_frames += 1;
        }
    }
    for expected in ["UPDATE", "KEEPALIVE", "OPEN", "NOTIFICATION", "STATE"] {
        assert!(
            types.contains(expected),
            "fixture lost its {expected} frame"
        );
    }
    assert!(
        comma_joined_frames > 0,
        "fixture lost its comma-joined next-hop UPDATE frames"
    );
}

/// UPDATEs with a comma-joined next hop yield every announced and withdrawn
/// route, with the global half of the pair as the next hop.
#[test]
fn comma_joined_next_hop_yields_all_routes() {
    let mut checked = 0;
    for frame in frames() {
        let msg = ris_message(frame);
        if !has_comma_joined_next_hop(&msg) {
            continue;
        }
        checked += 1;
        let (announcements, withdrawals) = update_routes(&msg).unwrap();
        let elems = parse_ris_live_message(frame).unwrap();

        // independent oracle: resolve the pair by scope without NextHopAddress
        for announcement in announcements {
            let addresses: Vec<IpAddr> = announcement
                .next_hop
                .split(',')
                .map(|addr| addr.trim().parse().unwrap())
                .collect();
            let global = *addresses
                .iter()
                .find(|addr| !matches!(addr, IpAddr::V6(v6) if v6.is_unicast_link_local()))
                .expect("captured pairs carry a global address");
            for prefix in &announcement.prefixes {
                assert!(
                    elems.iter().any(|elem| elem.elem_type == ElemType::ANNOUNCE
                        && elem.prefix.to_string() == *prefix
                        && elem.next_hop == Some(global)),
                    "missing announcement of {prefix} via {global} in frame {}",
                    msg.id
                );
            }
        }

        // withdrawals were silently lost when the announcement next to them
        // failed to deserialise
        for prefix in withdrawals {
            // fixture prefixes use expanded-zero notation; compare parsed
            let withdrawn = prefix.parse::<NetworkPrefix>().unwrap();
            assert!(
                elems.iter().any(|elem| elem.elem_type == ElemType::WITHDRAW
                    && elem.prefix.prefix == withdrawn.prefix),
                "missing withdrawal of {prefix} in frame {}",
                msg.id
            );
        }

        let announced: usize = announcements.iter().map(|a| a.prefixes.len()).sum();
        assert_eq!(
            elems.len(),
            announced + withdrawals.len(),
            "route count mismatch for frame {}",
            msg.id
        );
    }
    assert!(
        checked > 0,
        "no comma-joined next-hop UPDATE frames in fixture"
    );
}

/// The JSON projection and the authoritative raw BGP bytes must describe the
/// same routes — the check that catches a silently lossy JSON path. Compared
/// on the fields RIS Live projects into JSON (see [`projected_key`]). Exact
/// for the current feed; a historic-style capture splitting one route across
/// two announcement entries would legitimately give the JSON side an extra elem.
#[test]
fn json_and_raw_paths_agree_for_update_frames() {
    let mut compared = 0;
    for frame in frames() {
        let msg = ris_message(frame);
        if update_routes(&msg).is_none() || msg.raw.is_none() {
            continue;
        }

        let from_json = parse_ris_live_message(frame).unwrap();
        let from_raw = parse_ris_live_message_raw(frame).unwrap();
        assert_eq!(
            sorted_keys(&from_json),
            sorted_keys(&from_raw),
            "JSON and raw parsers disagree for frame {}",
            msg.id
        );
        compared += 1;
    }
    assert!(compared > 0, "no UPDATE frames with raw bytes in fixture");
}
