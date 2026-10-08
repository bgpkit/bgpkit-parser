/*!
Provides parsing functions for [RIS-Live](https://ris-live.ripe.net/manual/) real-time
BGP message stream JSON data.

The main parsing function, [parse_ris_live_message] converts RIS Live's JSON-projected UPDATE
fields into a vector of [BgpElem]s. If you subscribe with `includeRaw`, use
[parse_ris_live_message_raw] to parse the original BGP wire message instead; this preserves BGP
attributes that RIS Live omits from its JSON fields.

Here is an example parsing stream data from one collector:
```no_run
use bgpkit_parser::{parse_ris_live_message_raw, RisLiveClientMessage, RisSubscribe};
use tungstenite::{connect, Message};

const RIS_LIVE_URL: &str = "ws://ris-live.ripe.net/v1/ws/?client=rust-bgpkit-parser";

/// This is an example of subscribing to RIS-Live's streaming data from one host (`rrc21`).
///
/// For more RIS-Live details, check out their documentation at https://ris-live.ripe.net/manual/
fn main() {
    // connect to RIPE RIS Live websocket server
    let (mut socket, _response) =
        connect(RIS_LIVE_URL)
            .expect("Can't connect to RIS Live websocket server");

    // subscribe to messages from one collector and request hex-encoded raw BGP messages
    let msg = RisSubscribe::new().host("rrc21").include_raw(true).to_json_string();
    socket.send(Message::Text(msg.into())).unwrap();

    loop {
        let msg = socket.read().expect("Error reading message").to_string();
        if let Ok(elems) = parse_ris_live_message_raw(msg.as_str()) {
            for elem in elems {
                println!("{}", elem);
            }
        }
    }
}
```
*/
use crate::parser::rislive::error::ParserRisliveError;
pub use crate::parser::rislive::messages::parse_ris_live_message_raw;
pub use crate::parser::rislive::messages::{
    parse_ris_live_message_raw_full, RisLiveMeta, RisLiveRawFull,
};
use crate::parser::rislive::messages::{RisLiveMessage, RisMessageEnum};

use crate::models::*;
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr};

pub mod error;
pub mod messages;

// simple macro to make the code look a bit nicer
macro_rules! unwrap_or_return {
    ( $e:expr, $msg_string:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return Err(ParserRisliveError::IncorrectJson($msg_string)),
        }
    };
}

/// Parse a RIS Live next-hop string — one address or a comma-joined RFC 2545
/// pair — into its scope-resolved global address.
fn parse_next_hop(next_hop: String) -> Result<IpAddr, ParserRisliveError> {
    match next_hop.parse::<NextHopAddress>() {
        Ok(addr) => Ok(addr.global_addr()),
        Err(_) => Err(ParserRisliveError::ElemIncorrectIp(next_hop)),
    }
}

/// parse prefix string into IpNet
fn parse_prefix(prefix_str: &str) -> Result<IpNet, ParserRisliveError> {
    let p = match prefix_str.parse::<IpNet>() {
        Ok(net) => net,
        Err(_) => {
            if prefix_str == "eor" {
                return Err(ParserRisliveError::ElemEndOfRibPrefix);
            }
            return Err(ParserRisliveError::ElemIncorrectPrefix(
                prefix_str.to_string(),
            ));
        }
    };
    Ok(p)
}

/// Message types this crate decodes, as RIS Live spells them in the body's `type` field.
///
/// Frames that declare one of these must produce a body. Keep in sync with [`RisMessageEnum`]:
/// a missing entry only costs the loud failure for that type, never a wrong result.
const DECODED_MESSAGE_TYPES: [&str; 6] = [
    "UPDATE",
    "KEEPALIVE",
    "OPEN",
    "NOTIFICATION",
    "STATE",
    "RIS_PEER_STATE",
];

/// Explain a `RisMessage::msg` that came out `None` although the frame declares a decoded
/// message type.
///
/// The flattened `Option<RisMessageEnum>` reports a body-level deserialisation failure as
/// `None`, so the caller sees an empty frame and loses every route it carried. Re-deserialising
/// the body here keeps the underlying reason.
fn unparsed_body_error(msg_str: &str) -> Option<ParserRisliveError> {
    #[derive(serde::Deserialize)]
    struct Envelope {
        data: Option<serde_json::Value>,
    }

    let envelope: Envelope = serde_json::from_str(msg_str).ok()?;
    let data = envelope.data?;
    let message_type = data.get("type")?.as_str()?.to_string();
    if !DECODED_MESSAGE_TYPES.contains(&message_type.as_str()) {
        // a message type this crate does not decode yet: nothing was lost
        return None;
    }

    serde_json::from_value::<RisMessageEnum>(data)
        .err()
        .map(|e| ParserRisliveError::UnparsedMessageBody(format!("{message_type}: {e}")))
}

/// Parse one RIS Live message using RIS Live's JSON-projected UPDATE fields.
///
/// This parser is convenient and does not require `socketOptions.includeRaw`, but RIS Live's JSON
/// schema exposes only a subset of BGP path attributes. Use [`parse_ris_live_message_raw`] when you
/// need attributes that are only present in the raw BGP message.
///
/// A frame that declares a message type this crate decodes but whose body fails to deserialize
/// returns [`ParserRisliveError::UnparsedMessageBody`] rather than no elems: callers streaming
/// frames should log and skip it, and can fall back to [`parse_ris_live_message_raw`], which reads
/// the `raw` bytes instead of the projection.
///
/// Every elem carries its own copy of the message's AS path and communities, so the returned
/// `Vec` grows with prefixes × path length. For messages that announce many prefixes, use
/// [`parse_ris_live_message_iter`] to produce the elems one at a time instead.
pub fn parse_ris_live_message(msg_str: &str) -> Result<Vec<BgpElem>, ParserRisliveError> {
    Ok(parse_ris_live_message_iter(msg_str)?.collect())
}

/// Parse one RIS Live message into an iterator over its elems.
///
/// Same inputs, validation, and elems as [`parse_ris_live_message`], but the per-prefix copies of
/// the AS path and communities are made as each elem is yielded rather than all at once, so memory
/// stays bounded by one elem plus the parsed prefix list. The message is validated up front: any
/// error this function would report is returned here, and iteration itself cannot fail.
pub fn parse_ris_live_message_iter(msg_str: &str) -> Result<RisLiveElemIter, ParserRisliveError> {
    // parse RIS Live message to internal struct using serde.
    let msg: RisLiveMessage = match serde_json::from_str(msg_str) {
        Ok(m) => m,
        Err(_e) => return Err(ParserRisliveError::IncorrectJson(msg_str.to_string())),
    };

    // we currently only handle the `ris_message` data type. other types provide meta
    // information, but reveal no BGP elements, and thus for now will be ignored.
    let RisLiveMessage::RisMessage(ris_msg) = msg else {
        return Ok(RisLiveElemIter::empty());
    };

    let Some(body) = ris_msg.msg else {
        // `msg` is flattened, so a body-level deserialisation failure arrives here as
        // `None`: indistinguishable from a frame without a body, and silently empty.
        if let Some(err) = unparsed_body_error(msg_str) {
            return Err(err);
        }
        return Ok(RisLiveElemIter::empty());
    };

    let RisMessageEnum::UPDATE {
        path,
        community,
        origin,
        med,
        aggregator,
        announcements,
        withdrawals,
    } = body
    else {
        return Ok(RisLiveElemIter::empty());
    };

    // parse community
    let communities = community.map(|values| {
        values
            .into_iter()
            .map(|(asn, data)| MetaCommunity::Plain(Community::Custom(Asn::new_32bit(asn), data)))
            .collect()
    });

    // parse origin
    let bgp_origin = match origin {
        None => None,
        Some(o) => Some(match o.as_str() {
            "igp" | "IGP" => Origin::IGP,
            "egp" | "EGP" => Origin::EGP,
            "incomplete" | "INCOMPLETE" => Origin::INCOMPLETE,
            other => {
                return Err(ParserRisliveError::ElemUnknownOriginType(other.to_string()));
            }
        }),
    };

    // parse aggregator
    let (aggr_asn, aggr_ip) = match aggregator {
        None => (None, None),
        Some(aggr_str) => {
            let (asn_str, ip_str) = match aggr_str.split_once(':') {
                None => return Err(ParserRisliveError::ElemIncorrectAggregator(aggr_str)),
                Some(v) => v,
            };

            let asn = unwrap_or_return!(asn_str.parse::<Asn>(), msg_str.to_string());
            let ip = unwrap_or_return!(ip_str.parse::<Ipv4Addr>(), msg_str.to_string());
            (Some(asn), Some(ip))
        }
    };

    // validate announcements and withdrawals now, so iteration cannot fail
    let announcements = announcements.unwrap_or_default();
    let mut announced = Vec::with_capacity(
        announcements
            .iter()
            .map(|a| a.prefixes.len())
            .sum::<usize>(),
    );
    for announcement in announcements {
        let next_hop = parse_next_hop(announcement.next_hop)?;
        for prefix in &announcement.prefixes {
            announced.push((parse_prefix(prefix.as_str())?, next_hop));
        }
    }
    let withdrawn = withdrawals
        .unwrap_or_default()
        .iter()
        .map(|prefix| parse_prefix(prefix.as_str()))
        .collect::<Result<Vec<_>, _>>()?;

    let origin_asns = path
        .as_ref()
        .map(|as_path| as_path.iter_origins().collect());

    Ok(RisLiveElemIter {
        attrs: Some(RisLiveUpdateAttrs {
            timestamp: ris_msg.timestamp,
            peer_ip: ris_msg.peer,
            peer_asn: ris_msg.peer_asn,
            as_path: path,
            origin_asns,
            origin: bgp_origin,
            med,
            communities,
            aggr_asn,
            aggr_ip,
        }),
        announced: announced.into_iter(),
        withdrawn: withdrawn.into_iter(),
    })
}

/// The attributes one RIS Live UPDATE message shares across all of its elems.
#[derive(Debug)]
struct RisLiveUpdateAttrs {
    timestamp: f64,
    peer_ip: IpAddr,
    peer_asn: Asn,
    as_path: Option<AsPath>,
    origin_asns: Option<Vec<Asn>>,
    origin: Option<Origin>,
    med: Option<u32>,
    communities: Option<Vec<MetaCommunity>>,
    aggr_asn: Option<Asn>,
    aggr_ip: Option<BgpIdentifier>,
}

/// Iterator over the elems of one RIS Live message, produced by [`parse_ris_live_message_iter`].
///
/// Announcements are yielded first, in message order, then withdrawals. The shared AS path,
/// origin ASNs and communities are cloned into each announcement as it is yielded; the last
/// announcement takes them without a copy.
#[derive(Debug)]
pub struct RisLiveElemIter {
    attrs: Option<RisLiveUpdateAttrs>,
    announced: std::vec::IntoIter<(IpNet, IpAddr)>,
    withdrawn: std::vec::IntoIter<IpNet>,
}

impl RisLiveElemIter {
    /// An iterator for a message that carries no elems.
    fn empty() -> Self {
        Self {
            attrs: None,
            announced: Vec::new().into_iter(),
            withdrawn: Vec::new().into_iter(),
        }
    }
}

impl Iterator for RisLiveElemIter {
    type Item = BgpElem;

    fn next(&mut self) -> Option<BgpElem> {
        let attrs = self.attrs.as_mut()?;

        if let Some((prefix, next_hop)) = self.announced.next() {
            // the last announcement takes the shared attributes instead of cloning them
            let (as_path, origin_asns, communities) = if self.announced.len() == 0 {
                (
                    attrs.as_path.take(),
                    attrs.origin_asns.take(),
                    attrs.communities.take(),
                )
            } else {
                (
                    attrs.as_path.clone(),
                    attrs.origin_asns.clone(),
                    attrs.communities.clone(),
                )
            };
            return Some(BgpElem {
                timestamp: attrs.timestamp,
                elem_type: ElemType::ANNOUNCE,
                peer_ip: attrs.peer_ip,
                peer_asn: attrs.peer_asn,
                peer_bgp_id: None,
                prefix: NetworkPrefix {
                    prefix,
                    path_id: None,
                },
                next_hop: Some(next_hop),
                as_path,
                origin_asns,
                origin: attrs.origin,
                local_pref: None,
                med: attrs.med,
                communities,
                atomic: false,
                aggr_asn: attrs.aggr_asn,
                aggr_ip: attrs.aggr_ip,
                only_to_customer: None,
                unknown: None,
                deprecated: None,
                error_handling: None,
            });
        }

        let prefix = self.withdrawn.next()?;
        Some(BgpElem {
            timestamp: attrs.timestamp,
            elem_type: ElemType::WITHDRAW,
            peer_ip: attrs.peer_ip,
            peer_asn: attrs.peer_asn,
            peer_bgp_id: None,
            prefix: NetworkPrefix {
                prefix,
                path_id: None,
            },
            next_hop: None,
            as_path: None,
            origin_asns: None,
            origin: None,
            local_pref: None,
            med: None,
            communities: None,
            atomic: false,
            aggr_asn: None,
            aggr_ip: None,
            only_to_customer: None,
            unknown: None,
            deprecated: None,
            error_handling: None,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.announced.len() + self.withdrawn.len();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for RisLiveElemIter {}

/// Alias for [`parse_ris_live_message`] to make the JSON-vs-raw choice explicit.
pub fn parse_ris_live_message_json(msg_str: &str) -> Result<Vec<BgpElem>, ParserRisliveError> {
    parse_ris_live_message(msg_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ris_live_msg() {
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1636247118.76,"peer":"2001:7f8:24::82","peer_asn":"58299","id":"20-5761-238131559","host":"rrc20","type":"UPDATE","path":[58299,49981,397666],"origin":"igp","announcements":[{"next_hop":"2001:7f8:24::82","prefixes":["2602:fd9e:f00::/40"]},{"next_hop":"fe80::768e:f8ff:fea6:b2c4","prefixes":["2602:fd9e:f00::/40"]}],"raw":"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF005A02000000434001010040020E02030000E3BB0000C33D00061162800E2B00020120200107F8002400000000000000000082FE80000000000000768EF8FFFEA6B2C400282602FD9E0F"}}
        "#;
        let msg = parse_ris_live_message(msg_str).unwrap();
        for elem in msg {
            println!("{elem}");
        }
    }

    #[test]
    fn test_error_message() {
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1636342486.17,"peer":"37.49.237.175","peer_asn":"199524","id":"21-587-22045871","host":"rrc21","type":"UPDATE","path":[199524,1299,3356,13904,13904,13904,13904,13904,13904],"origin":"igp","aggregator":"65000:8.42.232.1","announcements":[{"next_hop":"37.49.237.175","prefixes":["64.68.236.0/22"]}]}}
        "#;
        let msg = parse_ris_live_message(msg_str).unwrap();
        for elem in msg {
            println!("{elem}");
        }
    }

    #[test]
    fn test_error_message_2() {
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1636339375.83,"peer":"37.49.236.1","peer_asn":"8218","id":"21-594-37970252","host":"rrc21"}}
        "#;
        let msg = parse_ris_live_message(msg_str).unwrap();
        for elem in msg {
            println!("{elem}");
        }
    }

    #[test]
    fn test_error_message_3() {
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1640553894.84,"peer":"195.66.226.38","peer_asn":"24482","id":"01-2833-11980099","host":"rrc01","type":"UPDATE","path":[24482,30844,328471,328471,328471],"community":[[0,5713],[0,6939],[0,32934],[8714,65010],[8714,65012],[24482,2],[24482,12010],[24482,12011],[24482,65201],[30844,27]],"origin":"igp","aggregator":"4200000002:10.102.100.2","announcements":[{"next_hop":"195.66.224.68","prefixes":["102.66.116.0/24"]}]}}
        "#;
        let msg = parse_ris_live_message(msg_str).unwrap();
        for elem in msg {
            println!("{elem}");
        }
    }

    #[test]
    fn test_ris_live_with_withdrawals() {
        // correct prefix
        let msg_str = r#"{ "type": "ris_message", "data": { "timestamp": 1740561857.910, "peer": "2606:6dc0:1301::1", "peer_asn": "13781", "id": "2606:6dc0:1301::1-019541923d760008", "host": "rrc25.ripe.net", "type": "UPDATE", "path": [], "community": [], "announcements": [], "withdrawals": [ "2605:de00:bb:0:0:0:0:0/48" ] } }"#;
        let elems = parse_ris_live_message(msg_str).unwrap();
        assert_eq!(elems.len(), 1);
        assert_eq!(elems[0].elem_type, ElemType::WITHDRAW);
    }

    #[test]
    fn test_comma_joined_next_hop_resolves_by_scope() {
        // reversed RFC 2545 pair: the global address is still the next hop
        let msg_str = r#"{"type": "ris_message","data":{"timestamp":1636247118.76,"peer":"2001:7f8:24::82","peer_asn":"58299","id":"20-5761-238131559","host":"rrc20","type":"UPDATE","path":[58299,49981,397666],"origin":"igp","announcements":[{"next_hop":"fe80::768e:f8ff:fea6:b2c4,2001:7f8:24::82","prefixes":["2602:fd9e:f00::/40"]}]}}"#;
        let elems = parse_ris_live_message(msg_str).unwrap();
        assert_eq!(elems.len(), 1);
        assert_eq!(elems[0].next_hop, Some("2001:7f8:24::82".parse().unwrap()));
    }

    #[test]
    fn test_incorrect_next_hop() {
        // a loud error, like bad origins/aggregators/prefixes — not a
        // silently dropped UPDATE
        for bad in ["fe80::1%eth0", "2001:db8::1,fe80::1,fe80::2", ""] {
            let msg_str = format!(
                r#"{{"type": "ris_message","data":{{"timestamp":1636247118.76,"peer":"2001:7f8:24::82","peer_asn":"58299","id":"20-5761-238131559","host":"rrc20","type":"UPDATE","path":[58299,49981],"origin":"igp","announcements":[{{"next_hop":"{bad}","prefixes":["2602:fd9e:f00::/40"]}}]}}}}"#
            );
            match parse_ris_live_message(&msg_str) {
                Err(ParserRisliveError::ElemIncorrectIp(value)) => assert_eq!(value, bad),
                other => panic!("expected ElemIncorrectIp for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_unparsed_body_is_an_error_not_empty_elems() {
        // A frame that declares a message type this crate decodes must produce a body: the
        // flattened `Option` reports a body-level deserialisation failure as `None`, which used
        // to come back as `Ok(vec![])` with every route in the frame silently dropped.
        let broken_bodies = [
            (
                "UPDATE",
                r#"{"type":"ris_message","data":{"timestamp":1789019601.670,"peer":"2001:7f8:4::1","peer_asn":"207841","id":"x-1","host":"rrc01.ripe.net","type":"UPDATE","path":[207841,6939],"med":"high","announcements":[{"next_hop":"2001:db8::1","prefixes":["2001:db8::/32"]}]}}"#,
            ),
            (
                "OPEN",
                r#"{"type":"ris_message","data":{"timestamp":1789019601.670,"peer":"2001:7f8:4::1","peer_asn":"207841","id":"x-2","host":"rrc01.ripe.net","type":"OPEN"}}"#,
            ),
            (
                "NOTIFICATION",
                r#"{"type":"ris_message","data":{"timestamp":1789019601.670,"peer":"2001:7f8:4::1","peer_asn":"207841","id":"x-3","host":"rrc01.ripe.net","type":"NOTIFICATION","notification":"code 6"}}"#,
            ),
            (
                "STATE",
                r#"{"type":"ris_message","data":{"timestamp":1789019601.670,"peer":"2001:7f8:4::1","peer_asn":"207841","id":"x-4","host":"rrc01.ripe.net","type":"STATE","state":7}}"#,
            ),
        ];
        for (message_type, frame) in broken_bodies {
            let err = parse_ris_live_message(frame).unwrap_err();
            assert!(
                matches!(&err, ParserRisliveError::UnparsedMessageBody(_)),
                "expected UnparsedMessageBody for {message_type}, got {err:?}"
            );
            assert!(
                err.to_string().starts_with(&format!(
                    "message body failed to deserialize: {message_type}: "
                )),
                "reason should name the declared type: {err}"
            );
        }
    }

    #[test]
    fn test_undecoded_frames_still_yield_no_elems() {
        // nothing is lost for a message type this crate does not decode, or for an empty
        // UPDATE: those keep returning no elems rather than erroring
        for frame in [
            r#"{"type":"ris_message","data":{"timestamp":1789019601.670,"peer":"2001:7f8:4::1","peer_asn":"207841","id":"x-5","host":"rrc01.ripe.net","type":"SOMETHING_NEW","payload":{}}}"#,
            r#"{"type":"ris_message","data":{"timestamp":1789019601.670,"peer":"2001:7f8:4::1","peer_asn":"207841","id":"x-6","host":"rrc01.ripe.net","type":"UPDATE","path":[],"announcements":[],"withdrawals":[]}}"#,
            r#"{"type":"ris_error","data":{"message":"client too slow"}}"#,
        ] {
            let elems = parse_ris_live_message(frame).unwrap();
            assert!(elems.is_empty(), "expected no elems for {frame}");
        }
    }

    #[test]
    fn test_parse_prefix() {
        // parse correct ipv4 prefix
        let prefix_str = "192.0.2.0/24".to_string();
        let parse_result = parse_prefix(&prefix_str);
        assert!(parse_result.is_ok());
        assert_eq!(parse_result.unwrap().to_string().as_str(), &prefix_str);

        // parse correct ipv6 prefix
        let prefix_str = "2001:db8::/32".to_string();
        let parse_result = parse_prefix(&prefix_str);
        assert!(parse_result.is_ok());
        assert_eq!(parse_result.unwrap().to_string().as_str(), &prefix_str);

        // parse incorrect ipv4 prefix
        let prefix_str = "192.0.2.0/38".to_string();
        let parse_result = parse_prefix(&prefix_str);
        assert!(parse_result.is_err());
        matches!(
            parse_result,
            Err(ParserRisliveError::ElemIncorrectPrefix(_))
        );

        // parse eof string
        let prefix_str = "eor".to_string();
        let parse_result = parse_prefix(&prefix_str);
        assert!(parse_result.is_err());
        matches!(parse_result, Err(ParserRisliveError::ElemEndOfRibPrefix));
    }

    #[test]
    fn test_unknown_origin_type() {
        // Test with an unknown origin type
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1636247118.76,"peer":"2001:7f8:24::82","peer_asn":"58299","id":"20-5761-238131559","host":"rrc20","type":"UPDATE","path":[58299,49981,397666],"origin":"unknown","announcements":[{"next_hop":"2001:7f8:24::82","prefixes":["2602:fd9e:f00::/40"]}]}}
        "#;

        let result = parse_ris_live_message(msg_str);
        assert!(result.is_err());

        if let Err(ParserRisliveError::ElemUnknownOriginType(origin_type)) = result {
            assert_eq!(origin_type, "unknown");
        } else {
            panic!("Expected ElemUnknownOriginType error");
        }
    }

    #[test]
    fn test_incorrect_aggregator_format() {
        // Test with an incorrect aggregator format (missing colon)
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1636247118.76,"peer":"2001:7f8:24::82","peer_asn":"58299","id":"20-5761-238131559","host":"rrc20","type":"UPDATE","path":[58299,49981,397666],"origin":"igp","aggregator":"65000-8.42.232.1","announcements":[{"next_hop":"2001:7f8:24::82","prefixes":["2602:fd9e:f00::/40"]}]}}
        "#;

        let result = parse_ris_live_message(msg_str);
        assert!(result.is_err());

        if let Err(ParserRisliveError::ElemIncorrectAggregator(aggregator)) = result {
            assert_eq!(aggregator, "65000-8.42.232.1");
        } else {
            panic!("Expected ElemIncorrectAggregator error");
        }
    }

    #[test]
    fn test_non_ris_message() {
        // Test with a non-RIS message
        let msg_str = r#"
        {"type": "other_message","data":{}}
        "#;

        let result = parse_ris_live_message(msg_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_non_update_message() {
        // Test with a RIS message that is not an UPDATE message
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1636247118.76,"peer":"2001:7f8:24::82","peer_asn":"58299","id":"20-5761-238131559","host":"rrc20","type":"OTHER","msg":{"type":"OTHER"}}}
        "#;

        let result = parse_ris_live_message(msg_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn iter_yields_one_elem_per_prefix_with_the_shared_attributes() {
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1640553894.84,"peer":"195.66.226.38","peer_asn":"24482","id":"01-2833-11980099","host":"rrc01","type":"UPDATE","path":[24482,30844,328471],"community":[[0,5713],[24482,2]],"origin":"igp","med":10,"aggregator":"4200000002:10.102.100.2","announcements":[{"next_hop":"195.66.224.68","prefixes":["102.66.116.0/24","102.66.117.0/24"]},{"next_hop":"195.66.224.69","prefixes":["102.66.118.0/24"]}],"withdrawals":["10.0.0.0/24","10.0.1.0/24"]}}
        "#;
        let iter = parse_ris_live_message_iter(msg_str).unwrap();
        assert_eq!(iter.len(), 5);
        let elems: Vec<BgpElem> = iter.collect();

        let peer_ip: IpAddr = "195.66.226.38".parse().unwrap();
        let as_path = AsPath::from_sequence([24482, 30844, 328471]);
        let communities = vec![
            MetaCommunity::Plain(Community::Custom(Asn::new_32bit(0), 5713)),
            MetaCommunity::Plain(Community::Custom(Asn::new_32bit(24482), 2)),
        ];
        let announce = |prefix: &str, next_hop: &str| BgpElem {
            timestamp: 1640553894.84,
            elem_type: ElemType::ANNOUNCE,
            peer_ip,
            peer_asn: Asn::new_32bit(24482),
            prefix: NetworkPrefix::new(prefix.parse().unwrap(), None),
            next_hop: Some(next_hop.parse().unwrap()),
            as_path: Some(as_path.clone()),
            origin_asns: Some(vec![Asn::new_32bit(328471)]),
            origin: Some(Origin::IGP),
            med: Some(10),
            communities: Some(communities.clone()),
            aggr_asn: Some(Asn::new_32bit(4200000002)),
            aggr_ip: Some("10.102.100.2".parse().unwrap()),
            ..Default::default()
        };
        let withdraw = |prefix: &str| BgpElem {
            timestamp: 1640553894.84,
            elem_type: ElemType::WITHDRAW,
            peer_ip,
            peer_asn: Asn::new_32bit(24482),
            prefix: NetworkPrefix::new(prefix.parse().unwrap(), None),
            next_hop: None,
            ..Default::default()
        };

        // the last announcement takes the shared attributes instead of cloning them, so it is
        // the one most likely to come out wrong
        assert_eq!(
            elems,
            vec![
                announce("102.66.116.0/24", "195.66.224.68"),
                announce("102.66.117.0/24", "195.66.224.68"),
                announce("102.66.118.0/24", "195.66.224.69"),
                withdraw("10.0.0.0/24"),
                withdraw("10.0.1.0/24"),
            ]
        );
        assert_eq!(parse_ris_live_message(msg_str).unwrap(), elems);
    }

    #[test]
    fn origin_asn_filter_matches_json_parsed_elems() {
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1.0,"peer":"192.0.2.1","peer_asn":"64496","id":"x","host":"rrc00","type":"UPDATE","path":[64496,64511],"origin":"igp","announcements":[{"next_hop":"192.0.2.1","prefixes":["10.0.0.0/24","10.0.2.0/24"]}]}}
        "#;
        use crate::parser::{Filter, Filterable};

        let filters = [Filter::new("origin_asn", "64511").unwrap()];
        let elems = parse_ris_live_message(msg_str).unwrap();
        assert_eq!(elems.len(), 2);
        assert!(elems.iter().all(|elem| elem.match_filters(&filters)));
    }

    #[test]
    fn iter_size_hint_tracks_remaining_elems() {
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1.0,"peer":"192.0.2.1","peer_asn":"64496","id":"x","host":"rrc00","type":"UPDATE","path":[64496],"origin":"igp","announcements":[{"next_hop":"192.0.2.1","prefixes":["10.0.0.0/24"]}],"withdrawals":["10.0.1.0/24"]}}
        "#;
        let mut iter = parse_ris_live_message_iter(msg_str).unwrap();
        assert_eq!(iter.size_hint(), (2, Some(2)));
        assert!(iter.next().is_some());
        assert_eq!(iter.size_hint(), (1, Some(1)));
        assert!(iter.next().is_some());
        assert_eq!(iter.size_hint(), (0, Some(0)));
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }

    #[test]
    fn iter_reports_validation_errors_before_yielding() {
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1.0,"peer":"192.0.2.1","peer_asn":"64496","id":"x","host":"rrc00","type":"UPDATE","path":[64496],"origin":"igp","announcements":[{"next_hop":"192.0.2.1","prefixes":["10.0.0.0/24"]}],"withdrawals":["not a prefix"]}}
        "#;
        let error = parse_ris_live_message_iter(msg_str).unwrap_err();
        assert!(matches!(error, ParserRisliveError::ElemIncorrectPrefix(_)));
    }

    #[test]
    fn iter_is_empty_for_frames_without_elems() {
        let msg_str = r#"{"type": "ris_message","data":{"timestamp":1.0,"peer":"192.0.2.1","peer_asn":"64496","id":"x","host":"rrc00","type":"KEEPALIVE"}}"#;
        let mut iter = parse_ris_live_message_iter(msg_str).unwrap();
        assert_eq!(iter.len(), 0);
        assert!(iter.next().is_none());
    }
}
