/*!
Provides parsing functions for [RIS-Live](https://ris-live.ripe.net/manual/) real-time
BGP message stream JSON data.

The main parsing function, [parse_ris_live_message] converts a JSON-formatted message string into a
vector of [BgpElem]s.

Here is an example parsing stream data from one collector:
```no_run
use bgpkit_parser::parse_ris_live_message;
use serde_json::json;
use tungstenite::{connect, Message};
use url::Url;

const RIS_LIVE_URL: &str = "ws://ris-live.ripe.net/v1/ws/?client=rust-bgpkit-parser";

/// This is an example of subscribing to RIS-Live's streaming data from one host (`rrc21`).
///
/// For more RIS-Live details, check out their documentation at https://ris-live.ripe.net/manual/
fn main() {
    // connect to RIPE RIS Live websocket server
    let (mut socket, _response) =
        connect(Url::parse(RIS_LIVE_URL).unwrap())
            .expect("Can't connect to RIS Live websocket server");

    // subscribe to messages from one collector
    let msg = json!({"type": "ris_subscribe", "data": {"host": "rrc21"}}).to_string();
    socket.write_message(Message::Text(msg)).unwrap();

    loop {
        let msg = socket.read_message().expect("Error reading message").to_string();
        if let Ok(elems) = parse_ris_live_message(msg.as_str()) {
            for elem in elems {
                println!("{}", elem);
            }
        }
    }
}
```
*/
use crate::parser::rislive::error::ParserRisliveError;
use crate::parser::rislive::messages::{RisLiveMessage, RisMessageEnum};
use crate::parser::rislive::messages::ris_message::path_to_as_path;

use crate::BgpElem;
use std::net::IpAddr;
use bgp_models::bgp::attributes::Community;
use bgp_models::bgp::attributes::Origin::{EGP, IGP, INCOMPLETE};
use bgp_models::network::NetworkPrefix;
use ipnetwork::IpNetwork;
use crate::parser::ElemType;

pub mod error;
pub mod messages;

// simple macro to make the code look a bit nicer
macro_rules! unwrap_or_return {
    ( $e:expr, $msg_string:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return Err(ParserRisliveError::IncorrectJson($msg_string)),
        }
    }
}

/// This function parses one message and returns a result of a vector of [BgpElem]s or an error
pub fn parse_ris_live_message(msg_str: &str) -> Result<Vec<BgpElem>, ParserRisliveError> {

    let msg_string = msg_str.to_string();

    // parse RIS Live message to internal struct using serde.
    let msg: RisLiveMessage = match serde_json::from_str(msg_str) {
        Ok(m) => m,
        Err(_e) => return Err(ParserRisliveError::IncorrectJson(msg_string)),
    };

    match msg {
        RisLiveMessage::RisMessage(ris_msg) => {
            // we currently only handles the `ris_message` data type. other
            // types provides meta information, but reveals no BGP elements, and
            // thus for now will be ignored.

            if ris_msg.msg.is_none() {
                return Ok(vec![])
            }

            match ris_msg.msg.unwrap() {
                RisMessageEnum::UPDATE {
                    path,
                    community,
                    origin,
                    med,
                    aggregator,
                    announcements,
                } => {
                    let mut elems: Vec<BgpElem> = vec![];

                    let peer_ip = unwrap_or_return!(ris_msg.peer.parse::<IpAddr>(), msg_string);
                    let peer_asn = unwrap_or_return!(ris_msg.peer_asn.parse::<u32>(), msg_string);

                    // parse path
                    let as_path = match path{
                        Some(p) => Some(path_to_as_path(p)),
                        None => None
                    };

                    // parse community
                    let communities = match community {
                        None => {None}
                        Some(cs) => {
                            let mut comms: Vec<Community> = vec![];
                            for c in cs {
                                comms.push(Community::Custom(c.0,c.1));
                            }
                            Some(comms)
                        }
                    };

                    // parse origin
                    let bgp_origin = match origin {
                        None => {None}
                        Some(o) => {
                            Some(match o.as_str(){
                                "igp" | "IGP" => IGP,
                                "egp" | "EGP" => EGP,
                                "incomplete" | "INCOMPLETE" => INCOMPLETE,
                                other => {
                                    return Err(ParserRisliveError::ElemUnknownOriginType(other.to_string()))
                                }
                            })
                        }
                    };

                    // parse med
                    let bgp_med = match med{
                        None => {None}
                        Some(med) => {Some(med)}
                    };

                    // parse aggregator
                    let bgp_aggregator = match aggregator{
                        None => {(None, None)}
                        Some(aggr_str) => {
                            let parts = aggr_str.split(":").collect::<Vec<&str>>();
                            if parts.len()!=2 {
                                return Err(ParserRisliveError::ElemIncorrectAggregator(aggr_str))
                            }
                            let asn = unwrap_or_return!(parts[0].to_owned().parse::<u32>(), msg_string);
                            let ip = unwrap_or_return!(parts[1].to_owned().parse::<IpAddr>(), msg_string);
                            (Some(asn), Some(ip))
                        }
                    };

                    // parser announcements
                    if let Some(announcements) = announcements {
                        for announcement in announcements {
                            let nexthop = match announcement.next_hop.parse::<IpAddr>(){
                                Ok(a) => {a}
                                Err(_) => {
                                    return Err(ParserRisliveError::IncorrectJson(msg_string))
                                }
                            };
                            for prefix in &announcement.prefixes {
                                let p = match prefix.parse::<IpNetwork>(){
                                    Ok(net) => { net }
                                    Err(_) => {
                                        if prefix == "eor" {
                                            return Err(ParserRisliveError::ElemEndOfRibPrefix)
                                        }
                                        return Err(ParserRisliveError::ElemIncorrectPrefix(prefix.to_string()))
                                    }
                                };
                                elems.push(
                                    BgpElem{
                                        timestamp: ris_msg.timestamp.clone(),
                                        elem_type: ElemType::ANNOUNCE,
                                        peer_ip: peer_ip.clone(),
                                        peer_asn: peer_asn.clone(),
                                        prefix: NetworkPrefix{ prefix: p, path_id: 0 },
                                        next_hop: Some(nexthop.clone()),
                                        as_path: as_path.clone(),
                                        origin_asns: None,
                                        origin: bgp_origin.clone(),
                                        local_pref: None,
                                        med: bgp_med.clone(),
                                        communities: communities.clone(),
                                        atomic: None,
                                        aggr_asn: bgp_aggregator.0.clone(),
                                        aggr_ip: bgp_aggregator.1.clone(),
                                    }
                                );
                            }
                        }
                    }

                    Ok(elems)
                }
                _ => Ok(vec![]),
            }
        },
        _ => Ok(vec![]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ris_live_msg() {
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1636247118.76,"peer":"2001:7f8:24::82","peer_asn":"58299","id":"20-5761-238131559","host":"rrc20","type":"UPDATE","path":[58299,49981,397666],"origin":"igp","announcements":[{"next_hop":"2001:7f8:24::82","prefixes":["2602:fd9e:f00::/40"]},{"next_hop":"fe80::768e:f8ff:fea6:b2c4","prefixes":["2602:fd9e:f00::/40"]}],"raw":"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF005A02000000434001010040020E02030000E3BB0000C33D00061162800E2B00020120200107F8002400000000000000000082FE80000000000000768EF8FFFEA6B2C400282602FD9E0F"}}
        "#;
        let msg = parse_ris_live_message(&msg_str).unwrap();
        for elem in msg {
            println!("{}", elem);
        }
    }

    #[test]
    fn test_error_message() {
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1636342486.17,"peer":"37.49.237.175","peer_asn":"199524","id":"21-587-22045871","host":"rrc21","type":"UPDATE","path":[199524,1299,3356,13904,13904,13904,13904,13904,13904],"origin":"igp","aggregator":"65000:8.42.232.1","announcements":[{"next_hop":"37.49.237.175","prefixes":["64.68.236.0/22"]}]}}
        "#;
        let msg = parse_ris_live_message(&msg_str).unwrap();
        for elem in msg {
            println!("{}", elem);
        }
    }

    #[test]
    fn test_error_message_2() {
        let msg_str = r#"
        {"type": "ris_message","data":{"timestamp":1636339375.83,"peer":"37.49.236.1","peer_asn":"8218","id":"21-594-37970252","host":"rrc21"}}
        "#;
        let msg = parse_ris_live_message(&msg_str).unwrap();
        for elem in msg {
            println!("{}", elem);
        }
    }
}
