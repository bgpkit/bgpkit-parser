use bgp_models::prelude::AsPathSegment::{AsSequence, AsSet};
use bgp_models::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct RisMessage {
    pub timestamp: f64,
    pub peer: String,
    pub peer_asn: String,
    pub id: String,
    pub raw: Option<String>,
    pub host: String,
    #[serde(rename = "type", flatten)]
    pub msg: Option<RisMessageEnum>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RisMessageEnum {
    UPDATE {
        path: Option<Vec<PathSeg>>,
        community: Option<Vec<(u32, u16)>>,
        origin: Option<String>,
        med: Option<u32>,
        aggregator: Option<String>,
        announcements: Option<Vec<Announcement>>,
    },
    KEEPALIVE {},
    OPEN {
        direction: String,
        version: u8,
        asn: u32,
        hold_time: u32,
        router_id: String,
        capabilities: Value,
    },
    NOTIFICATION {
        notification: Notification,
    },
    RIS_PEER_STATE {
        state: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Notification {
    pub code: u32,
    pub subcode: u32,
    pub data: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Announcement {
    pub next_hop: String,
    pub prefixes: Vec<String>,
    pub withdrawals: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathSeg {
    Asn(u32),
    AsSet(Vec<u32>),
}

pub fn path_to_as_path(path: Vec<PathSeg>) -> AsPath {
    let mut as_path = AsPath::new();
    let mut sequence = vec![];
    let mut set: Option<Vec<Asn>> = None;
    for node in path {
        match node {
            PathSeg::Asn(asn) => sequence.push(asn.into()),
            PathSeg::AsSet(s) => set = Some(s.into_iter().map(|i| i.into()).collect::<Vec<Asn>>()),
        }
    }
    as_path.segments.push(AsSequence(sequence));
    if let Some(s) = set {
        as_path.segments.push(AsSet(s))
    }

    as_path
}

#[cfg(test)]
mod tests {
    use crate::parser::rislive::messages::ris_message::RisMessage;

    #[test]
    fn test_deserialize_update() {
        let message = r#"
            {"timestamp":1568279796.63,"peer":"192.0.2.0","peer_asn":"64496","id":"21-192-0-2-0-11188782","host":"rrc21","type":"UPDATE","path":[1,2,3,4],"announcements":[{"next_hop":"192.0.2.0","prefixes":["192.0.3.0/24"]}]}
        "#;
        let _msg: RisMessage = serde_json::from_str(&message).unwrap();
    }

    #[test]
    fn test_keep_alive_msg() {
        let msg_str = r#"{"timestamp":1568284616.24,"peer":"192.0.2.0","peer_asn":"64496","id":"21-192-0-2-0-53776312","host":"rrc00","type":"KEEPALIVE"}
"#;
        let _msg: RisMessage = serde_json::from_str(&msg_str).unwrap();
    }

    #[test]
    fn test_open_msg() {
        let msg_str = r#"
        {"timestamp":1568365292.84,"peer":"192.0.2.1","peer_asn":"64496","id":"00-192-0-2-0-180513","host":"rrc00","type":"OPEN","direction":"sent","version":4,"asn":65536,"hold_time":180,"router_id":"192.0.3.1","capabilities":{"1":{"name":"multiprotocol","families":["ipv4/unicast","ipv6/unicast"]},"65":{"name":"asn4","asn4":65536}}}
"#;
        let _msg: RisMessage = serde_json::from_str(&msg_str).unwrap();
    }

    #[test]
    fn test_notification_msg() {
        let msg_str = r#"
        {"timestamp":1568365292.84,"peer":"192.0.2.1","peer_asn":"64496","id":"00-192-0-2-0-180513","host":"rrc00","type":"NOTIFICATION","notification":{"code":6,"subcode":7,"data":"0605"}}
"#;
        let _msg: RisMessage = serde_json::from_str(&msg_str).unwrap();
    }

    #[test]
    fn test_peer_state_change_msg() {
        let msg_str = r#"
        {"timestamp":1568365292.84,"peer":"192.0.2.1","peer_asn":"64496","id":"00-192-0-2-0-180513","host":"rrc00","type":"RIS_PEER_STATE","state":"connected"}
"#;
        let _msg: RisMessage = serde_json::from_str(&msg_str).unwrap();
    }
}
