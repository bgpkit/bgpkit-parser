use crate::models::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;

#[derive(Debug, Serialize, Deserialize)]
pub struct RisMessage {
    pub timestamp: f64,
    #[serde(with = "as_str")]
    pub peer: IpAddr,
    #[serde(with = "as_str")]
    pub peer_asn: Asn,
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
        path: Option<AsPath>,
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
    #[serde(with = "as_str")]
    pub next_hop: IpAddr,
    pub prefixes: Vec<String>,
    pub withdrawals: Option<Vec<String>>,
}

mod as_str {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::borrow::Cow;
    use std::fmt::Display;
    use std::str::FromStr;

    pub fn serialize<S, T>(this: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Display,
    {
        serializer.collect_str(this)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromStr,
        <T as FromStr>::Err: Display,
    {
        let str_repr = <Cow<'de, str>>::deserialize(deserializer)?;
        str_repr.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::rislive::messages::ris_message::RisMessage;

    #[test]
    fn test_deserialize_update() {
        let message = r#"
            {"timestamp":1568279796.63,"peer":"192.0.2.0","peer_asn":"64496","id":"21-192-0-2-0-11188782","host":"rrc21","type":"UPDATE","path":[1,2,3,4],"announcements":[{"next_hop":"192.0.2.0","prefixes":["192.0.3.0/24"]}]}
        "#;
        let _msg: RisMessage = serde_json::from_str(message).unwrap();
    }

    #[test]
    fn test_keep_alive_msg() {
        let msg_str = r#"{"timestamp":1568284616.24,"peer":"192.0.2.0","peer_asn":"64496","id":"21-192-0-2-0-53776312","host":"rrc00","type":"KEEPALIVE"}
"#;
        let _msg: RisMessage = serde_json::from_str(msg_str).unwrap();
    }

    #[test]
    fn test_open_msg() {
        let msg_str = r#"
        {"timestamp":1568365292.84,"peer":"192.0.2.1","peer_asn":"64496","id":"00-192-0-2-0-180513","host":"rrc00","type":"OPEN","direction":"sent","version":4,"asn":65536,"hold_time":180,"router_id":"192.0.3.1","capabilities":{"1":{"name":"multiprotocol","families":["ipv4/unicast","ipv6/unicast"]},"65":{"name":"asn4","asn4":65536}}}
"#;
        let _msg: RisMessage = serde_json::from_str(msg_str).unwrap();
    }

    #[test]
    fn test_notification_msg() {
        let msg_str = r#"
        {"timestamp":1568365292.84,"peer":"192.0.2.1","peer_asn":"64496","id":"00-192-0-2-0-180513","host":"rrc00","type":"NOTIFICATION","notification":{"code":6,"subcode":7,"data":"0605"}}
"#;
        let _msg: RisMessage = serde_json::from_str(msg_str).unwrap();
    }

    #[test]
    fn test_peer_state_change_msg() {
        let msg_str = r#"
        {"timestamp":1568365292.84,"peer":"192.0.2.1","peer_asn":"64496","id":"00-192-0-2-0-180513","host":"rrc00","type":"RIS_PEER_STATE","state":"connected"}
"#;
        let _msg: RisMessage = serde_json::from_str(msg_str).unwrap();
    }
}
