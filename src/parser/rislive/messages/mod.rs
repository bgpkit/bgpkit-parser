#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
pub mod pong;
pub mod raw_bytes;
pub mod ris_error;
pub mod ris_message;
pub mod ris_rrc_list;
pub mod ris_subscribe_ok;

use serde::{Deserialize, Serialize};

pub use pong::Pong;
pub use ris_error::RisError;
pub use ris_message::RisMessage;
pub use ris_message::RisMessageEnum;
pub use ris_rrc_list::RisRrcList;
pub use ris_subscribe_ok::RisSubscribeOk;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum RisLiveMessage {
    #[serde(rename = "ris_message")]
    RisMessage(RisMessage),
    #[serde(rename = "ris_error")]
    RisError(RisError),
    #[serde(rename = "ris_rrc_list")]
    RisRrcList(Option<RisRrcList>),
    #[serde(rename = "ris_subscribe_ok")]
    RisSubscribeOk(RisSubscribeOk),
    #[serde(rename = "pong")]
    Pong(Option<Pong>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::rislive::messages::ris_message::{PathSeg, RisMessageEnum};

    #[test]
    fn test_serialize_update() {
        let msg = RisMessage {
            timestamp: 1.0,
            peer: "1.1.1.1".to_string(),
            peer_asn: "12345".to_string(),
            id: "id1".to_string(),
            raw: None,
            host: "host1".to_string(),
            msg: Some(RisMessageEnum::UPDATE {
                path: Some(vec![PathSeg::Asn(1), PathSeg::AsSet(vec![1, 2, 3])]),
                community: None,
                origin: None,
                med: None,
                aggregator: None,
                announcements: None,
            }),
        };

        let live_msg = RisLiveMessage::RisMessage(msg);
        let msg_str = serde_json::to_string(&live_msg).unwrap();
        println!("{}", &msg_str);
    }

    #[test]
    fn test_serialize_ris_error() {
        let live_msg = RisLiveMessage::RisError(RisError {
            message: "error!".to_string(),
        });
        let msg_str = serde_json::to_string(&live_msg).unwrap();
        println!("{}", &msg_str);
    }

    #[test]
    fn test_serialize_pong() {
        let live_msg = RisLiveMessage::Pong(Some(Pong {}));
        let msg_str = serde_json::to_string(&live_msg).unwrap();
        println!("{}", &msg_str);
    }

    #[test]
    fn test_deserialize_pong() {
        let msg_str = r#"{"type":"pong","data":null}"#;
        let _pong_msg: RisLiveMessage = serde_json::from_str(msg_str).unwrap();
    }
}
