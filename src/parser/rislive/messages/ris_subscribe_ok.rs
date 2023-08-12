use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct RisSubscribeOk {
    pub subscription: Value,
    pub socketOptions: Value,
}
