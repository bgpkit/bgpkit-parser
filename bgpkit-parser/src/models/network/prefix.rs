use crate::models::BgpModelsError;
use ipnet::IpNet;
use serde::{Serialize, Serializer};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// A representation of a IP prefix with optional path ID.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct NetworkPrefix {
    pub prefix: IpNet,
    pub path_id: u32,
}

impl Serialize for NetworkPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl FromStr for NetworkPrefix {
    type Err = BgpModelsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prefix = IpNet::from_str(s)?;
        Ok(NetworkPrefix { prefix, path_id: 0 })
    }
}

impl NetworkPrefix {
    pub fn new(prefix: IpNet, path_id: u32) -> NetworkPrefix {
        NetworkPrefix { prefix, path_id }
    }
}

impl Display for NetworkPrefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.prefix)
    }
}
