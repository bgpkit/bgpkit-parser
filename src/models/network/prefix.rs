use crate::models::BgpModelsError;
use ipnet::IpNet;
use serde::{Serialize, Serializer};
use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;

/// A representation of a IP prefix with optional path ID.
#[derive(PartialEq, Eq, Clone, Copy, Hash)]
pub struct NetworkPrefix {
    pub prefix: IpNet,
    pub path_id: u32,
}

impl Deref for NetworkPrefix {
    type Target = IpNet;

    fn deref(&self) -> &Self::Target {
        &self.prefix
    }
}

// Attempt to reduce the size of the debug output
impl Debug for NetworkPrefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.path_id == 0 {
            write!(f, "{}", self.prefix)
        } else {
            write!(f, "{}#{}", self.prefix, self.path_id)
        }
    }
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
