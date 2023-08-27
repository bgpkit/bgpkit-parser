use crate::models::BgpModelsError;
use ipnet::IpNet;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// A representation of a IP prefix with optional path ID.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct NetworkPrefix {
    pub prefix: IpNet,
    pub path_id: u32,
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

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(untagged, deny_unknown_fields)]
    enum SerdeNetworkPrefixRepr {
        PlainPrefix(IpNet),
        WithPathId { prefix: IpNet, path_id: u32 },
    }

    impl Serialize for NetworkPrefix {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() && self.path_id == 0 {
                self.prefix.serialize(serializer)
            } else {
                SerdeNetworkPrefixRepr::WithPathId {
                    prefix: self.prefix,
                    path_id: self.path_id,
                }
                .serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for NetworkPrefix {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            match SerdeNetworkPrefixRepr::deserialize(deserializer)? {
                SerdeNetworkPrefixRepr::PlainPrefix(prefix) => {
                    Ok(NetworkPrefix { prefix, path_id: 0 })
                }
                SerdeNetworkPrefixRepr::WithPathId { prefix, path_id } => {
                    Ok(NetworkPrefix { prefix, path_id })
                }
            }
        }
    }
}
