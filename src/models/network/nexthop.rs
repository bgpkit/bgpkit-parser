use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

/// enum that represents the type of the next hop address.
///
/// [NextHopAddress] is used when parsing for next hops in [Nlri](crate::models::Nlri).
#[derive(Debug, PartialEq, Copy, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NextHopAddress {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Ipv6LinkLocal(Ipv6Addr, Ipv6Addr),
}

impl Display for NextHopAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NextHopAddress::Ipv4(v) => write!(f, "{}", v),
            NextHopAddress::Ipv6(v) => write!(f, "{}", v),
            NextHopAddress::Ipv6LinkLocal(v, _) => write!(f, "{}", v),
        }
    }
}
