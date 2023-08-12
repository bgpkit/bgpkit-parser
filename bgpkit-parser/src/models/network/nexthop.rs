use serde::Serialize;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

/// enum that represents the type of the next hop address.
///
/// [NextHopAddress] is used when parsing for next hops in [Nlri](crate::models::Nlri).
#[derive(Debug, PartialEq, Copy, Clone, Serialize, Eq)]
pub enum NextHopAddress {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Ipv6LinkLocal(Ipv6Addr, Ipv6Addr),
}

impl Display for NextHopAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                NextHopAddress::Ipv4(v) => {
                    v.to_string()
                }
                NextHopAddress::Ipv6(v) => {
                    v.to_string()
                }
                NextHopAddress::Ipv6LinkLocal(v1, _v2) => {
                    v1.to_string()
                }
            }
        )
    }
}
