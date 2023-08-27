use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// enum that represents the type of the next hop address.
///
/// [NextHopAddress] is used when parsing for next hops in [Nlri](crate::models::Nlri).
#[derive(PartialEq, Copy, Clone, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NextHopAddress {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Ipv6LinkLocal(Ipv6Addr, Ipv6Addr),
}

impl NextHopAddress {
    /// Returns true if the next hop is a link local address
    pub const fn is_link_local(&self) -> bool {
        match self {
            NextHopAddress::Ipv4(x) => x.is_link_local(),
            NextHopAddress::Ipv6(x) => (x.segments()[0] & 0xffc0) == 0xfe80,
            NextHopAddress::Ipv6LinkLocal(_, _) => true,
        }
    }

    /// Returns the address that this next hop points to
    pub const fn addr(&self) -> IpAddr {
        match self {
            NextHopAddress::Ipv4(x) => IpAddr::V4(*x),
            NextHopAddress::Ipv6(x) => IpAddr::V6(*x),
            NextHopAddress::Ipv6LinkLocal(x, _) => IpAddr::V6(*x),
        }
    }
}

// Attempt to reduce the size of the debug output
impl Debug for NextHopAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NextHopAddress::Ipv4(x) => write!(f, "{}", x),
            NextHopAddress::Ipv6(x) => write!(f, "{}", x),
            // Is there a better notation for link local?
            NextHopAddress::Ipv6LinkLocal(x, y) => write!(f, "Ipv6LinkLocal({}, {})", x, y),
        }
    }
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
