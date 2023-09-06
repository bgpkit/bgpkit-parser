use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::net::IpAddr;

/// AFI -- Address Family Identifier
///
/// <https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml>
#[derive(Debug, PartialEq, TryFromPrimitive, IntoPrimitive, Clone, Copy, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2,
}

impl From<IpAddr> for Afi {
    #[inline]
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => Afi::Ipv4,
            IpAddr::V6(_) => Afi::Ipv6,
        }
    }
}

/// SAFI -- Subsequent Address Family Identifier
///
/// SAFI can be: Unicast, Multicast, or both.
#[derive(Debug, PartialEq, TryFromPrimitive, IntoPrimitive, Clone, Copy, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Safi {
    Unicast = 1,
    Multicast = 2,
    UnicastMulticast = 3,
}
