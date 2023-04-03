use serde::Serialize;

/// AFI -- Address Family Identifier
///
/// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
#[derive(Debug, PartialEq, Primitive, Clone, Copy, Serialize, Eq)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2,
}

/// SAFI -- Subsequent Address Family Identifier
///
/// SAFI can be: Unicast, Multicast, or both.
#[derive(Debug, PartialEq, Primitive, Clone, Copy, Serialize, Eq)]
pub enum Safi {
    Unicast = 1,
    Multicast = 2,
    UnicastMulticast = 3,
}
