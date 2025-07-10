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
            NextHopAddress::Ipv4(x) => write!(f, "{x}"),
            NextHopAddress::Ipv6(x) => write!(f, "{x}"),
            NextHopAddress::Ipv6LinkLocal(x, y) => write!(f, "Ipv6LinkLocal({x}, {y})"),
        }
    }
}

impl Display for NextHopAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NextHopAddress::Ipv4(v) => write!(f, "{v}"),
            NextHopAddress::Ipv6(v) => write!(f, "{v}"),
            NextHopAddress::Ipv6LinkLocal(v, _) => write!(f, "{v}"),
        }
    }
}

impl From<IpAddr> for NextHopAddress {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(x) => NextHopAddress::Ipv4(x),
            IpAddr::V6(x) => NextHopAddress::Ipv6(x),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_next_hop_address_is_link_local() {
        let ipv4_addr = Ipv4Addr::new(169, 254, 0, 1);
        let ipv6_addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
        let ipv6_link_local_addrs = (
            Ipv6Addr::new(0xfe80, 0, 0, 1, 0, 0, 0, 1),
            Ipv6Addr::new(0xfe80, 0, 0, 2, 0, 0, 0, 1),
        );

        let next_hop_ipv4 = NextHopAddress::Ipv4(ipv4_addr);
        let next_hop_ipv6 = NextHopAddress::Ipv6(ipv6_addr);
        let next_hop_ipv6_link_local =
            NextHopAddress::Ipv6LinkLocal(ipv6_link_local_addrs.0, ipv6_link_local_addrs.1);

        assert!(next_hop_ipv4.is_link_local());
        assert!(next_hop_ipv6.is_link_local());
        assert!(next_hop_ipv6_link_local.is_link_local());
    }

    #[test]
    fn test_next_hop_address_addr() {
        let ipv4_addr = Ipv4Addr::new(192, 0, 2, 1);
        let ipv6_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let ipv6_link_local_addrs = (
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        );

        let next_hop_ipv4 = NextHopAddress::Ipv4(ipv4_addr);
        let next_hop_ipv6 = NextHopAddress::Ipv6(ipv6_addr);
        let next_hop_ipv6_link_local =
            NextHopAddress::Ipv6LinkLocal(ipv6_link_local_addrs.0, ipv6_link_local_addrs.1);

        assert_eq!(next_hop_ipv4.addr(), IpAddr::V4(ipv4_addr));
        assert_eq!(next_hop_ipv6.addr(), IpAddr::V6(ipv6_addr));
        assert_eq!(
            next_hop_ipv6_link_local.addr(),
            IpAddr::V6(ipv6_link_local_addrs.0)
        );
    }

    #[test]
    fn test_next_hop_address_from() {
        let ipv4_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let ipv6_addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        let next_hop_ipv4 = NextHopAddress::from(ipv4_addr);
        let next_hop_ipv6 = NextHopAddress::from(ipv6_addr);

        assert_eq!(next_hop_ipv4.addr(), ipv4_addr);
        assert_eq!(next_hop_ipv6.addr(), ipv6_addr);
    }

    #[test]
    fn test_debug_for_next_hop_address() {
        let ipv4_addr = Ipv4Addr::new(192, 0, 2, 1);
        let ipv6_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let ipv6_link_local_addrs = (
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        );

        let next_hop_ipv4 = NextHopAddress::Ipv4(ipv4_addr);
        let next_hop_ipv6 = NextHopAddress::Ipv6(ipv6_addr);
        let next_hop_ipv6_link_local =
            NextHopAddress::Ipv6LinkLocal(ipv6_link_local_addrs.0, ipv6_link_local_addrs.1);

        assert_eq!(format!("{next_hop_ipv4:?}"), "192.0.2.1");
        assert_eq!(format!("{next_hop_ipv6:?}"), "2001:db8::1");
        assert_eq!(
            format!("{next_hop_ipv6_link_local:?}"),
            "Ipv6LinkLocal(fe80::, fe80::)"
        );
    }

    #[test]
    fn test_display_for_next_hop_address() {
        let ipv4_addr = Ipv4Addr::new(192, 0, 2, 1);
        let ipv6_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let ipv6_link_local_addrs = (
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        );

        let next_hop_ipv4 = NextHopAddress::Ipv4(ipv4_addr);
        let next_hop_ipv6 = NextHopAddress::Ipv6(ipv6_addr);
        let next_hop_ipv6_link_local =
            NextHopAddress::Ipv6LinkLocal(ipv6_link_local_addrs.0, ipv6_link_local_addrs.1);

        assert_eq!(format!("{next_hop_ipv4}"), "192.0.2.1");
        assert_eq!(format!("{next_hop_ipv6}"), "2001:db8::1");
        assert_eq!(format!("{next_hop_ipv6_link_local}"), "fe80::");
    }
}
