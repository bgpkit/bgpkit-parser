use crate::models::BgpModelsError;
use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Route Distinguisher for VPN next-hops - RFC 4364, Section 4.1
/// An 8-byte value used to distinguish VPN routes with potentially overlapping address spaces
#[derive(PartialEq, Copy, Clone, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS), ts(export))]
pub struct RouteDistinguisher(pub [u8; 8]);

impl Debug for RouteDistinguisher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RD({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        )
    }
}

impl Display for RouteDistinguisher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        )
    }
}

/// enum that represents the type of the next hop address.
///
/// [NextHopAddress] is used when parsing for next hops in [Nlri](crate::models::Nlri).
/// RFC 8950 extends this to support VPN next-hops with Route Distinguishers.
#[derive(PartialEq, Copy, Clone, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS), ts(export))]
pub enum NextHopAddress {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Ipv6LinkLocal(Ipv6Addr, Ipv6Addr),
    /// VPN-IPv6 next hop - RFC 8950, Section 4
    /// Contains Route Distinguisher (8 bytes) + IPv6 address (16 bytes) = 24 bytes total
    VpnIpv6(RouteDistinguisher, Ipv6Addr),
    /// VPN-IPv6 next hop with link-local - RFC 8950, Section 4  
    /// Contains RD (8 bytes) + IPv6 (16 bytes) + RD (8 bytes) + IPv6 link-local (16 bytes) = 48 bytes total
    VpnIpv6LinkLocal(RouteDistinguisher, Ipv6Addr, RouteDistinguisher, Ipv6Addr),
}

impl NextHopAddress {
    /// Returns true if the next hop is a link local address
    pub const fn is_link_local(&self) -> bool {
        match self {
            NextHopAddress::Ipv4(x) => x.is_link_local(),
            NextHopAddress::Ipv6(x) => x.is_unicast_link_local(),
            NextHopAddress::Ipv6LinkLocal(_, _) => true,
            NextHopAddress::VpnIpv6(_, x) => x.is_unicast_link_local(),
            NextHopAddress::VpnIpv6LinkLocal(_, _, _, _) => true,
        }
    }

    /// Returns the address that this next hop points to — the first address
    /// of a pair, in wire order. See [`global_addr`](Self::global_addr) to
    /// resolve by scope instead.
    pub const fn addr(&self) -> IpAddr {
        match self {
            NextHopAddress::Ipv4(x) => IpAddr::V4(*x),
            NextHopAddress::Ipv6(x) => IpAddr::V6(*x),
            NextHopAddress::Ipv6LinkLocal(x, _) => IpAddr::V6(*x),
            NextHopAddress::VpnIpv6(_, x) => IpAddr::V6(*x),
            NextHopAddress::VpnIpv6LinkLocal(_, x, _, _) => IpAddr::V6(*x),
        }
    }

    /// The two addresses of an RFC 2545 pair, in wire order.
    const fn pair(&self) -> Option<(Ipv6Addr, Ipv6Addr)> {
        match self {
            NextHopAddress::Ipv6LinkLocal(x, y) => Some((*x, *y)),
            NextHopAddress::VpnIpv6LinkLocal(_, x, _, y) => Some((*x, *y)),
            _ => None,
        }
    }

    /// Returns the global-scope address of the next hop. Pairs are resolved
    /// by scope, not position — a reversed RFC 2545 pair still yields the
    /// global address; same-scope pairs and single addresses fall back to
    /// [`addr`](Self::addr).
    pub const fn global_addr(&self) -> IpAddr {
        match self.pair() {
            Some((first, second)) => {
                if first.is_unicast_link_local() && !second.is_unicast_link_local() {
                    IpAddr::V6(second)
                } else {
                    IpAddr::V6(first)
                }
            }
            None => self.addr(),
        }
    }

    /// Returns the link-local half of a pair (RFC 2545): the address
    /// [`global_addr`](Self::global_addr) does not return, when link-local.
    /// Single addresses yield `None`, even link-local ones.
    pub const fn link_local_addr(&self) -> Option<Ipv6Addr> {
        match self.pair() {
            // mirrors global_addr(), which keeps `first` of a both-link-local pair
            Some((_, second)) if second.is_unicast_link_local() => Some(second),
            Some((first, _)) if first.is_unicast_link_local() => Some(first),
            _ => None,
        }
    }
}

/// Parses a single IPv4/IPv6 address, or a comma-joined IPv6 pair as RIS Live
/// renders an RFC 2545 next hop (`"2001:db8::1,fe80::1"`), stored positionally
/// as [`NextHopAddress::Ipv6LinkLocal`]. Whitespace around the separator is
/// tolerated.
impl FromStr for NextHopAddress {
    type Err = BgpModelsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fn invalid(addr: &str, e: std::net::AddrParseError) -> BgpModelsError {
            BgpModelsError::NextHopParsingError(format!("invalid address {addr:?}: {e}"))
        }
        fn parse_v6(addr: &str) -> Result<Ipv6Addr, BgpModelsError> {
            let addr = addr.trim();
            Ipv6Addr::from_str(addr).map_err(|e| invalid(addr, e))
        }

        match s.split_once(',') {
            None => {
                let addr = s.trim();
                IpAddr::from_str(addr)
                    .map(NextHopAddress::from)
                    .map_err(|e| invalid(addr, e))
            }
            Some((_, second)) if second.contains(',') => Err(BgpModelsError::NextHopParsingError(
                format!("more than two addresses: {s:?}"),
            )),
            Some((first, second)) => Ok(NextHopAddress::Ipv6LinkLocal(
                parse_v6(first)?,
                parse_v6(second)?,
            )),
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
            NextHopAddress::VpnIpv6(rd, x) => write!(f, "VpnIpv6({rd}, {x})"),
            NextHopAddress::VpnIpv6LinkLocal(rd1, x, rd2, y) => {
                write!(f, "VpnIpv6LinkLocal({rd1}, {x}, {rd2}, {y})")
            }
        }
    }
}

/// Renders the address; pairs render comma-joined in wire order, round-tripping
/// with [`FromStr`] (non-VPN forms). Route Distinguishers are not rendered.
impl Display for NextHopAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.pair() {
            Some((first, second)) => write!(f, "{first},{second}"),
            None => write!(f, "{}", self.addr()),
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
        assert_eq!(format!("{next_hop_ipv6_link_local}"), "fe80::,fe80::");
    }

    #[test]
    fn test_next_hop_address_from_str() {
        // single addresses
        assert_eq!(
            "192.0.2.1".parse::<NextHopAddress>().unwrap(),
            NextHopAddress::Ipv4(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(
            "2001:db8::1".parse::<NextHopAddress>().unwrap(),
            NextHopAddress::Ipv6("2001:db8::1".parse().unwrap())
        );
        // a lone link-local address is a plain single next hop
        assert_eq!(
            "fe80::1".parse::<NextHopAddress>().unwrap(),
            NextHopAddress::Ipv6("fe80::1".parse().unwrap())
        );

        // a comma-joined pair is stored positionally, in wire order
        let pair = NextHopAddress::Ipv6LinkLocal(
            "2001:db8::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
        );
        assert_eq!(
            "2001:db8::1,fe80::1".parse::<NextHopAddress>().unwrap(),
            pair
        );
        assert_eq!(
            "fe80::1,2001:db8::1".parse::<NextHopAddress>().unwrap(),
            NextHopAddress::Ipv6LinkLocal(
                "fe80::1".parse().unwrap(),
                "2001:db8::1".parse().unwrap()
            )
        );
        // whitespace around the separator is tolerated
        assert_eq!(
            "2001:db8::1, fe80::1".parse::<NextHopAddress>().unwrap(),
            pair
        );

        // errors: not one address or two IPv6 addresses
        assert!("".parse::<NextHopAddress>().is_err());
        assert!("not-an-address".parse::<NextHopAddress>().is_err());
        assert!("fe80::1%eth0".parse::<NextHopAddress>().is_err());
        assert!("2001:db8::1,fe80::1,fe80::2"
            .parse::<NextHopAddress>()
            .is_err());
        assert!("2001:db8::1,".parse::<NextHopAddress>().is_err());
        assert!("192.0.2.1,fe80::1".parse::<NextHopAddress>().is_err());
    }

    #[test]
    fn test_next_hop_address_display_from_str_round_trip() {
        for repr in [
            "192.0.2.1",
            "2001:db8::1",
            "2001:db8::1,fe80::1",
            "fe80::1,2001:db8::1",
        ] {
            assert_eq!(repr.parse::<NextHopAddress>().unwrap().to_string(), repr);
        }
    }

    #[test]
    fn test_next_hop_address_global_addr() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let rd = RouteDistinguisher([0; 8]);

        // single addresses are returned as-is, including a lone link-local one
        assert_eq!(
            NextHopAddress::Ipv6(link_local).global_addr(),
            IpAddr::V6(link_local)
        );

        // a pair is resolved by scope, regardless of order
        assert_eq!(
            NextHopAddress::Ipv6LinkLocal(global, link_local).global_addr(),
            IpAddr::V6(global)
        );
        assert_eq!(
            NextHopAddress::Ipv6LinkLocal(link_local, global).global_addr(),
            IpAddr::V6(global)
        );
        assert_eq!(
            NextHopAddress::VpnIpv6LinkLocal(rd, link_local, rd, global).global_addr(),
            IpAddr::V6(global)
        );

        // a same-scope pair falls back to the first address
        let second_global: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let second_link_local: Ipv6Addr = "fe80::2".parse().unwrap();
        assert_eq!(
            NextHopAddress::Ipv6LinkLocal(global, second_global).global_addr(),
            IpAddr::V6(global)
        );
        assert_eq!(
            NextHopAddress::Ipv6LinkLocal(link_local, second_link_local).global_addr(),
            IpAddr::V6(link_local)
        );
    }

    #[test]
    fn test_next_hop_address_link_local_addr() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();

        // single addresses have no link-local companion
        assert_eq!(NextHopAddress::Ipv6(global).link_local_addr(), None);
        assert_eq!(NextHopAddress::Ipv6(link_local).link_local_addr(), None);

        // the link-local half of a pair, regardless of order
        assert_eq!(
            NextHopAddress::Ipv6LinkLocal(global, link_local).link_local_addr(),
            Some(link_local)
        );
        assert_eq!(
            NextHopAddress::Ipv6LinkLocal(link_local, global).link_local_addr(),
            Some(link_local)
        );

        // same-scope pairs: the half that global_addr() does not return
        let second_link_local: Ipv6Addr = "fe80::2".parse().unwrap();
        assert_eq!(
            NextHopAddress::Ipv6LinkLocal(link_local, second_link_local).link_local_addr(),
            Some(second_link_local)
        );
        assert_eq!(
            NextHopAddress::Ipv6LinkLocal(global, "2001:db8::2".parse().unwrap()).link_local_addr(),
            None
        );
    }

    #[test]
    fn test_route_distinguisher() {
        let rd = RouteDistinguisher([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);

        // Test Debug format
        assert_eq!(format!("{rd:?}"), "RD(00:01:02:03:04:05:06:07)");

        // Test Display format
        assert_eq!(format!("{rd}"), "00:01:02:03:04:05:06:07");
    }

    #[test]
    fn test_vpn_next_hop_address() {
        let rd = RouteDistinguisher([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let ipv6_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let ipv6_link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let rd2 = RouteDistinguisher([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]);

        // Test VpnIpv6
        let vpn_next_hop = NextHopAddress::VpnIpv6(rd, ipv6_addr);
        assert_eq!(vpn_next_hop.addr(), IpAddr::V6(ipv6_addr));
        assert!(!vpn_next_hop.is_link_local());
        assert_eq!(format!("{vpn_next_hop}"), "2001:db8::1");
        assert_eq!(
            format!("{vpn_next_hop:?}"),
            "VpnIpv6(00:01:02:03:04:05:06:07, 2001:db8::1)"
        );

        // Test VpnIpv6LinkLocal
        let vpn_ll_next_hop = NextHopAddress::VpnIpv6LinkLocal(rd, ipv6_addr, rd2, ipv6_link_local);
        assert_eq!(vpn_ll_next_hop.addr(), IpAddr::V6(ipv6_addr));
        assert!(vpn_ll_next_hop.is_link_local()); // Should return true for VpnIpv6LinkLocal
        assert_eq!(format!("{vpn_ll_next_hop}"), "2001:db8::1,fe80::1");
        assert_eq!(format!("{vpn_ll_next_hop:?}"), "VpnIpv6LinkLocal(00:01:02:03:04:05:06:07, 2001:db8::1, 10:11:12:13:14:15:16:17, fe80::1)");

        // Test VpnIpv6 with link-local IP (not VpnIpv6LinkLocal variant)
        let vpn_ll_ip = NextHopAddress::VpnIpv6(rd, ipv6_link_local);
        assert!(vpn_ll_ip.is_link_local()); // Should detect link-local from IPv6 address
    }
}
