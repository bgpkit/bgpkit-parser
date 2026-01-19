use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Route Distinguisher for VPN next-hops - RFC 4364, Section 4.1
/// An 8-byte value used to distinguish VPN routes with potentially overlapping address spaces.
///
/// The first 2 bytes indicate the type:
/// - Type 0: 2-byte ASN + 4-byte assigned number
/// - Type 1: 4-byte IPv4 address + 2-byte assigned number
/// - Type 2: 4-byte ASN + 2-byte assigned number
#[derive(PartialEq, Copy, Clone, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RouteDistinguisher(pub [u8; 8]);

impl RouteDistinguisher {
    /// Convert to u64 matching bgpdump's memory layout (little-endian interpretation).
    /// This is how bgpdump reads the RD: memcpy of 8 bytes directly into a uint64_t,
    /// which on little-endian x86 gives a specific bit layout used by rd_format().
    fn as_u64(&self) -> u64 {
        u64::from_le_bytes(self.0)
    }

    /// Get the RD type using bgpdump's bit-shift method: rd >> 48
    pub fn rd_type(&self) -> u16 {
        (self.as_u64() >> 48) as u16
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl Debug for RouteDistinguisher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Debug format includes the RD() wrapper
        write!(f, "RD({})", self)
    }
}

impl Display for RouteDistinguisher {
    /// Display in human-readable format matching rd_format() from bgpdump.
    /// Uses the same bit-shift logic as the C implementation.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let rd = self.as_u64();
        let rd_type = (rd >> 48) as u16;

        match rd_type {
            0 => {
                // Type 0: (rd >> 32) gives ASN (2-byte), rd & 0xFFFFFFFF gives value (4-byte)
                let asn = (rd >> 32) as u32;
                let value = (rd & 0xFFFFFFFF) as u32;
                write!(f, "{}:{}", asn, value)
            }
            1 => {
                // Type 1: (rd >> 16) gives IP (4-byte), rd & 0xFFFF gives value (2-byte)
                let ip_u32 = (rd >> 16) as u32;
                let ip = Ipv4Addr::from(ip_u32);
                let value = (rd & 0xFFFF) as u16;
                write!(f, "{}:{}", ip, value)
            }
            2 => {
                // Type 2: (rd >> 16) gives ASN (4-byte), rd & 0xFFFF gives value (2-byte)
                // If ASN fits in 16 bits, show as "ASN:Value", else "2:ASN:Value"
                let asn = (rd >> 16) as u32;
                let value = (rd & 0xFFFF) as u16;
                if asn >> 16 != 0 {
                    write!(f, "{}:{}", asn, value)
                } else {
                    write!(f, "2:{}:{}", asn, value)
                }
            }
            _ => {
                // Unknown type: fallback to hex format
                write!(
                    f,
                    "X:{:08x}:{:08x}",
                    (rd >> 32) as u32,
                    (rd & 0xFFFFFFFF) as u32
                )
            }
        }
    }
}

/// enum that represents the type of the next hop address.
///
/// [NextHopAddress] is used when parsing for next hops in [Nlri](crate::models::Nlri).
/// RFC 8950 extends this to support VPN next-hops with Route Distinguishers.
#[derive(PartialEq, Copy, Clone, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
            NextHopAddress::Ipv6(x) => (x.segments()[0] & 0xffc0) == 0xfe80,
            NextHopAddress::Ipv6LinkLocal(_, _) => true,
            NextHopAddress::VpnIpv6(_, x) => (x.segments()[0] & 0xffc0) == 0xfe80,
            NextHopAddress::VpnIpv6LinkLocal(_, _, _, _) => true,
        }
    }

    /// Returns the address that this next hop points to
    pub const fn addr(&self) -> IpAddr {
        match self {
            NextHopAddress::Ipv4(x) => IpAddr::V4(*x),
            NextHopAddress::Ipv6(x) => IpAddr::V6(*x),
            NextHopAddress::Ipv6LinkLocal(x, _) => IpAddr::V6(*x),
            NextHopAddress::VpnIpv6(_, x) => IpAddr::V6(*x),
            NextHopAddress::VpnIpv6LinkLocal(_, x, _, _) => IpAddr::V6(*x),
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

impl Display for NextHopAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NextHopAddress::Ipv4(v) => write!(f, "{v}"),
            NextHopAddress::Ipv6(v) => write!(f, "{v}"),
            NextHopAddress::Ipv6LinkLocal(v, _) => write!(f, "{v}"),
            NextHopAddress::VpnIpv6(_, v) => write!(f, "{v}"),
            NextHopAddress::VpnIpv6LinkLocal(_, v, _, _) => write!(f, "{v}"),
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

    #[test]
    fn test_route_distinguisher() {
        // Test Type 0: "65000:8" - matches fi_test expectation for test.data.vpn4.mrt
        // rd as u64 = 0x0000fde800000008, stored as little-endian bytes
        let rd_type0 = RouteDistinguisher([0x08, 0x00, 0x00, 0x00, 0xe8, 0xfd, 0x00, 0x00]);
        assert_eq!(rd_type0.rd_type(), 0);
        assert_eq!(format!("{rd_type0}"), "65000:8");
        assert_eq!(format!("{rd_type0:?}"), "RD(65000:8)");

        // Test Type 1: "1.2.3.4:100" - IP address format
        // rd as u64: type=1, ip=0x01020304, value=100
        // 0x0001_01020304_0064 = in little-endian bytes: 64 00 04 03 02 01 01 00
        let rd_type1 = RouteDistinguisher([0x64, 0x00, 0x04, 0x03, 0x02, 0x01, 0x01, 0x00]);
        assert_eq!(rd_type1.rd_type(), 1);
        assert_eq!(format!("{rd_type1}"), "1.2.3.4:100");

        // Test Type 2: "65552:65010" (ASN > 16 bits)
        // From bgpdump tests.c: rd = 0x0002_00010010_fe12
        // In little-endian bytes: 12 fe 10 00 01 00 02 00
        let rd_type2 = RouteDistinguisher([0x12, 0xfe, 0x10, 0x00, 0x01, 0x00, 0x02, 0x00]);
        assert_eq!(rd_type2.rd_type(), 2);
        assert_eq!(format!("{rd_type2}"), "65552:65010");

        // Test unknown type: fallback to hex format
        let rd_unknown = RouteDistinguisher([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x20, 0x00]);
        assert_eq!(format!("{rd_unknown}"), "X:00200504:03020100");
    }

    #[test]
    fn test_vpn_next_hop_address() {
        // Use RD that formats as "65000:8" (Type 0)
        let rd = RouteDistinguisher([0x08, 0x00, 0x00, 0x00, 0xe8, 0xfd, 0x00, 0x00]);
        let ipv6_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let ipv6_link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        // Use RD that formats as "1.2.3.4:100" (Type 1)
        let rd2 = RouteDistinguisher([0x64, 0x00, 0x04, 0x03, 0x02, 0x01, 0x01, 0x00]);

        // Test VpnIpv6
        let vpn_next_hop = NextHopAddress::VpnIpv6(rd, ipv6_addr);
        assert_eq!(vpn_next_hop.addr(), IpAddr::V6(ipv6_addr));
        assert!(!vpn_next_hop.is_link_local());
        assert_eq!(format!("{vpn_next_hop}"), "2001:db8::1");
        assert_eq!(
            format!("{vpn_next_hop:?}"),
            "VpnIpv6(RD(65000:8), 2001:db8::1)"
        );

        // Test VpnIpv6LinkLocal
        let vpn_ll_next_hop = NextHopAddress::VpnIpv6LinkLocal(rd, ipv6_addr, rd2, ipv6_link_local);
        assert_eq!(vpn_ll_next_hop.addr(), IpAddr::V6(ipv6_addr));
        assert!(vpn_ll_next_hop.is_link_local()); // Should return true for VpnIpv6LinkLocal
        assert_eq!(format!("{vpn_ll_next_hop}"), "2001:db8::1");
        assert_eq!(format!("{vpn_ll_next_hop:?}"), "VpnIpv6LinkLocal(RD(65000:8), 2001:db8::1, RD(1.2.3.4:100), fe80::1)");

        // Test VpnIpv6 with link-local IP (not VpnIpv6LinkLocal variant)
        let vpn_ll_ip = NextHopAddress::VpnIpv6(rd, ipv6_link_local);
        assert!(vpn_ll_ip.is_link_local()); // Should detect link-local from IPv6 address
    }
}
