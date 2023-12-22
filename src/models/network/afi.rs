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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afi_from() {
        assert_eq!(
            Afi::from(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            Afi::Ipv4
        );
        assert_eq!(
            Afi::from(IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
            Afi::Ipv6
        );
    }

    #[test]
    fn test_afi_safi_repr() {
        assert_eq!(Afi::Ipv4 as u16, 1);
        assert_eq!(Afi::Ipv6 as u16, 2);

        assert_eq!(Safi::Unicast as u8, 1);
        assert_eq!(Safi::Multicast as u8, 2);
        assert_eq!(Safi::UnicastMulticast as u8, 3);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_afi_safi_serde() {
        let afi = Afi::Ipv4;
        let serialized = serde_json::to_string(&afi).unwrap();
        assert_eq!(serialized, "\"Ipv4\"");
        let deserialized: Afi = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, afi);

        let afi = Afi::Ipv6;
        let serialized = serde_json::to_string(&afi).unwrap();
        assert_eq!(serialized, "\"Ipv6\"");
        let deserialized: Afi = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, afi);

        let safi = Safi::Unicast;
        let serialized = serde_json::to_string(&safi).unwrap();
        assert_eq!(serialized, "\"Unicast\"");
        let deserialized: Safi = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, safi);

        let safi = Safi::Multicast;
        let serialized = serde_json::to_string(&safi).unwrap();
        assert_eq!(serialized, "\"Multicast\"");
        let deserialized: Safi = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, safi);

        let safi = Safi::UnicastMulticast;
        let serialized = serde_json::to_string(&safi).unwrap();
        assert_eq!(serialized, "\"UnicastMulticast\"");
        let deserialized: Safi = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, safi);
    }
}
