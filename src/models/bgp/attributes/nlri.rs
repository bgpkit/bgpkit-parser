use crate::models::attributes::STORAGE_SIZE_LIMIT;
use crate::models::*;
use ipnet::IpNet;
use smallvec::SmallVec;
use std::fmt::Debug;
use std::iter::Map;
use std::mem::size_of;
use std::net::IpAddr;
use std::slice::Iter;

/// TODO: Create a PrefixListStorage with variants for IPv4/IPv6 with/without add path.
pub type PrefixList = SmallVec<
    [NetworkPrefix;
        (STORAGE_SIZE_LIMIT - size_of::<(Afi, Safi, NextHopAddress)>())
            / size_of::<NetworkPrefix>()],
>;

#[derive(Debug, PartialEq, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReachableNlri {
    pub afi: Afi,
    pub safi: Safi,
    pub next_hop: NextHopAddress,
    pub prefixes: PrefixList,
}

impl ReachableNlri {
    #[inline]
    pub const fn new(
        afi: Afi,
        safi: Safi,
        next_hop: NextHopAddress,
        prefixes: PrefixList,
    ) -> ReachableNlri {
        ReachableNlri {
            afi,
            safi,
            next_hop,
            prefixes,
        }
    }

    /// Returns true if this NLRI refers to the IPv4 address space.
    pub const fn is_ipv4(&self) -> bool {
        matches!(self.afi, Afi::Ipv4)
    }

    /// Returns true if this NLRI refers to the IPv6 address space.
    pub const fn is_ipv6(&self) -> bool {
        matches!(self.afi, Afi::Ipv6)
    }

    pub const fn address_family(&self) -> Afi {
        self.afi
    }

    pub const fn safi(&self) -> Safi {
        self.safi
    }

    pub const fn next_hop(&self) -> NextHopAddress {
        self.next_hop
    }

    /// Get the address of the next hop indicated by this NLRI.
    ///
    /// Panics if used on a unreachable NLRI message (ie. there is no next hop).
    pub const fn next_hop_addr(&self) -> IpAddr {
        self.next_hop.addr()
    }

    pub fn iter_with_path_id(&self) -> <&'_ PrefixList as IntoIterator>::IntoIter {
        self.prefixes.iter()
    }

    pub fn into_iter_with_path_id(self) -> <PrefixList as IntoIterator>::IntoIter {
        self.prefixes.into_iter()
    }
}

impl IntoIterator for ReachableNlri {
    type Item = IpNet;
    type IntoIter = Map<<PrefixList as IntoIterator>::IntoIter, fn(NetworkPrefix) -> IpNet>;

    fn into_iter(self) -> Self::IntoIter {
        self.prefixes.into_iter().map(|x| x.prefix)
    }
}

impl<'a> IntoIterator for &'a ReachableNlri {
    type Item = &'a IpNet;
    type IntoIter = Map<Iter<'a, NetworkPrefix>, fn(&NetworkPrefix) -> &IpNet>;

    fn into_iter(self) -> Self::IntoIter {
        self.prefixes.iter().map(|x| &x.prefix)
    }
}

#[derive(Debug, PartialEq, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnreachableNlri {
    pub afi: Afi,
    pub safi: Safi,
    pub prefixes: PrefixList,
}

impl UnreachableNlri {
    #[inline]
    pub const fn new(afi: Afi, safi: Safi, prefixes: PrefixList) -> UnreachableNlri {
        UnreachableNlri {
            afi,
            safi,
            prefixes,
        }
    }

    pub const fn address_family(&self) -> Afi {
        self.afi
    }

    pub const fn safi(&self) -> Safi {
        self.safi
    }

    /// Returns true if this NLRI refers to the IPv4 address space.
    pub const fn is_ipv4(&self) -> bool {
        matches!(self.afi, Afi::Ipv4)
    }

    /// Returns true if this NLRI refers to the IPv6 address space.
    pub const fn is_ipv6(&self) -> bool {
        matches!(self.afi, Afi::Ipv6)
    }

    pub fn iter_with_path_id(&self) -> <&'_ PrefixList as IntoIterator>::IntoIter {
        self.prefixes.iter()
    }

    pub fn into_iter_with_path_id(self) -> <PrefixList as IntoIterator>::IntoIter {
        self.prefixes.into_iter()
    }
}

impl IntoIterator for UnreachableNlri {
    type Item = IpNet;
    type IntoIter = Map<<PrefixList as IntoIterator>::IntoIter, fn(NetworkPrefix) -> IpNet>;

    fn into_iter(self) -> Self::IntoIter {
        self.prefixes.into_iter().map(|x| x.prefix)
    }
}

impl<'a> IntoIterator for &'a UnreachableNlri {
    type Item = &'a IpNet;
    type IntoIter = Map<Iter<'a, NetworkPrefix>, fn(&NetworkPrefix) -> &IpNet>;

    fn into_iter(self) -> Self::IntoIter {
        self.prefixes.iter().map(|x| &x.prefix)
    }
}
