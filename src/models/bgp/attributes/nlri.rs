use crate::models::*;
use ipnet::IpNet;
use serde::Serialize;
use std::fmt::Debug;
use std::iter::Map;
use std::net::IpAddr;
use std::ops::Deref;
use std::slice::Iter;
use std::vec::IntoIter;

/// Network Layer Reachability Information
#[derive(Debug, PartialEq, Clone, Serialize, Eq)]
pub struct Nlri {
    pub afi: Afi,
    pub safi: Safi,
    pub next_hop: Option<NextHopAddress>,
    pub prefixes: Vec<NetworkPrefix>,
}

impl Nlri {
    /// Returns true if this NLRI refers to the IPv4 address space.
    pub const fn is_ipv4(&self) -> bool {
        matches!(self.afi, Afi::Ipv4)
    }

    /// Returns true if this NLRI refers to the IPv6 address space.
    pub const fn is_ipv6(&self) -> bool {
        matches!(self.afi, Afi::Ipv6)
    }

    /// Returns true if this NLRI refers to reachable prefixes
    pub const fn is_reachable(&self) -> bool {
        self.next_hop.is_some()
    }

    /// Get the address of the next hop indicated by this NLRI.
    ///
    /// Panics if used on a unreachable NLRI message (ie. there is no next hop).
    pub const fn addr(&self) -> IpAddr {
        match self.next_hop {
            Some(next_hop) => next_hop.addr(),
            None => panic!("unreachable NLRI "),
        }
    }
}

impl Deref for Nlri {
    type Target = Vec<NetworkPrefix>;

    fn deref(&self) -> &Self::Target {
        &self.prefixes
    }
}

impl IntoIterator for Nlri {
    type Item = IpNet;
    type IntoIter = Map<IntoIter<NetworkPrefix>, fn(NetworkPrefix) -> IpNet>;

    fn into_iter(self) -> Self::IntoIter {
        self.prefixes.into_iter().map(|x| x.prefix)
    }
}

impl<'a> IntoIterator for &'a Nlri {
    type Item = &'a IpNet;
    type IntoIter = Map<Iter<'a, NetworkPrefix>, fn(&NetworkPrefix) -> &IpNet>;

    fn into_iter(self) -> Self::IntoIter {
        self.prefixes.iter().map(|x| &x.prefix)
    }
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct MpReachableNlri {
    afi: Afi,
    safi: Safi,
    next_hop: NextHopAddress,
    prefixes: Vec<NetworkPrefix>,
}

impl MpReachableNlri {
    pub fn new(
        afi: Afi,
        safi: Safi,
        next_hop: NextHopAddress,
        prefixes: Vec<NetworkPrefix>,
    ) -> MpReachableNlri {
        MpReachableNlri {
            afi,
            safi,
            next_hop,
            prefixes,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct MpUnreachableNlri {
    afi: Afi,
    safi: Safi,
    prefixes: Vec<NetworkPrefix>,
}

impl MpUnreachableNlri {
    pub fn new(afi: Afi, safi: Safi, prefixes: Vec<NetworkPrefix>) -> MpUnreachableNlri {
        MpUnreachableNlri {
            afi,
            safi,
            prefixes,
        }
    }
}
