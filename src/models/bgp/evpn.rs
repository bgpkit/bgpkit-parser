//! Ethernet VPN (EVPN) NLRI and route fields - RFC 7432.
//!
//! EVPN is carried in the L2VPN address family ([`Afi::L2vpn`]) with the EVPN
//! subsequent address family ([`Safi::Evpn`]). Every NLRI starts with a route
//! type and a length in octets, followed by a route-distinguisher and a
//! type-specific body.
//!
//! References:
//! - RFC 7432: BGP MPLS-Based Ethernet VPN - route types 1 to 4, MAC Mobility
//!   extended community (§7.2, §7.3, §7.7)
//! - RFC 8365: Network Virtualization Overlay Solution Using EVPN - VXLAN
//!   encapsulation, where the label field carries the VXLAN Network Identifier
//! - RFC 9136: IP Prefix Advertisement in EVPN - route type 5 (§3.1)
//!
//! [`Afi::L2vpn`]: crate::models::Afi::L2vpn
//! [`Safi::Evpn`]: crate::models::Safi::Evpn

use crate::models::RouteDistinguisher;
use num_enum::{FromPrimitive, IntoPrimitive};
use std::net::IpAddr;

/// EVPN route type - the first octet of every EVPN NLRI.
///
/// Types 1 to 5 are defined by RFC 7432 and RFC 9136; anything else is kept as
/// [`EvpnRouteType::Unknown`] so that new route types do not fail parsing.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, FromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum EvpnRouteType {
    /// Ethernet Auto-Discovery route - RFC 7432 §7.1
    EthernetAutoDiscovery = 1,
    /// MAC/IP Advertisement route - RFC 7432 §7.2
    MacIpAdvertisement = 2,
    /// Inclusive Multicast Ethernet Tag route - RFC 7432 §7.3
    InclusiveMulticastEthernetTag = 3,
    /// Ethernet Segment route - RFC 7432 §7.4
    EthernetSegment = 4,
    /// IP Prefix route - RFC 9136 §3.1
    IpPrefix = 5,
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// One EVPN NLRI entry (AFI 25 / SAFI 70).
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvpnNlri {
    pub route_type: EvpnRouteType,
    /// Route Distinguisher (8 octets), shared by every EVPN route type.
    pub route_distinguisher: RouteDistinguisher,
    pub payload: EvpnRoutePayload,
}

/// Route-type-specific part of an EVPN NLRI.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EvpnRoutePayload {
    /// Route type 2 - RFC 7432 §7.2
    MacIpAdvertisement(MacIpAdvertisement),
    /// Route type 3 - RFC 7432 §7.3
    InclusiveMulticast(InclusiveMulticastRoute),
    /// Route type 5 - RFC 9136 §3.1
    IpPrefix(IpPrefixRoute),
    /// Route types this parser does not decode yet (1 and 4 at the time of
    /// writing). The octets after the route distinguisher are preserved, so
    /// nothing is lost and the value survives a debug or JSON round trip.
    Raw(Vec<u8>),
}

/// MAC/IP Advertisement route body - RFC 7432 §7.2.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MacIpAdvertisement {
    /// Ethernet Segment Identifier (10 octets); all zero for a single-homed
    /// host - RFC 7432 §5.
    pub esi: [u8; 10],
    /// Ethernet Tag ID (4 octets).
    pub ethernet_tag_id: u32,
    /// MAC address (6 octets); the route type fixes the length at 48 bits.
    pub mac: [u8; 6],
    /// IP address when the advertisement carries one; `None` when the IP
    /// address length is zero, which is a MAC-only advertisement.
    pub ip: Option<IpAddr>,
    /// Label1 (3 octets). For VXLAN this is the VNI - RFC 8365.
    pub label: u32,
}

/// Inclusive Multicast Ethernet Tag route body - RFC 7432 §7.3.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InclusiveMulticastRoute {
    /// Ethernet Tag ID (4 octets).
    pub ethernet_tag_id: u32,
    /// Originating router's IP address (4 or 16 octets).
    pub originating_router_ip: IpAddr,
}

/// IP Prefix route body - RFC 9136 §3.1.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IpPrefixRoute {
    /// Ethernet Tag ID (4 octets).
    pub ethernet_tag_id: u32,
    /// The advertised IP prefix; the prefix length is on the wire and the
    /// address family follows from it.
    pub ip_prefix: ipnet::IpNet,
    /// Gateway IP address (4 or 16 octets, matching the prefix family).
    pub gateway_ip: IpAddr,
    /// MPLS label or VNI (3 octets).
    pub label: u32,
}
