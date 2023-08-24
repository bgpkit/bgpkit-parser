//! BGP attribute structs
mod aspath;
mod atomic_aggregate;
mod nlri;
mod origin;

use crate::models::network::*;
use std::net::IpAddr;

use crate::models::*;

pub use aspath::*;
pub use atomic_aggregate::*;
pub use nlri::*;
pub use origin::*;

/// The high-order bit (bit 0) of the Attribute Flags octet is the
/// Optional bit.  It defines whether the attribute is optional (if
/// set to 1) or well-known (if set to 0).
///
/// The second high-order bit (bit 1) of the Attribute Flags octet
/// is the Transitive bit.  It defines whether an optional
/// attribute is transitive (if set to 1) or non-transitive (if set
/// to 0).
///
/// For well-known attributes, the Transitive bit MUST be set to 1.
/// (See Section 5 for a discussion of transitive attributes.)
///
/// The third high-order bit (bit 2) of the Attribute Flags octet
/// is the Partial bit.  It defines whether the information
/// contained in the optional transitive attribute is partial (if
/// set to 1) or complete (if set to 0).  For well-known attributes
/// and for optional non-transitive attributes, the Partial bit
/// MUST be set to 0.
///
/// The fourth high-order bit (bit 3) of the Attribute Flags octet
/// is the Extended Length bit.  It defines whether the Attribute
/// Length is one octet (if set to 0) or two octets (if set to 1).
pub enum AttributeFlagsBit {
    /// 128 = 0b10000000
    OptionalBit = 0b10000000,
    /// 64 = 0b01000000
    TransitiveBit = 0b01000000,
    /// 32 = 0b00100000
    PartialBit = 0b00100000,
    /// 16 = 0b00010000
    ExtendedLengthBit = 0b00010000,
}

/// Attribute types.
///
/// All attributes currently defined and not Unassigned or Deprecated are included here.
/// To see the full list, check out IANA at:
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2>
#[allow(non_camel_case_types)]
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AttrType {
    RESERVED = 0,
    ORIGIN = 1,
    AS_PATH = 2,
    NEXT_HOP = 3,
    MULTI_EXIT_DISCRIMINATOR = 4,
    LOCAL_PREFERENCE = 5,
    ATOMIC_AGGREGATE = 6,
    AGGREGATOR = 7,
    COMMUNITIES = 8,
    /// <https://tools.ietf.org/html/rfc4456>
    ORIGINATOR_ID = 9,
    CLUSTER_LIST = 10,
    /// <https://tools.ietf.org/html/rfc4760>
    CLUSTER_ID = 13,
    MP_REACHABLE_NLRI = 14,
    MP_UNREACHABLE_NLRI = 15,
    /// <https://datatracker.ietf.org/doc/html/rfc4360>
    EXTENDED_COMMUNITIES = 16,
    AS4_PATH = 17,
    AS4_AGGREGATOR = 18,
    PMSI_TUNNEL = 22,
    TUNNEL_ENCAPSULATION = 23,
    TRAFFIC_ENGINEERING = 24,
    IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES = 25,
    AIGP = 26,
    PE_DISTINGUISHER_LABELS = 27,
    BGP_LS_ATTRIBUTE = 29,
    LARGE_COMMUNITIES = 32,
    BGPSEC_PATH = 33,
    ONLY_TO_CUSTOMER = 35,
    SFP_ATTRIBUTE = 37,
    BFD_DISCRIMINATOR = 38,
    BGP_PREFIX_SID = 40,
    ATTR_SET = 128,
    /// <https://datatracker.ietf.org/doc/html/rfc2042>
    DEVELOPMENT = 255,
}

pub fn get_deprecated_attr_type(attr_type: u8) -> Option<&'static str> {
    match attr_type {
        11 => Some("DPA"),
        12 => Some("ADVERTISER"),
        13 => Some("RCID_PATH"),
        19 => Some("SAFI Specific Attribute"),
        20 => Some("Connector Attribute"),
        21 => Some("AS_PATHLIMIT"),
        28 => Some("BGP Entropy Label Capability"),
        30 | 31 | 129 | 241 | 242 | 243 => Some("RFC8093"),

        _ => None,
    }
}

/// BGP Attribute struct with attribute value and flag
#[derive(Debug, PartialEq, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Attribute {
    pub attr_type: u8,
    pub value: AttributeValue,
    pub flag: u8,
}

/// The `AttributeValue` enum represents different kinds of Attribute values.
#[derive(Debug, PartialEq, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AttributeValue {
    Origin(Origin),
    AsPath(AsPath),
    As4Path(AsPath),
    NextHop(IpAddr),
    MultiExitDiscriminator(u32),
    LocalPreference(u32),
    OnlyToCustomer(u32),
    AtomicAggregate(AtomicAggregate),
    Aggregator(Asn, IpAddr),
    Communities(Vec<Community>),
    ExtendedCommunities(Vec<ExtendedCommunity>),
    LargeCommunities(Vec<LargeCommunity>),
    OriginatorId(IpAddr),
    Clusters(Vec<IpAddr>),
    MpReachNlri(Nlri),
    MpUnreachNlri(Nlri),
    Development(Vec<u8>),
    Deprecated(AttrRaw),
    Unknown(AttrRaw),
}

#[derive(Debug, PartialEq, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AttrRaw {
    pub attr_type: u8,
    pub bytes: Vec<u8>,
}

///////////////////
// DISPLAY IMPLS //
///////////////////
