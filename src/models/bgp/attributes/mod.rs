//! BGP attribute structs
mod aspath;
mod atomic_aggregate;
mod nlri;
mod origin;

use crate::models::network::*;
use bitflags::bitflags;
use std::iter::{FromIterator, Map};
use std::net::IpAddr;
use std::ops::Deref;
use std::slice::Iter;
use std::vec::IntoIter;

use crate::models::*;

pub use aspath::*;
pub use atomic_aggregate::*;
pub use nlri::*;
pub use origin::*;

bitflags! {
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
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct AttrFlags: u8 {
        const OPTIONAL   = 0b10000000;
        const TRANSITIVE = 0b01000000;
        const PARTIAL    = 0b00100000;
        const EXTENDED   = 0b00010000;
    }
}

/// Attribute types.
///
/// All attributes currently defined and not Unassigned or Deprecated are included here.
/// To see the full list, check out IANA at:
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2>
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AttrType {
    RESERVED,
    ORIGIN,
    AS_PATH,
    NEXT_HOP,
    MULTI_EXIT_DISCRIMINATOR,
    LOCAL_PREFERENCE,
    ATOMIC_AGGREGATE,
    AGGREGATOR,
    COMMUNITIES,
    /// <https://tools.ietf.org/html/rfc4456>
    ORIGINATOR_ID,
    CLUSTER_LIST,
    /// <https://tools.ietf.org/html/rfc4760>
    CLUSTER_ID,
    MP_REACHABLE_NLRI,
    MP_UNREACHABLE_NLRI,
    /// <https://datatracker.ietf.org/doc/html/rfc4360>
    EXTENDED_COMMUNITIES,
    AS4_PATH,
    AS4_AGGREGATOR,
    PMSI_TUNNEL,
    TUNNEL_ENCAPSULATION,
    TRAFFIC_ENGINEERING,
    IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES,
    AIGP,
    PE_DISTINGUISHER_LABELS,
    BGP_LS_ATTRIBUTE,
    LARGE_COMMUNITIES,
    BGPSEC_PATH,
    ONLY_TO_CUSTOMER,
    SFP_ATTRIBUTE,
    BFD_DISCRIMINATOR,
    BGP_PREFIX_SID,
    ATTR_SET,
    /// <https://datatracker.ietf.org/doc/html/rfc2042>
    DEVELOPMENT,
    /// Catch all for any unknown attribute types
    Unknown(u8),
}

impl From<u8> for AttrType {
    fn from(value: u8) -> Self {
        match value {
            0 => AttrType::RESERVED,
            1 => AttrType::ORIGIN,
            2 => AttrType::AS_PATH,
            3 => AttrType::NEXT_HOP,
            4 => AttrType::MULTI_EXIT_DISCRIMINATOR,
            5 => AttrType::LOCAL_PREFERENCE,
            6 => AttrType::ATOMIC_AGGREGATE,
            7 => AttrType::AGGREGATOR,
            8 => AttrType::COMMUNITIES,
            9 => AttrType::ORIGINATOR_ID,
            10 => AttrType::CLUSTER_LIST,
            13 => AttrType::CLUSTER_ID,
            14 => AttrType::MP_REACHABLE_NLRI,
            15 => AttrType::MP_UNREACHABLE_NLRI,
            16 => AttrType::EXTENDED_COMMUNITIES,
            17 => AttrType::AS4_PATH,
            18 => AttrType::AS4_AGGREGATOR,
            22 => AttrType::PMSI_TUNNEL,
            23 => AttrType::TUNNEL_ENCAPSULATION,
            24 => AttrType::TRAFFIC_ENGINEERING,
            25 => AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES,
            26 => AttrType::AIGP,
            27 => AttrType::PE_DISTINGUISHER_LABELS,
            29 => AttrType::BGP_LS_ATTRIBUTE,
            32 => AttrType::LARGE_COMMUNITIES,
            33 => AttrType::BGPSEC_PATH,
            35 => AttrType::ONLY_TO_CUSTOMER,
            37 => AttrType::SFP_ATTRIBUTE,
            38 => AttrType::BFD_DISCRIMINATOR,
            40 => AttrType::BGP_PREFIX_SID,
            128 => AttrType::ATTR_SET,
            255 => AttrType::DEVELOPMENT,
            x => AttrType::Unknown(x),
        }
    }
}

impl From<AttrType> for u8 {
    fn from(value: AttrType) -> Self {
        match value {
            AttrType::RESERVED => 0,
            AttrType::ORIGIN => 1,
            AttrType::AS_PATH => 2,
            AttrType::NEXT_HOP => 3,
            AttrType::MULTI_EXIT_DISCRIMINATOR => 4,
            AttrType::LOCAL_PREFERENCE => 5,
            AttrType::ATOMIC_AGGREGATE => 6,
            AttrType::AGGREGATOR => 7,
            AttrType::COMMUNITIES => 8,
            AttrType::ORIGINATOR_ID => 9,
            AttrType::CLUSTER_LIST => 10,
            AttrType::CLUSTER_ID => 13,
            AttrType::MP_REACHABLE_NLRI => 14,
            AttrType::MP_UNREACHABLE_NLRI => 15,
            AttrType::EXTENDED_COMMUNITIES => 16,
            AttrType::AS4_PATH => 17,
            AttrType::AS4_AGGREGATOR => 18,
            AttrType::PMSI_TUNNEL => 22,
            AttrType::TUNNEL_ENCAPSULATION => 23,
            AttrType::TRAFFIC_ENGINEERING => 24,
            AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES => 25,
            AttrType::AIGP => 26,
            AttrType::PE_DISTINGUISHER_LABELS => 27,
            AttrType::BGP_LS_ATTRIBUTE => 29,
            AttrType::LARGE_COMMUNITIES => 32,
            AttrType::BGPSEC_PATH => 33,
            AttrType::ONLY_TO_CUSTOMER => 35,
            AttrType::SFP_ATTRIBUTE => 37,
            AttrType::BFD_DISCRIMINATOR => 38,
            AttrType::BGP_PREFIX_SID => 40,
            AttrType::ATTR_SET => 128,
            AttrType::DEVELOPMENT => 255,
            AttrType::Unknown(x) => x,
        }
    }
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

/// Convenience wrapper for a list of attributes
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Attributes {
    // Black box type to allow for later changes/optimizations. The most common attributes could be
    // added as fields to allow for easier lookup.
    inner: Vec<Attribute>,
}

impl Attributes {
    pub fn has_attr(&self, ty: AttrType) -> bool {
        self.inner.iter().any(|x| x.value.attr_type() == ty)
    }

    // These implementations are horribly inefficient, but they were super easy to write and use
    pub fn as_path(&self) -> Option<&AsPath> {
        self.inner
            .iter()
            .filter_map(|x| match &x.value {
                AttributeValue::AsPath(x) | AttributeValue::As4Path(x) => Some(x),
                _ => None,
            })
            .next()
    }

    pub fn get_reachable(&self) -> Option<&Nlri> {
        self.inner
            .iter()
            .filter_map(|x| match &x.value {
                AttributeValue::MpReachNlri(x) => Some(x),
                _ => None,
            })
            .next()
    }

    pub fn get_unreachable(&self) -> Option<&Nlri> {
        self.inner
            .iter()
            .filter_map(|x| match &x.value {
                AttributeValue::MpUnreachNlri(x) => Some(x),
                _ => None,
            })
            .next()
    }
}

impl FromIterator<Attribute> for Attributes {
    fn from_iter<T: IntoIterator<Item = Attribute>>(iter: T) -> Self {
        Attributes {
            inner: iter.into_iter().collect(),
        }
    }
}

impl From<Vec<Attribute>> for Attributes {
    fn from(value: Vec<Attribute>) -> Self {
        Attributes { inner: value }
    }
}

impl Extend<Attribute> for Attributes {
    fn extend<T: IntoIterator<Item = Attribute>>(&mut self, iter: T) {
        self.inner.extend(iter)
    }
}

impl FromIterator<AttributeValue> for Attributes {
    fn from_iter<T: IntoIterator<Item = AttributeValue>>(iter: T) -> Self {
        Attributes {
            inner: iter
                .into_iter()
                .map(|value| Attribute {
                    attr_type: value.attr_type(),
                    value,
                    flag: AttrFlags::empty(),
                })
                .collect(),
        }
    }
}

impl IntoIterator for Attributes {
    type Item = AttributeValue;
    type IntoIter = Map<IntoIter<Attribute>, fn(Attribute) -> AttributeValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter().map(|x| x.value)
    }
}

impl<'a> IntoIterator for &'a Attributes {
    type Item = &'a AttributeValue;
    type IntoIter = Map<Iter<'a, Attribute>, fn(&Attribute) -> &AttributeValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter().map(|x| &x.value)
    }
}

impl Deref for Attributes {
    type Target = Vec<Attribute>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for Attributes {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            self.inner.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Attributes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            Ok(Attributes {
                inner: <Vec<Attribute>>::deserialize(deserializer)?,
            })
        }
    }
}

/// BGP Attribute struct with attribute value and flag
#[derive(Debug, PartialEq, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Attribute {
    pub attr_type: AttrType,
    pub value: AttributeValue,
    pub flag: AttrFlags,
}

impl Deref for Attribute {
    type Target = AttributeValue;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
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

impl AttributeValue {
    pub fn attr_type(&self) -> AttrType {
        match self {
            AttributeValue::Origin(_) => AttrType::ORIGIN,
            AttributeValue::AsPath(_) => AttrType::AS_PATH,
            AttributeValue::As4Path(_) => AttrType::AS4_PATH,
            AttributeValue::NextHop(_) => AttrType::NEXT_HOP,
            AttributeValue::MultiExitDiscriminator(_) => AttrType::MULTI_EXIT_DISCRIMINATOR,
            AttributeValue::LocalPreference(_) => AttrType::LOCAL_PREFERENCE,
            AttributeValue::OnlyToCustomer(_) => AttrType::ONLY_TO_CUSTOMER,
            AttributeValue::AtomicAggregate(_) => AttrType::ATOMIC_AGGREGATE,
            AttributeValue::Aggregator(_, _) => AttrType::AGGREGATOR,
            AttributeValue::Communities(_) => AttrType::COMMUNITIES,
            AttributeValue::ExtendedCommunities(_) => AttrType::EXTENDED_COMMUNITIES,
            AttributeValue::LargeCommunities(_) => AttrType::LARGE_COMMUNITIES,
            AttributeValue::OriginatorId(_) => AttrType::ORIGINATOR_ID,
            AttributeValue::Clusters(_) => AttrType::CLUSTER_LIST,
            AttributeValue::MpReachNlri(_) => AttrType::MP_REACHABLE_NLRI,
            AttributeValue::MpUnreachNlri(_) => AttrType::MP_UNREACHABLE_NLRI,
            AttributeValue::Development(_) => AttrType::DEVELOPMENT,
            AttributeValue::Deprecated(x) | AttributeValue::Unknown(x) => x.attr_type,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AttrRaw {
    pub attr_type: AttrType,
    pub bytes: Vec<u8>,
}
