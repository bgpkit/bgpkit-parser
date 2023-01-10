use std::fmt::Formatter;
use enum_primitive_derive::Primitive;
use std::net::{Ipv4Addr, Ipv6Addr};
use serde::Serialize;
use crate::network::Asn;

#[derive(Debug, PartialEq, Copy, Clone, Eq)]
pub enum MetaCommunity {
    Community(Community),
    ExtendedCommunity(ExtendedCommunity),
    LargeCommunity(LargeCommunity),
}

#[derive(Debug, PartialEq, Copy, Clone, Eq)]
pub enum Community {
    NoExport,
    NoAdvertise,
    NoExportSubConfed,
    Custom(Asn, u16),
}

#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub struct LargeCommunity {
    pub global_administrator: u32,
    pub local_data: [u32; 2],
}

impl LargeCommunity {
    pub fn new(global_administrator: u32, local_data: [u32; 2]) -> LargeCommunity {
        LargeCommunity {
            global_administrator,
            local_data,
        }
    }
}

/// Type definitions of extended communities
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
pub enum ExtendedCommunityType {
    // transitive types

    TransitiveTwoOctetAsSpecific = 0x00,
    TransitiveIpv4AddressSpecific = 0x01,
    TransitiveFourOctetAsSpecific = 0x02,
    TransitiveOpaque = 0x03,

    // non-transitive types

    NonTransitiveTwoOctetAsSpecific = 0x40,
    NonTransitiveIpv4AddressSpecific = 0x41,
    NonTransitiveFourOctetAsSpecific = 0x42,
    NonTransitiveOpaque = 0x43,

    // the rest are either draft or experimental
}

/// Extended Communities.
///
/// It is a 8-octet data that has flexible definition based on the types:
/// <https://datatracker.ietf.org/doc/html/rfc4360>
///
/// For more up-to-date definitions, see [IANA' website](https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml#e-tree-flags).
///
/// ```text
///    Each Extended Community is encoded as an 8-octet quantity, as
///    follows:
///
///       - Type Field  : 1 or 2 octets
///       - Value Field : Remaining octets
///
///        0                   1                   2                   3
///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |  Type high    |  Type low(*)  |                               |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+          Value                |
///       |                                                               |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///       (*) Present for Extended types only, used for the Value field
///           otherwise.
/// ```
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub enum ExtendedCommunity {
    TransitiveTwoOctetAsSpecific(TwoOctetAsSpecific),
    TransitiveIpv4AddressSpecific(Ipv4AddressSpecific),
    TransitiveFourOctetAsSpecific(FourOctetAsSpecific),
    TransitiveOpaque(Opaque),
    NonTransitiveTwoOctetAsSpecific(TwoOctetAsSpecific),
    NonTransitiveIpv4AddressSpecific(Ipv4AddressSpecific),
    NonTransitiveFourOctetAsSpecific(FourOctetAsSpecific),
    NonTransitiveOpaque(Opaque),
    Ipv6AddressSpecific(Ipv6AddressSpecific),
    Raw([u8; 8]),
}

#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub struct Ipv6AddressSpecific {
    pub ec_type: u8,
    pub ec_subtype: u8,
    // 16 octets
    pub global_administrator: Ipv6Addr,
    // 2 octets
    pub local_administrator: [u8; 2]
}


/// Two-Octet AS Specific Extended Community
///
/// <https://datatracker.ietf.org/doc/html/rfc4360#section-3.1>
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub struct TwoOctetAsSpecific {
    pub ec_type: u8,
    pub ec_subtype: u8,
    // 2 octet
    pub global_administrator: Asn,
    // 4 octet
    pub local_administrator: [u8; 4],
}

/// Four-Octet AS Specific Extended Community
///
/// <https://datatracker.ietf.org/doc/html/rfc5668#section-2>
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub struct FourOctetAsSpecific {
    pub ec_type: u8,
    pub ec_subtype: u8,
    // 4 octet
    pub global_administrator: Asn,
    // 2 octet
    pub local_administrator: [u8; 2],
}

/// IPv4 Address Specific Extended Community
///
/// <https://datatracker.ietf.org/doc/html/rfc4360#section-3.2>
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub struct Ipv4AddressSpecific {
    pub ec_type: u8,
    pub ec_subtype: u8,
    // 4 octet
    pub global_administrator: Ipv4Addr,
    // 2 octet
    pub local_administrator: [u8; 2],
}

/// Opaque Extended Community
///
/// <https://datatracker.ietf.org/doc/html/rfc4360#section-3.3>
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub struct Opaque {
    pub ec_type: u8,
    pub ec_subtype: u8,
    // 6 octet
    pub value: [u8; 6],
}

/////////////
// DISPLAY //
/////////////

fn bytes_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{:02X}", x)).collect::<Vec<String>>().join("")
}


impl std::fmt::Display for Community {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Community::NoExport => {
                "no-export".to_string()
            }
            Community::NoAdvertise => {
                "no-advertise".to_string()
            }
            Community::NoExportSubConfed => {
                "no-export-sub-confed".to_string()
            }
            Community::Custom(asn, value) => {
                format!("{}:{}", asn, value)
            }
        }
        )
    }
}

impl std::fmt::Display for LargeCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lg:{}:{}:{}", self.global_administrator, self.local_data[0], self.local_data[1])
    }
}

impl std::fmt::Display for ExtendedCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            ExtendedCommunity::TransitiveTwoOctetAsSpecific(ec) | ExtendedCommunity::NonTransitiveTwoOctetAsSpecific(ec) => {
                format!("ecas2:{}:{}:{}:{}", ec.ec_type, ec.ec_subtype, ec.global_administrator, bytes_to_string(&ec.local_administrator))
            }
            ExtendedCommunity::TransitiveIpv4AddressSpecific(ec) |
            ExtendedCommunity::NonTransitiveIpv4AddressSpecific(ec) => {
                format!("ecv4:{}:{}:{}:{}", ec.ec_type, ec.ec_subtype, ec.global_administrator, bytes_to_string(&ec.local_administrator))
            }
            ExtendedCommunity::TransitiveFourOctetAsSpecific(ec) |
            ExtendedCommunity::NonTransitiveFourOctetAsSpecific(ec) => {
                format!("ecas4:{}:{}:{}:{}", ec.ec_type, ec.ec_subtype, ec.global_administrator, bytes_to_string(&ec.local_administrator))
            }
            ExtendedCommunity::TransitiveOpaque(ec) |
            ExtendedCommunity::NonTransitiveOpaque(ec) => {
                format!("ecop:{}:{}:{}", ec.ec_type, ec.ec_subtype, bytes_to_string(&ec.value))
            }
            ExtendedCommunity::Ipv6AddressSpecific(ec) => {
                format!("ecv6:{}:{}:{}:{}", ec.ec_type, ec.ec_subtype, ec.global_administrator, bytes_to_string(&ec.local_administrator))
            }
            ExtendedCommunity::Raw(ec) => {
                format!("ecraw:{}", bytes_to_string(ec))
            }
        })
    }
}

impl std::fmt::Display for MetaCommunity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}",
            match self {
                MetaCommunity::Community(c) => {c.to_string()}
                MetaCommunity::ExtendedCommunity(c) => {c.to_string()}
                MetaCommunity::LargeCommunity(c) => {c.to_string()}
            }
        )
    }
}

///////////////
// SERIALIZE //
///////////////

macro_rules! impl_serialize {
    ($a:ident) => {
        impl Serialize for $a {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
                serializer.serialize_str(self.to_string().as_str())
            }
        }
    }
}

impl_serialize!(Community);
impl_serialize!(ExtendedCommunity);
impl_serialize!(LargeCommunity);
impl_serialize!(MetaCommunity);
