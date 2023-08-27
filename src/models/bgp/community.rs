use crate::models::Asn;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq, Copy, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum MetaCommunity {
    Community(Community),
    ExtendedCommunity(ExtendedCommunity),
    LargeCommunity(LargeCommunity),
}

#[derive(Debug, PartialEq, Copy, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Community {
    NoExport,
    NoAdvertise,
    NoExportSubConfed,
    Custom(Asn, u16),
}

/// Large community structure as defined in [RFC8092](https://datatracker.ietf.org/doc/html/rfc8092)
///
/// ## Display
///
/// Large community is displayed as `lg:GLOBAL_ADMINISTRATOR:LOCAL_DATA_1:LOCAL_DATA_2`, where `lg`
/// is a prefix for large community.
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
/// ## Overview  
///
/// It is a 8-octet data that has flexible definition based on the types:
/// <https://datatracker.ietf.org/doc/html/rfc4360>
///
/// For more up-to-date definitions, see [IANA' website](https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml).
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
///
/// ## Display
///
/// When output, the extended communities has the following string prefixes to indicate the sub type:
/// - `ecas2:` stands for `Extended Community AS Specific 2-octet`
/// - `ecas4:` stands for `Extended Community AS Specific 4-octet`
/// - `ecv4:` stands for `Extended Community IPv4 Specific`
/// - `ecv6:` stands for `Extended Community IPv6 Specific`
/// - `ecop:` stands for `Extended Community Opaque`
/// - `ecraw:` stands for `Extended Community Raw`
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ipv6AddressSpecific {
    pub ec_type: u8,
    pub ec_subtype: u8,
    // 16 octets
    pub global_administrator: Ipv6Addr,
    // 2 octets
    pub local_administrator: [u8; 2],
}

/// Two-Octet AS Specific Extended Community
///
/// <https://datatracker.ietf.org/doc/html/rfc4360#section-3.1>
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Opaque {
    pub ec_type: u8,
    pub ec_subtype: u8,
    // 6 octet
    pub value: [u8; 6],
}

/////////////
// DISPLAY //
/////////////

struct ToHexString<'a>(&'a [u8]);

impl Display for ToHexString<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl Display for Community {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Community::NoExport => write!(f, "no-export"),
            Community::NoAdvertise => write!(f, "no-advertise"),
            Community::NoExportSubConfed => write!(f, "no-export-sub-confed"),
            Community::Custom(asn, value) => write!(f, "{}:{}", asn, value),
        }
    }
}

impl Display for LargeCommunity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "lg:{}:{}:{}",
            self.global_administrator, self.local_data[0], self.local_data[1]
        )
    }
}

impl Display for ExtendedCommunity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtendedCommunity::TransitiveTwoOctetAsSpecific(ec)
            | ExtendedCommunity::NonTransitiveTwoOctetAsSpecific(ec) => {
                write!(
                    f,
                    "ecas2:{}:{}:{}:{}",
                    ec.ec_type,
                    ec.ec_subtype,
                    ec.global_administrator,
                    ToHexString(&ec.local_administrator)
                )
            }
            ExtendedCommunity::TransitiveIpv4AddressSpecific(ec)
            | ExtendedCommunity::NonTransitiveIpv4AddressSpecific(ec) => {
                write!(
                    f,
                    "ecv4:{}:{}:{}:{}",
                    ec.ec_type,
                    ec.ec_subtype,
                    ec.global_administrator,
                    ToHexString(&ec.local_administrator)
                )
            }
            ExtendedCommunity::TransitiveFourOctetAsSpecific(ec)
            | ExtendedCommunity::NonTransitiveFourOctetAsSpecific(ec) => {
                write!(
                    f,
                    "ecas4:{}:{}:{}:{}",
                    ec.ec_type,
                    ec.ec_subtype,
                    ec.global_administrator,
                    ToHexString(&ec.local_administrator)
                )
            }
            ExtendedCommunity::TransitiveOpaque(ec)
            | ExtendedCommunity::NonTransitiveOpaque(ec) => {
                write!(
                    f,
                    "ecop:{}:{}:{}",
                    ec.ec_type,
                    ec.ec_subtype,
                    ToHexString(&ec.value)
                )
            }
            ExtendedCommunity::Ipv6AddressSpecific(ec) => {
                write!(
                    f,
                    "ecv6:{}:{}:{}:{}",
                    ec.ec_type,
                    ec.ec_subtype,
                    ec.global_administrator,
                    ToHexString(&ec.local_administrator)
                )
            }
            ExtendedCommunity::Raw(ec) => {
                write!(f, "ecraw:{}", ToHexString(ec))
            }
        }
    }
}

impl Display for MetaCommunity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MetaCommunity::Community(c) => write!(f, "{}", c),
            MetaCommunity::ExtendedCommunity(c) => write!(f, "{}", c),
            MetaCommunity::LargeCommunity(c) => write!(f, "{}", c),
        }
    }
}
