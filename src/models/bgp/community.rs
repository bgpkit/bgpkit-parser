use crate::models::Asn;
use num_enum::{FromPrimitive, IntoPrimitive};
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq, Copy, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum MetaCommunity {
    Plain(Community),
    Extended(ExtendedCommunity),
    Ipv6Extended(Ipv6AddrExtCommunity),
    Large(LargeCommunity),
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
    pub global_admin: u32,
    pub local_data: [u32; 2],
}

impl LargeCommunity {
    pub fn new(global_admin: u32, local_data: [u32; 2]) -> LargeCommunity {
        LargeCommunity {
            global_admin,
            local_data,
        }
    }
}

/// Type definitions of extended communities
#[derive(Debug, FromPrimitive, IntoPrimitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ExtendedCommunityType {
    // transitive types
    TransitiveTwoOctetAs = 0x00,
    TransitiveIpv4Addr = 0x01,
    TransitiveFourOctetAs = 0x02,
    TransitiveOpaque = 0x03,

    // non-transitive types
    NonTransitiveTwoOctetAs = 0x40,
    NonTransitiveIpv4Addr = 0x41,
    NonTransitiveFourOctetAs = 0x42,
    NonTransitiveOpaque = 0x43,
    // the rest are either draft or experimental
    #[num_enum(catch_all)]
    Unknown(u8),
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
    TransitiveTwoOctetAs(TwoOctetAsExtCommunity),
    TransitiveIpv4Addr(Ipv4AddrExtCommunity),
    TransitiveFourOctetAs(FourOctetAsExtCommunity),
    TransitiveOpaque(OpaqueExtCommunity),
    NonTransitiveTwoOctetAs(TwoOctetAsExtCommunity),
    NonTransitiveIpv4Addr(Ipv4AddrExtCommunity),
    NonTransitiveFourOctetAs(FourOctetAsExtCommunity),
    NonTransitiveOpaque(OpaqueExtCommunity),
    Raw([u8; 8]),
}

impl ExtendedCommunity {
    pub const fn community_type(&self) -> ExtendedCommunityType {
        use ExtendedCommunityType::*;
        match self {
            ExtendedCommunity::TransitiveTwoOctetAs(_) => TransitiveTwoOctetAs,
            ExtendedCommunity::TransitiveIpv4Addr(_) => TransitiveIpv4Addr,
            ExtendedCommunity::TransitiveFourOctetAs(_) => TransitiveFourOctetAs,
            ExtendedCommunity::TransitiveOpaque(_) => TransitiveOpaque,
            ExtendedCommunity::NonTransitiveTwoOctetAs(_) => NonTransitiveTwoOctetAs,
            ExtendedCommunity::NonTransitiveIpv4Addr(_) => NonTransitiveIpv4Addr,
            ExtendedCommunity::NonTransitiveFourOctetAs(_) => NonTransitiveFourOctetAs,
            ExtendedCommunity::NonTransitiveOpaque(_) => NonTransitiveOpaque,
            ExtendedCommunity::Raw(buffer) => Unknown(buffer[0]),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ipv6AddrExtCommunity {
    pub community_type: ExtendedCommunityType,
    pub subtype: u8,
    // 16 octets
    pub global_admin: Ipv6Addr,
    // 2 octets
    pub local_admin: [u8; 2],
}

/// Two-Octet AS Specific Extended Community
///
/// <https://datatracker.ietf.org/doc/html/rfc4360#section-3.1>
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TwoOctetAsExtCommunity {
    pub subtype: u8,
    // 2 octet
    pub global_admin: Asn,
    // 4 octet
    pub local_admin: [u8; 4],
}

/// Four-Octet AS Specific Extended Community
///
/// <https://datatracker.ietf.org/doc/html/rfc5668#section-2>
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FourOctetAsExtCommunity {
    pub subtype: u8,
    // 4 octet
    pub global_admin: Asn,
    // 2 octet
    pub local_admin: [u8; 2],
}

/// IPv4 Address Specific Extended Community
///
/// <https://datatracker.ietf.org/doc/html/rfc4360#section-3.2>
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ipv4AddrExtCommunity {
    pub subtype: u8,
    // 4 octet
    pub global_admin: Ipv4Addr,
    // 2 octet
    pub local_admin: [u8; 2],
}

/// Opaque Extended Community
///
/// <https://datatracker.ietf.org/doc/html/rfc4360#section-3.3>
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OpaqueExtCommunity {
    pub subtype: u8,
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
            self.global_admin, self.local_data[0], self.local_data[1]
        )
    }
}

impl Display for ExtendedCommunity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let ec_type = u8::from(self.community_type());
        match self {
            ExtendedCommunity::TransitiveTwoOctetAs(ec)
            | ExtendedCommunity::NonTransitiveTwoOctetAs(ec) => {
                write!(
                    f,
                    "ecas2:{}:{}:{}:{}",
                    ec_type,
                    ec.subtype,
                    ec.global_admin,
                    ToHexString(&ec.local_admin)
                )
            }
            ExtendedCommunity::TransitiveIpv4Addr(ec)
            | ExtendedCommunity::NonTransitiveIpv4Addr(ec) => {
                write!(
                    f,
                    "ecv4:{}:{}:{}:{}",
                    ec_type,
                    ec.subtype,
                    ec.global_admin,
                    ToHexString(&ec.local_admin)
                )
            }
            ExtendedCommunity::TransitiveFourOctetAs(ec)
            | ExtendedCommunity::NonTransitiveFourOctetAs(ec) => {
                write!(
                    f,
                    "ecas4:{}:{}:{}:{}",
                    ec_type,
                    ec.subtype,
                    ec.global_admin,
                    ToHexString(&ec.local_admin)
                )
            }
            ExtendedCommunity::TransitiveOpaque(ec)
            | ExtendedCommunity::NonTransitiveOpaque(ec) => {
                write!(
                    f,
                    "ecop:{}:{}:{}",
                    ec_type,
                    ec.subtype,
                    ToHexString(&ec.value)
                )
            }
            ExtendedCommunity::Raw(ec) => {
                write!(f, "ecraw:{}", ToHexString(ec))
            }
        }
    }
}

impl Display for Ipv6AddrExtCommunity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ecv6:{}:{}:{}:{}",
            u8::from(self.community_type),
            self.subtype,
            self.global_admin,
            ToHexString(&self.local_admin)
        )
    }
}

impl Display for MetaCommunity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MetaCommunity::Plain(c) => write!(f, "{}", c),
            MetaCommunity::Extended(c) => write!(f, "{}", c),
            MetaCommunity::Large(c) => write!(f, "{}", c),
            MetaCommunity::Ipv6Extended(c) => write!(f, "{}", c),
        }
    }
}
