use serde::{Deserialize, Serialize, Serializer};
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};

/// AS number length: 16 or 32 bits.
#[derive(Debug, Clone, Serialize, Copy, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum AsnLength {
    Bits16,
    Bits32,
}

/// ASN -- Autonomous System Number
#[derive(Debug, Clone, Copy, Eq, Ord, PartialOrd)]
pub struct Asn {
    pub asn: u32,
    pub len: AsnLength,
}

impl Asn {
    /// Constructs a new 2-octet `Asn` with `AsnLength::Bits16`.
    pub const fn new_16bit(asn: u16) -> Self {
        Asn {
            asn: asn as u32,
            len: AsnLength::Bits16,
        }
    }

    /// Constructs a new 4-octet `Asn` with `AsnLength::Bits32`.
    pub const fn new_32bit(asn: u32) -> Self {
        Asn {
            asn,
            len: AsnLength::Bits32,
        }
    }

    /// Checks if the given ASN is reserved for private use.
    ///
    /// <https://datatracker.ietf.org/doc/rfc7249/>
    pub const fn is_private(&self) -> bool {
        match self.asn {
            64512..=65534 => true,           // reserved by RFC6996
            4200000000..=4294967294 => true, // reserved by RFC6996
            _ => false,
        }
    }

    /// Checks if the given ASN is public. This is done by checking that the asn is not included
    /// within IANA's "Special-Purpose AS Numbers" registry. This includes checking against private
    /// ASN ranges, ASNs reserved for documentation, and ASNs reserved for specific uses by various
    /// RFCs.
    ///
    /// Up to date as of 2023-03-01 (Registry was last updated 2015-08-07).
    ///
    /// For additional details see:
    ///  - <https://datatracker.ietf.org/doc/rfc7249/>
    ///  - <https://www.iana.org/assignments/iana-as-numbers-special-registry/iana-as-numbers-special-registry.xhtml>
    pub const fn is_public(&self) -> bool {
        match self.asn {
            0 => false,                       // reserved by RFC7607
            112 => false,                     // reserved by RFC7534
            23456 => false,                   // reserved by RFC6793
            64496..=64511 => false,           // reserved by RFC5398
            64512..=65534 => false,           // reserved by RFC6996
            65535 => false,                   // reserved by RFC7300
            65536..=65551 => false,           // reserved by RFC5398
            4200000000..=4294967294 => false, // reserved by RFC6996
            4294967295 => false,              // reserved by RFC7300
            _ => true,
        }
    }

    /// Checks if the given ASN is reserved for use in documentation and sample code.
    ///
    /// <https://datatracker.ietf.org/doc/rfc7249/>
    pub const fn is_reserved_for_documentation(&self) -> bool {
        match self.asn {
            64496..=64511 => true, // reserved by RFC5398
            65536..=65551 => true, // reserved by RFC5398
            _ => false,
        }
    }
}

impl PartialEq for Asn {
    fn eq(&self, other: &Self) -> bool {
        self.asn == other.asn
    }
}

impl Hash for Asn {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.asn.hash(state);
    }
}

impl PartialEq<i32> for Asn {
    fn eq(&self, other: &i32) -> bool {
        self.asn as i32 == *other
    }
}

impl PartialEq<u32> for Asn {
    fn eq(&self, other: &u32) -> bool {
        self.asn == *other
    }
}

impl From<u32> for Asn {
    fn from(v: u32) -> Self {
        Asn::new_32bit(v)
    }
}

impl From<i32> for Asn {
    fn from(v: i32) -> Self {
        Asn {
            asn: v as u32,
            len: AsnLength::Bits32,
        }
    }
}

impl From<Asn> for i32 {
    fn from(val: Asn) -> Self {
        val.asn as i32
    }
}

impl From<Asn> for u32 {
    fn from(value: Asn) -> Self {
        value.asn
    }
}

impl Serialize for Asn {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.asn)
    }
}

impl Display for Asn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.asn)
    }
}
