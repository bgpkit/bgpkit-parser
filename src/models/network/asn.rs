use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};

/// AS number length: 16 or 32 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AsnLength {
    Bits16,
    Bits32,
}

/// ASN -- Autonomous System Number
#[derive(Clone, Copy, Eq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "u32", into = "u32"))]
pub struct Asn {
    pub asn: u32,
    pub len: AsnLength,
}

impl Asn {
    pub const RESERVED: Self = Asn::new_16bit(0);

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

    /// Gets the size required to store this ASN
    pub const fn required_len(&self) -> AsnLength {
        if self.asn <= u16::MAX as u32 {
            return AsnLength::Bits16;
        }

        AsnLength::Bits32
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

    /// Checks if the given ASN is reserved. This is done by checking if the asn is included
    /// within IANA's "Special-Purpose AS Numbers" registry. This includes checking against private
    /// ASN ranges, ASNs reserved for documentation, and ASNs reserved for specific uses by various
    /// RFCs.
    ///
    /// Up to date as of 2023-03-01 (Registry was last updated 2015-08-07).
    ///
    /// For additional details see:
    ///  - <https://datatracker.ietf.org/doc/rfc7249/>
    ///  - <https://www.iana.org/assignments/iana-as-numbers-special-registry/iana-as-numbers-special-registry.xhtml>
    pub const fn is_reserved(&self) -> bool {
        match self.asn {
            0 => true,                       // reserved by RFC7607
            112 => true,                     // reserved by RFC7534
            23456 => true,                   // reserved by RFC6793
            64496..=64511 => true,           // reserved by RFC5398
            64512..=65534 => true,           // reserved by RFC6996
            65535 => true,                   // reserved by RFC7300
            65536..=65551 => true,           // reserved by RFC5398
            4200000000..=4294967294 => true, // reserved by RFC6996
            4294967295 => true,              // reserved by RFC7300
            _ => false,
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

/// Creates an ASN with a value of 0. This is equivalent to [Asn::RESERVED].
impl Default for Asn {
    fn default() -> Self {
        Asn::RESERVED
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

impl Display for Asn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.asn)
    }
}

impl Debug for Asn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.asn)
    }
}
