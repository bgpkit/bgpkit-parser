use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

/// AS number length: 16 or 32 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AsnLength {
    Bits16,
    Bits32,
}

/// ASN -- Autonomous System Number
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "u32", into = "u32"))]
pub struct Asn {
    asn: u32,
}

impl Asn {
    pub const RESERVED: Self = Asn::new_16bit(0);
    #[doc(alias("AS_TRANS"))]
    pub const TRANSITION: Self = Asn::new_16bit(23456);

    /// Constructs a new 2-octet `Asn`.
    #[inline]
    pub const fn new_16bit(asn: u16) -> Self {
        Asn { asn: asn as u32 }
    }

    /// Constructs a new 4-octet `Asn`.
    #[inline]
    pub const fn new_32bit(asn: u32) -> Self {
        Asn { asn }
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
    fn default() -> Self {
        Asn::RESERVED
    }
}

impl PartialEq<u32> for Asn {
    #[inline]
    fn eq(&self, other: &u32) -> bool {
        self.asn == *other
    }
}

impl From<u32> for Asn {
    #[inline]
    fn from(v: u32) -> Self {
        Asn::new_32bit(v)
    }
}

impl From<Asn> for u32 {
    #[inline]
    fn from(value: Asn) -> Self {
        value.asn
    }
}

impl From<&Asn> for u32 {
    #[inline]
    fn from(value: &Asn) -> Self {
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

/// Parse an ASN matching the pattern `(AS)?[0-9]+`.
impl FromStr for Asn {
    type Err = <u32 as FromStr>::Err;

    #[inline]
    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        if let Some(number) = s.strip_prefix("AS") {
            s = number;
        }

        Ok(Asn::new_32bit(u32::from_str(s)?))
    }
}
