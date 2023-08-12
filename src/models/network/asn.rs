use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt::{Display, Formatter};

/// AS number length: 16 or 32 bits.
#[derive(Debug, Clone, Serialize, Copy, Deserialize, PartialEq, Eq)]
pub enum AsnLength {
    Bits16,
    Bits32,
}

/// ASN -- Autonomous System Number
#[derive(Debug, Clone, Copy, Eq)]
pub struct Asn {
    pub asn: u32,
    pub len: AsnLength,
}

impl PartialEq for Asn {
    fn eq(&self, other: &Self) -> bool {
        self.asn == other.asn
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
        Asn {
            asn: v,
            len: AsnLength::Bits32,
        }
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

impl Asn {
    pub fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        match self.len {
            AsnLength::Bits16 => bytes.put_u16(self.asn as u16),
            AsnLength::Bits32 => bytes.put_u32(self.asn),
        }
        bytes.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ReadUtils;

    #[test]
    fn test_asn_encode() {
        let asn = Asn {
            asn: 123,
            len: AsnLength::Bits16,
        };
        let mut bytes = asn.encode();
        assert_eq!(123, bytes.read_u16().unwrap());

        let asn = Asn {
            asn: 123,
            len: AsnLength::Bits32,
        };
        let mut bytes = asn.encode();
        assert_eq!(123, bytes.read_u32().unwrap());
    }
}
