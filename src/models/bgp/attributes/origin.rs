use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::fmt::{Display, Formatter};

#[allow(non_camel_case_types)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Origin {
    /// Interior Gateway Protocol
    IGP = 0,
    /// Exterior Gateway Protocol
    /// <https://datatracker.ietf.org/doc/html/rfc904>
    EGP = 1,
    INCOMPLETE = 2,
}

impl Display for Origin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::IGP => write!(f, "IGP"),
            Origin::EGP => write!(f, "EGP"),
            Origin::INCOMPLETE => write!(f, "INCOMPLETE"),
        }
    }
}
