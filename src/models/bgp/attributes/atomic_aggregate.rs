use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::fmt::{Display, Formatter};

#[allow(non_camel_case_types)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum AtomicAggregate {
    NAG = 0,
    AG = 1,
}

impl Display for AtomicAggregate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AtomicAggregate::NAG => write!(f, "NAG"),
            AtomicAggregate::AG => write!(f, "AG"),
        }
    }
}
