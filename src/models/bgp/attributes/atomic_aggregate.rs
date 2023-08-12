use serde::{Serialize, Serializer};
use std::fmt::{Display, Formatter};

#[allow(non_camel_case_types)]
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
pub enum AtomicAggregate {
    NAG = 0,
    AG = 1,
}

impl Display for AtomicAggregate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AtomicAggregate::NAG => {
                    "NAG"
                }
                AtomicAggregate::AG => {
                    "AG"
                }
            }
        )
    }
}

impl Serialize for AtomicAggregate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}
