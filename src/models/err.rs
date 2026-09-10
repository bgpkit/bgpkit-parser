use ipnet::AddrParseError;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
#[non_exhaustive]
pub enum BgpModelsError {
    PrefixParsingError(String),
    NextHopParsingError(String),
}

impl Display for BgpModelsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BgpModelsError::PrefixParsingError(msg) => {
                write!(f, "cannot convert str to IP prefix: {msg}")
            }
            BgpModelsError::NextHopParsingError(msg) => {
                write!(f, "cannot convert str to next hop: {msg}")
            }
        }
    }
}

impl Error for BgpModelsError {}

impl From<AddrParseError> for BgpModelsError {
    fn from(err: AddrParseError) -> Self {
        BgpModelsError::PrefixParsingError(err.to_string())
    }
}
