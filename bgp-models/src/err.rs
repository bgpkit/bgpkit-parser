use std::error::Error;
use std::fmt::{Display, Formatter};
use ipnetwork::IpNetworkError;

#[derive(Debug)]
pub enum BgpModelsError {
    PrefixParsingError(String),
}

impl Display for BgpModelsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self{
            BgpModelsError::PrefixParsingError(msg) => {
                write!(f, "cannot convert str to IP prefix: {}", msg)
            }
        }
    }
}

impl Error for BgpModelsError{}

impl From<IpNetworkError> for BgpModelsError {
    fn from(err: IpNetworkError) -> Self {
        BgpModelsError::PrefixParsingError(err.to_string())
    }
}