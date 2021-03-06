use std::error::Error;
use std::fmt::{Display, Formatter};
use crate::ParserErrorKind;

#[derive(Debug)]
pub enum ParserBmpError {
    InvalidOpenBmpHeader,
    UnsupportedOpenBmpMessage,
    CorruptedBmpMessage,
    TruncatedBmpMessage
}

impl Display for ParserBmpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ParserBmpError::InvalidOpenBmpHeader => {
                write!(f, "Invalid OpenBMP header")
            }
            ParserBmpError::UnsupportedOpenBmpMessage => {
                write!(f, "Unsupported OpenBMP message")
            }
            ParserBmpError::CorruptedBmpMessage => {
                write!(f, "Corrupted BMP message")
            }
            ParserBmpError::TruncatedBmpMessage => {
                write!(f, "Truncated BMP message")
            }
        }
    }
}

impl Error for ParserBmpError{}

impl std::convert::From<std::io::Error> for ParserBmpError {
    fn from(_: std::io::Error) -> Self {
        ParserBmpError::InvalidOpenBmpHeader
    }
}

impl std::convert::From<ParserErrorKind> for ParserBmpError {
    fn from(_: ParserErrorKind) -> Self {
        ParserBmpError::CorruptedBmpMessage
    }
}
