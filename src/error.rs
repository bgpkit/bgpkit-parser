/*!
error module defines the error types used in bgpkit-parser.
*/
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use std::fmt::{Display, Formatter};
use std::{error::Error, fmt, io};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParserError {
    // Finished error variants
    #[error("unrecognized value {value} for {type_name}")]
    UnrecognizedEnumVariant { type_name: &'static str, value: u64 },

    // TODO: Investigate usages of remaining error variants:
    #[error("todo")]
    IoError(#[from] io::Error),
    #[error("todo")]
    IoNotEnoughBytes(),
    #[error("todo")]
    EofError(io::Error),
    #[error("todo")]
    EofExpected,
    #[error("todo")]
    ParseError(String),
    #[error("todo")]
    TruncatedMsg(String),
    #[error("todo")]
    Unsupported(String),
}

impl<T> From<TryFromPrimitiveError<T>> for ParserError
where
    T: TryFromPrimitive,
    T::Primitive: Into<u64>,
{
    #[inline]
    fn from(value: TryFromPrimitiveError<T>) -> Self {
        ParserError::UnrecognizedEnumVariant {
            type_name: T::NAME,
            value: value.number.into(),
        }
    }
}

#[derive(Debug)]
pub struct ParserErrorWithBytes {
    pub error: ParserError,
    pub bytes: Option<Vec<u8>>,
}

impl Display for ParserErrorWithBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl Error for ParserErrorWithBytes {}

impl From<ParserError> for ParserErrorWithBytes {
    fn from(error: ParserError) -> Self {
        ParserErrorWithBytes { error, bytes: None }
    }
}
