use crate::ParserError;
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParserBmpError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    ParseError(#[from] ParserError),
    #[error("invalid OpenBMP header")]
    InvalidOpenBmpHeader,
    #[error("invalid stats data length {0}")]
    InvalidStatsDataLength(u16),
    #[error("unsupported OpenBMP message")]
    UnsupportedOpenBmpMessage,
}

impl<T> From<TryFromPrimitiveError<T>> for ParserBmpError
where
    T: TryFromPrimitive,
    ParserError: From<TryFromPrimitiveError<T>>,
{
    fn from(value: TryFromPrimitiveError<T>) -> Self {
        ParserBmpError::ParseError(ParserError::from(value))
    }
}
