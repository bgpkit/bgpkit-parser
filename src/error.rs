/*!
error module defines the error types used in bgpkit-parser.
*/
use crate::models::{Afi, Bgp4MpType, BgpState, EntryType, Safi, TableDumpV2Type};
use num_enum::TryFromPrimitiveError;
use oneio::OneIoError;
use std::fmt::{Display, Formatter};
use std::io::ErrorKind;
use std::{error::Error, fmt, io};

#[derive(Debug)]
pub enum ParserError {
    IoError(io::Error),
    IoNotEnoughBytes(),
    EofError(io::Error),
    OneIoError(OneIoError),
    EofExpected,
    ParseError(String),
    TruncatedMsg(String),
    Unsupported(String),
    FilterError(String),
}

impl Error for ParserError {}

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

/// implement Display trait for Error which satistifies the std::error::Error
/// trait's requirement (must implement Display and Debug traits, Debug already derived)
impl Display for ParserError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ParserError::IoError(e) => write!(f, "Error: {}", e),
            ParserError::EofError(e) => write!(f, "Error: {}", e),
            ParserError::ParseError(s) => write!(f, "Error: {}", s),
            ParserError::TruncatedMsg(s) => write!(f, "Error: {}", s),
            ParserError::Unsupported(s) => write!(f, "Error: {}", s),
            ParserError::EofExpected => write!(f, "Error: reach end of file"),
            ParserError::OneIoError(e) => write!(f, "Error: {}", e),
            ParserError::FilterError(e) => write!(f, "Error: {}", e),
            ParserError::IoNotEnoughBytes() => write!(f, "Error: Not enough bytes to read"),
        }
    }
}

impl From<OneIoError> for ParserErrorWithBytes {
    fn from(error: OneIoError) -> Self {
        ParserErrorWithBytes {
            error: ParserError::OneIoError(error),
            bytes: None,
        }
    }
}

impl From<OneIoError> for ParserError {
    fn from(error: OneIoError) -> Self {
        ParserError::OneIoError(error)
    }
}

impl From<ParserError> for ParserErrorWithBytes {
    fn from(error: ParserError) -> Self {
        ParserErrorWithBytes { error, bytes: None }
    }
}

impl From<io::Error> for ParserError {
    fn from(io_error: io::Error) -> Self {
        match io_error.kind() {
            ErrorKind::UnexpectedEof => ParserError::EofError(io_error),
            _ => ParserError::IoError(io_error),
        }
    }
}

impl From<TryFromPrimitiveError<Bgp4MpType>> for ParserError {
    fn from(value: TryFromPrimitiveError<Bgp4MpType>) -> Self {
        ParserError::ParseError(format!("cannot parse bgp4mp subtype: {}", value.number))
    }
}

impl From<TryFromPrimitiveError<BgpState>> for ParserError {
    fn from(value: TryFromPrimitiveError<BgpState>) -> Self {
        ParserError::ParseError(format!("cannot parse bgp4mp state: {}", value.number))
    }
}

impl From<TryFromPrimitiveError<TableDumpV2Type>> for ParserError {
    fn from(value: TryFromPrimitiveError<TableDumpV2Type>) -> Self {
        ParserError::ParseError(format!("cannot parse table dump v2 type: {}", value.number))
    }
}

impl From<TryFromPrimitiveError<EntryType>> for ParserError {
    fn from(value: TryFromPrimitiveError<EntryType>) -> Self {
        ParserError::ParseError(format!("cannot parse entry type: {}", value.number))
    }
}

impl From<TryFromPrimitiveError<Afi>> for ParserError {
    fn from(value: TryFromPrimitiveError<Afi>) -> Self {
        ParserError::ParseError(format!("Unknown AFI type: {}", value.number))
    }
}

impl From<TryFromPrimitiveError<Safi>> for ParserError {
    fn from(value: TryFromPrimitiveError<Safi>) -> Self {
        ParserError::ParseError(format!("Unknown SAFI type: {}", value.number))
    }
}
