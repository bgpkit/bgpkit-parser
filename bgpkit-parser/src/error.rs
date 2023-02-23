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
    UnknownAttr(String),
    DeprecatedAttr(String),
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
impl fmt::Display for ParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            ParserError::IoError(e) => e.to_string(),
            ParserError::EofError(e) => e.to_string(),
            ParserError::ParseError(s) => s.to_owned(),
            ParserError::TruncatedMsg(s) => s.to_owned(),
            ParserError::DeprecatedAttr(s) => s.to_owned(),
            ParserError::UnknownAttr(s) => s.to_owned(),
            ParserError::Unsupported(s) => s.to_owned(),
            ParserError::EofExpected => "reach end of file".to_string(),
            ParserError::OneIoError(e) => e.to_string(),
            ParserError::FilterError(e) => e.to_owned(),
            ParserError::IoNotEnoughBytes() => "Not enough bytes to read".to_string(),
        };
        write!(f, "Error: {}", message)
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
