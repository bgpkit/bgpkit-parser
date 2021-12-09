use std::{convert, error::Error, fmt, io};
use std::fmt::{Display, Formatter};
use std::io::ErrorKind;

#[derive(Debug)]
pub enum ParserErrorKind {
    IoError(io::Error),
    EofError(io::Error),
    RemoteIoError(String),
    EofExpected,
    ParseError(String),
    UnknownAttr(String),
    TruncatedMsg(String),
    Deprecated(String),
    Unsupported(String),
    FilterError(String),
}

impl Error for ParserErrorKind {}

#[derive(Debug)]
pub struct ParserError {
    pub error: ParserErrorKind,
    pub bytes: Option<Vec<u8>>,
}

impl Display for ParserError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error.to_string())
    }
}

impl Error for ParserError {}

/// implement Display trait for Error which satistifies the std::error::Error
/// trait's requirement (must implement Display and Debug traits, Debug already derived)
impl fmt::Display for ParserErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            ParserErrorKind::IoError(e) => e.to_string(),
            ParserErrorKind::EofError(e) => e.to_string(),
            ParserErrorKind::ParseError(s) => s.to_owned(),
            ParserErrorKind::TruncatedMsg(s) => s.to_owned(),
            ParserErrorKind::Deprecated(s) => s.to_owned(),
            ParserErrorKind::UnknownAttr(s) => s.to_owned(),
            ParserErrorKind::Unsupported(s) => s.to_owned(),
            ParserErrorKind::EofExpected => "reach end of file".to_string(),
            ParserErrorKind::RemoteIoError(e) => e.to_string(),
            ParserErrorKind::FilterError(e) => e.to_owned(),
        };
        write!(f, "Error: {}", message)
    }
}

impl convert::From<reqwest::Error> for ParserErrorKind {
    fn from(error: reqwest::Error) -> Self {
        ParserErrorKind::RemoteIoError(error.to_string())
    }
}

impl convert::From<ParserErrorKind> for ParserError {
    fn from(error: ParserErrorKind) -> Self {
        ParserError{error, bytes: None}
    }
}

impl convert::From<io::Error> for ParserErrorKind {
    fn from(io_error: io::Error) -> Self {
        match io_error.kind() {
            ErrorKind::UnexpectedEof => { ParserErrorKind::EofError(io_error)}
            _ => ParserErrorKind::IoError(io_error)
        }
    }
}
