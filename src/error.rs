use std::{convert, error::Error, fmt, io};
use std::io::ErrorKind;

#[derive(Debug)]
pub enum ParserError {
    IoError(io::Error, Option<Vec<u8>>),
    EofError(io::Error, Option<Vec<u8>>),
    RemoteIoError(reqwest::Error),
    EofExpected,
    ParseError(String),
    UnknownAttr(String),
    TruncatedMsg(String),
    Deprecated(String),
    Unsupported(String),
}

impl Error for ParserError {}

/// implement Display trait for Error which satistifies the std::error::Error
/// trait's requirement (must implement Display and Debug traits, Debug already derived)
impl fmt::Display for ParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            ParserError::IoError(e, _bytes) => e.to_string(),
            ParserError::EofError(e, _) => e.to_string(),
            ParserError::ParseError(s) => s.to_owned(),
            ParserError::TruncatedMsg(s) => s.to_owned(),
            ParserError::Deprecated(s) => s.to_owned(),
            ParserError::UnknownAttr(s) => s.to_owned(),
            ParserError::Unsupported(s) => s.to_owned(),
            ParserError::EofExpected => "reach end of file".to_string(),
            ParserError::RemoteIoError(e) => e.to_string()
        };
        write!(f, "Error: {}", message)
    }
}

impl convert::From<reqwest::Error> for ParserError {
    fn from(error: reqwest::Error) -> Self {
        ParserError::RemoteIoError(error)
    }
}

impl convert::From<io::Error> for ParserError {
    fn from(io_error: io::Error) -> Self {
        match io_error.kind() {
            ErrorKind::UnexpectedEof => {ParserError::EofError(io_error, None)}
            _ => ParserError::IoError(io_error, None)
        }
    }
}
