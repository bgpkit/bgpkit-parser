use std::convert;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum ParserRisliveError {
    IncorrectJson,
    IncorrectRawBytes,
    IrregularRisLiveFormat,
    UnsupportedMessage,
}

impl Display for ParserRisliveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ParserRisliveError::IncorrectJson => {write!(f, "incorrect json message")}
            ParserRisliveError::IncorrectRawBytes => {write!(f, "incorrect raw bytes")}
            ParserRisliveError::UnsupportedMessage => {write!(f, "unsupported message")}
            ParserRisliveError::IrregularRisLiveFormat => {write!(f, "irregular ris live format")}
        }
    }
}

impl convert::From<serde_json::Error> for ParserRisliveError {
    fn from(_: serde_json::Error) -> Self {
        ParserRisliveError::IncorrectJson
    }
}

impl Error for ParserRisliveError{}

