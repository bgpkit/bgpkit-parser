use std::convert;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum ParserRisliveError {
    IncorrectJson(String),
    IncorrectRawBytes,
    IrregularRisLiveFormat,
    UnsupportedMessage,
    ElemEndOfRibPrefix,
    ElemUnknownOriginType(String),
    ElemIncorrectAggregator(String),
    ElemIncorrectPrefix(String),
    ElemIncorrectIp(String),
}

impl Display for ParserRisliveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ParserRisliveError::IncorrectJson(msg) => {write!(f, "incorrect json message: {}", msg)}
            ParserRisliveError::IncorrectRawBytes => {write!(f, "incorrect raw bytes")}
            ParserRisliveError::UnsupportedMessage => {write!(f, "unsupported message")}
            ParserRisliveError::IrregularRisLiveFormat => {write!(f, "irregular ris live format")}
            ParserRisliveError::ElemIncorrectPrefix(msg) => {
                write!(f, "incorrect prefix string: {}", msg)
            }
            ParserRisliveError::ElemUnknownOriginType(msg) => {
                write!(f, "unknown origin type: {}", msg)
            }
            ParserRisliveError::ElemIncorrectAggregator(msg) => {
                write!(f, "incorrect aggregator string: {}", msg)
            }
            ParserRisliveError::ElemIncorrectIp(msg) => {
                write!(f, "incorrect IP string: {}", msg)
            }
            ParserRisliveError::ElemEndOfRibPrefix => {
                write!(f, "found 'eor' (End of RIB) prefix")
            }
        }
    }
}

impl convert::From<serde_json::Error> for ParserRisliveError {
    fn from(_: serde_json::Error) -> Self {
        ParserRisliveError::IncorrectJson("serde_json error".to_string())
    }
}

impl Error for ParserRisliveError{}

