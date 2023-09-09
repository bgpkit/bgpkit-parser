use crate::ParserError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParserRisliveError {
    #[error(transparent)]
    IncorrectJson(#[from] serde_json::Error),
    #[error("unable to parse aggregator attribute {0:?}")]
    UnableToParseAggregator(String),
    #[error("unable to parse raw bytes: {0}")]
    UnableToParseRawBytes(ParserError),
    #[error("unknown message type: {0:?}")]
    UnknownMessageType(Option<String>),
    #[error("unsupported message type: {0}")]
    UnsupportedMessage(String),
    #[error("found 'eor' (End of RIB) prefix")]
    ElemEndOfRibPrefix,
    #[error("unknown origin type: {0}")]
    UnknownOriginType(String),
    #[error("unable to parse prefix: {0:?}")]
    UnableToParsePrefix(String),
}
