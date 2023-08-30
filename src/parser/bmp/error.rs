use crate::bmp::messages::headers::PeerType;
use crate::bmp::messages::initiation_message::InitiationTlvType;
use crate::bmp::messages::route_mirroring::RouteMirroringInfo;
use crate::bmp::messages::termination_message::TerminationTlvType;
use crate::bmp::messages::BmpMsgType;
use crate::ParserError;
use num_enum::TryFromPrimitiveError;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum ParserBmpError {
    InvalidOpenBmpHeader,
    UnsupportedOpenBmpMessage,
    CorruptedBmpMessage,
    TruncatedBmpMessage,
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

impl Error for ParserBmpError {}

// TODO: These conversions make the error difficult to debug as they drop all of the error context
impl From<std::io::Error> for ParserBmpError {
    fn from(_: std::io::Error) -> Self {
        ParserBmpError::InvalidOpenBmpHeader
    }
}

impl From<ParserError> for ParserBmpError {
    fn from(_: ParserError) -> Self {
        ParserBmpError::CorruptedBmpMessage
    }
}

impl From<TryFromPrimitiveError<BmpMsgType>> for ParserBmpError {
    fn from(_: TryFromPrimitiveError<BmpMsgType>) -> Self {
        // TODO: Should this get its own error variant?
        ParserBmpError::InvalidOpenBmpHeader
    }
}

impl From<TryFromPrimitiveError<PeerType>> for ParserBmpError {
    fn from(_: TryFromPrimitiveError<PeerType>) -> Self {
        ParserBmpError::InvalidOpenBmpHeader
    }
}

impl From<TryFromPrimitiveError<InitiationTlvType>> for ParserBmpError {
    fn from(_: TryFromPrimitiveError<InitiationTlvType>) -> Self {
        ParserBmpError::CorruptedBmpMessage
    }
}

impl From<TryFromPrimitiveError<RouteMirroringInfo>> for ParserBmpError {
    fn from(_: TryFromPrimitiveError<RouteMirroringInfo>) -> Self {
        ParserBmpError::CorruptedBmpMessage
    }
}

impl From<TryFromPrimitiveError<TerminationTlvType>> for ParserBmpError {
    fn from(_: TryFromPrimitiveError<TerminationTlvType>) -> Self {
        ParserBmpError::CorruptedBmpMessage
    }
}
