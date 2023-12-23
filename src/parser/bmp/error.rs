use crate::bmp::messages::headers::PeerType;
use crate::bmp::messages::initiation_message::InitiationTlvType;
use crate::bmp::messages::route_mirroring::RouteMirroringInfo;
use crate::bmp::messages::termination_message::TerminationTlvType;
use crate::bmp::messages::BmpMsgType;
use crate::ParserError;
use num_enum::TryFromPrimitiveError;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Clone, Copy, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_error_display() {
        assert_eq!(
            ParserBmpError::InvalidOpenBmpHeader.to_string(),
            "Invalid OpenBMP header"
        );
        assert_eq!(
            ParserBmpError::UnsupportedOpenBmpMessage.to_string(),
            "Unsupported OpenBMP message"
        );
        assert_eq!(
            ParserBmpError::CorruptedBmpMessage.to_string(),
            "Corrupted BMP message"
        );
        assert_eq!(
            ParserBmpError::TruncatedBmpMessage.to_string(),
            "Truncated BMP message"
        );
    }

    #[test]
    fn test_error_conversions() {
        assert_eq!(
            ParserBmpError::from(std::io::Error::new(std::io::ErrorKind::Other, "test")),
            ParserBmpError::InvalidOpenBmpHeader
        );
        assert_eq!(
            ParserBmpError::from(ParserError::ParseError("test".to_string())),
            ParserBmpError::CorruptedBmpMessage
        );
        assert_eq!(
            ParserBmpError::from(TryFromPrimitiveError::<BmpMsgType>::new(0)),
            ParserBmpError::InvalidOpenBmpHeader
        );
        assert_eq!(
            ParserBmpError::from(TryFromPrimitiveError::<PeerType>::new(0)),
            ParserBmpError::InvalidOpenBmpHeader
        );
        assert_eq!(
            ParserBmpError::from(TryFromPrimitiveError::<InitiationTlvType>::new(0)),
            ParserBmpError::CorruptedBmpMessage
        );
        assert_eq!(
            ParserBmpError::from(TryFromPrimitiveError::<RouteMirroringInfo>::new(0)),
            ParserBmpError::CorruptedBmpMessage
        );
        assert_eq!(
            ParserBmpError::from(TryFromPrimitiveError::<TerminationTlvType>::new(0)),
            ParserBmpError::CorruptedBmpMessage
        );
    }
}
