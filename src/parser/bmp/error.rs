use crate::bmp::messages::headers::BmpPeerType;
use crate::bmp::messages::peer_down_notification::PeerDownReason;
use crate::bmp::messages::route_mirroring::RouteMirroringInfo;
use crate::bmp::messages::termination_message::{TerminationReason, TerminationTlvType};
use crate::bmp::messages::BmpMsgType;
use crate::ParserError;
use num_enum::TryFromPrimitiveError;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Clone, Eq)]
#[non_exhaustive]
pub enum ParserBmpError {
    InvalidOpenBmpHeader,
    UnsupportedOpenBmpMessage,
    UnknownTlvType,
    UnknownTlvValue,
    CorruptedBmpMessage,
    CorruptedBgpMessage(String),
    TruncatedBmpMessage,
    /// Reading BMP framing or a message body failed. Carries the `ErrorKind` and the
    /// source message; the `io::Error` itself cannot be stored because this enum is
    /// `Clone` and `Eq`, which `io::Error` is not.
    IoError {
        kind: std::io::ErrorKind,
        message: String,
    },
    /// A message type value this crate does not know; carries the raw value.
    UnknownMessageType(u8),
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
            ParserBmpError::UnknownTlvType => {
                write!(f, "Unknown TLV type")
            }
            ParserBmpError::UnknownTlvValue => {
                write!(f, "Unknown TLV value")
            }
            ParserBmpError::CorruptedBgpMessage(s) => {
                write!(f, "Corrupted BGP message: {}", s)
            }
            ParserBmpError::IoError { kind, message } => {
                write!(f, "BMP read error ({:?}): {}", kind, message)
            }
            ParserBmpError::UnknownMessageType(value) => {
                write!(f, "Unknown BMP message type: {}", value)
            }
        }
    }
}

impl Error for ParserBmpError {}

impl From<std::io::Error> for ParserBmpError {
    fn from(e: std::io::Error) -> Self {
        ParserBmpError::IoError {
            kind: e.kind(),
            message: e.to_string(),
        }
    }
}

impl From<ParserError> for ParserBmpError {
    fn from(e: ParserError) -> Self {
        ParserBmpError::CorruptedBgpMessage(e.to_string())
    }
}

impl From<TryFromPrimitiveError<BmpMsgType>> for ParserBmpError {
    fn from(e: TryFromPrimitiveError<BmpMsgType>) -> Self {
        ParserBmpError::UnknownMessageType(e.number)
    }
}

impl From<TryFromPrimitiveError<BmpPeerType>> for ParserBmpError {
    fn from(_: TryFromPrimitiveError<BmpPeerType>) -> Self {
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
        ParserBmpError::UnknownTlvType
    }
}

impl From<TryFromPrimitiveError<TerminationReason>> for ParserBmpError {
    fn from(_: TryFromPrimitiveError<TerminationReason>) -> Self {
        ParserBmpError::UnknownTlvValue
    }
}

impl From<TryFromPrimitiveError<PeerDownReason>> for ParserBmpError {
    fn from(_: TryFromPrimitiveError<PeerDownReason>) -> Self {
        ParserBmpError::UnknownTlvValue
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
            ParserBmpError::CorruptedBgpMessage("test".to_string()).to_string(),
            "Corrupted BGP message: test"
        );
        assert_eq!(
            ParserBmpError::TruncatedBmpMessage.to_string(),
            "Truncated BMP message"
        );
        assert_eq!(
            ParserBmpError::UnknownTlvType.to_string(),
            "Unknown TLV type"
        );
        assert_eq!(
            ParserBmpError::UnknownTlvValue.to_string(),
            "Unknown TLV value"
        );
        assert_eq!(
            ParserBmpError::IoError {
                kind: std::io::ErrorKind::UnexpectedEof,
                message: "unexpected eof".to_string(),
            }
            .to_string(),
            "BMP read error (UnexpectedEof): unexpected eof"
        );
        assert_eq!(
            ParserBmpError::UnknownMessageType(7).to_string(),
            "Unknown BMP message type: 7"
        );
    }

    #[test]
    fn test_error_conversions() {
        assert_eq!(
            ParserBmpError::from(std::io::Error::other("test")),
            ParserBmpError::IoError {
                kind: std::io::ErrorKind::Other,
                message: "test".to_string(),
            }
        );
        assert_eq!(
            ParserBmpError::from(ParserError::ParseError("test".to_string())),
            ParserBmpError::CorruptedBgpMessage("Error: test".to_string())
        );
        assert_eq!(
            ParserBmpError::from(TryFromPrimitiveError::<BmpMsgType>::new(0)),
            ParserBmpError::UnknownMessageType(0)
        );
        assert_eq!(
            ParserBmpError::from(TryFromPrimitiveError::<BmpPeerType>::new(0)),
            ParserBmpError::CorruptedBmpMessage
        );
        assert_eq!(
            ParserBmpError::from(TryFromPrimitiveError::<RouteMirroringInfo>::new(0)),
            ParserBmpError::CorruptedBmpMessage
        );
        assert_eq!(
            ParserBmpError::from(TryFromPrimitiveError::<TerminationTlvType>::new(0)),
            ParserBmpError::UnknownTlvType
        );
        assert_eq!(
            ParserBmpError::from(TryFromPrimitiveError::<TerminationReason>::new(0)),
            ParserBmpError::UnknownTlvValue
        );
        assert_eq!(
            ParserBmpError::from(TryFromPrimitiveError::<PeerDownReason>::new(0)),
            ParserBmpError::UnknownTlvValue
        );
    }
}
