/*!
error module defines the error types used in bgpkit-parser.
*/
use crate::models::{Afi, AttrType, Bgp4MpType, BgpState, EntryType, Safi, TableDumpV2Type};
use num_enum::TryFromPrimitiveError;
#[cfg(feature = "oneio")]
use oneio::OneIoError;
use std::fmt::{Display, Formatter};
use std::io::ErrorKind;
use std::{error::Error, fmt, io};

#[derive(Debug)]
pub enum ParserError {
    IoError(io::Error),
    EofError(io::Error),
    #[cfg(feature = "oneio")]
    OneIoError(OneIoError),
    EofExpected,
    ParseError(String),
    TruncatedMsg(String),
    Unsupported(String),
    FilterError(String),
    /// NLRI length field is inconsistent with content
    /// (total_bits < minimum required, or underflow in prefix calculation)
    InvalidLabeledNlriLength,
    /// Input ended before completing NLRI structure
    TruncatedLabeledNlri,
    /// Input ended in the middle of prefix data
    TruncatedPrefix,
    /// Exceeded configured max_labels without finding Bottom-of-Stack bit
    MaxLabelStackDepthExceeded,
    /// Exceeded peer-advertised max labels (Multiple Labels Capability)
    /// Per RFC 8277 §2.1, this should be treated as a withdrawal
    PeerMaxLabelsExceeded,
    /// Invalid prefix in NLRI
    InvalidPrefix,
}

impl Error for ParserError {}

/// Errors that can occur during encoding of BGP/MRT messages to wire format.
///
/// These arise when in-memory data structures contain values that are too large
/// for their wire-format length fields (e.g. an AS_PATH segment with more than
/// 255 ASes, or an attribute value exceeding 65535 bytes), or values that cannot
/// be represented on the wire at all. All such conditions were previously
/// handled by panicking or silently truncating — see issue #313.
#[derive(Debug)]
#[non_exhaustive]
pub enum EncodingError {
    /// A value exceeded the maximum size that fits in its wire-format length
    /// field.
    ///
    /// `field` names the wire field (e.g. `"AS_PATH segment count"`,
    /// `"attribute value length"`, `"BGP message total length"`). `actual` is
    /// the byte/element count that overflowed; `max` is the field's capacity.
    ValueTooLarge {
        field: &'static str,
        actual: usize,
        max: usize,
    },
    /// The value cannot be represented in wire format at all — e.g. ATTR_SET
    /// encoding not implemented, a labeled NLRI with an empty label stack, or
    /// an OPEN optional parameter of type 255 in non-extended framing.
    Unencodable { field: &'static str, reason: String },
}

impl EncodingError {
    /// Construct a [`ValueTooLarge`](EncodingError::ValueTooLarge) error.
    pub(crate) fn too_large(field: &'static str, actual: usize, max: usize) -> Self {
        EncodingError::ValueTooLarge { field, actual, max }
    }

    /// Construct an [`Unencodable`](EncodingError::Unencodable) error.
    pub(crate) fn unencodable(field: &'static str, reason: impl Into<String>) -> Self {
        EncodingError::Unencodable {
            field,
            reason: reason.into(),
        }
    }
}

impl Display for EncodingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            EncodingError::ValueTooLarge { field, actual, max } => {
                write!(
                    f,
                    "encoding error: {field} ({actual}) exceeds maximum ({max})"
                )
            }
            EncodingError::Unencodable { field, reason } => {
                write!(f, "encoding error: {field}: {reason}")
            }
        }
    }
}

impl Error for EncodingError {}

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
            ParserError::IoError(e) => write!(f, "Error: {e}"),
            ParserError::EofError(e) => write!(f, "Error: {e}"),
            ParserError::ParseError(s) => write!(f, "Error: {s}"),
            ParserError::TruncatedMsg(s) => write!(f, "Error: {s}"),
            ParserError::Unsupported(s) => write!(f, "Error: {s}"),
            ParserError::EofExpected => write!(f, "Error: reach end of file"),
            #[cfg(feature = "oneio")]
            ParserError::OneIoError(e) => write!(f, "Error: {e}"),
            ParserError::FilterError(e) => write!(f, "Error: {e}"),
            ParserError::InvalidLabeledNlriLength => {
                write!(f, "Error: invalid labeled NLRI length field")
            }
            ParserError::TruncatedLabeledNlri => write!(f, "Error: truncated labeled NLRI"),
            ParserError::TruncatedPrefix => write!(f, "Error: truncated prefix in NLRI"),
            ParserError::MaxLabelStackDepthExceeded => write!(
                f,
                "Error: max label stack depth exceeded without finding BoS bit"
            ),
            ParserError::PeerMaxLabelsExceeded => write!(
                f,
                "Error: received more labels than peer advertised maximum"
            ),
            ParserError::InvalidPrefix => write!(f, "Error: invalid prefix in NLRI"),
        }
    }
}

#[cfg(feature = "oneio")]
impl From<OneIoError> for ParserErrorWithBytes {
    fn from(error: OneIoError) -> Self {
        ParserErrorWithBytes {
            error: ParserError::OneIoError(error),
            bytes: None,
        }
    }
}

#[cfg(feature = "oneio")]
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

/// BGP validation warnings for RFC 7606 compliant error handling.
/// These represent non-fatal validation issues that don't prevent parsing.
///
/// This enum is `#[non_exhaustive]` so that new warning variants can be added
/// in minor releases without breaking exhaustive matches.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BgpValidationWarning {
    /// Attribute flags conflict with attribute type code (RFC 4271 Section 6.3)
    AttributeFlagsError {
        attr_type: AttrType,
        expected_flags: u8,
        actual_flags: u8,
    },
    /// Attribute length conflicts with expected length (RFC 4271 Section 6.3)
    AttributeLengthError {
        attr_type: AttrType,
        expected_length: Option<usize>,
        actual_length: usize,
    },
    /// Missing well-known mandatory attribute (RFC 4271 Section 6.3)
    MissingWellKnownAttribute { attr_type: AttrType },
    /// Unrecognized well-known attribute (RFC 4271 Section 6.3)
    UnrecognizedWellKnownAttribute { attr_type_code: u8 },
    /// Invalid origin attribute value (RFC 4271 Section 6.3)
    InvalidOriginAttribute { value: u8 },
    /// Invalid next hop attribute (RFC 4271 Section 6.3)
    InvalidNextHopAttribute { reason: String },
    /// Malformed AS_PATH attribute (RFC 4271 Section 6.3)
    MalformedAsPath { reason: String },
    /// Optional attribute error (RFC 4271 Section 6.3)
    OptionalAttributeError { attr_type: AttrType, reason: String },
    /// Attribute appears more than once (RFC 4271 Section 6.3)
    DuplicateAttribute { attr_type: AttrType },
    /// Invalid network field in NLRI (RFC 4271 Section 6.3)
    InvalidNetworkField { reason: String },
    /// Malformed attribute list (RFC 4271 Section 6.3)
    MalformedAttributeList { reason: String },
    /// Partial attribute with errors (RFC 7606)
    PartialAttributeError { attr_type: AttrType, reason: String },
    /// Malformed NLRI field (RFC 7606 §5.3). The UPDATE message was parseable
    /// up to the NLRI section, but the NLRI itself contained syntactic errors.
    /// Per RFC 7606, the recommended action is "treat-as-withdrawal": all
    /// routes carried in the NLRI section should be withdrawn.
    ///
    /// `nlri_type` distinguishes between the standard (IPv4 unicast) NLRI
    /// field and the multiprotocol NLRI carried inside MP_REACH/MP_UNREACH
    /// path attributes. `raw_bytes` preserves the offending NLRI bytes so
    /// callers can inspect or export them without re-encoding.
    MalformedNlri {
        /// "withdrawn", "announced", "mp_reach", or "mp_unreach"
        nlri_type: &'static str,
        /// Human-readable description of the parse error
        reason: String,
        /// Raw NLRI bytes as they appeared in the UPDATE message
        raw_bytes: Vec<u8>,
    },
}

impl Display for BgpValidationWarning {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            BgpValidationWarning::AttributeFlagsError { attr_type, expected_flags, actual_flags } => {
                write!(f, "Attribute flags error for {attr_type:?}: expected 0x{expected_flags:02x}, got 0x{actual_flags:02x}")
            }
            BgpValidationWarning::AttributeLengthError { attr_type, expected_length, actual_length } => {
                match expected_length {
                    Some(expected) => write!(f, "Attribute length error for {attr_type:?}: expected {expected}, got {actual_length}"),
                    None => write!(f, "Attribute length error for {attr_type:?}: invalid length {actual_length}"),
                }
            }
            BgpValidationWarning::MissingWellKnownAttribute { attr_type } => {
                write!(f, "Missing well-known mandatory attribute: {attr_type:?}")
            }
            BgpValidationWarning::UnrecognizedWellKnownAttribute { attr_type_code } => {
                write!(f, "Unrecognized well-known attribute: type code {attr_type_code}")
            }
            BgpValidationWarning::InvalidOriginAttribute { value } => {
                write!(f, "Invalid origin attribute value: {value}")
            }
            BgpValidationWarning::InvalidNextHopAttribute { reason } => {
                write!(f, "Invalid next hop attribute: {reason}")
            }
            BgpValidationWarning::MalformedAsPath { reason } => {
                write!(f, "Malformed AS_PATH: {reason}")
            }
            BgpValidationWarning::OptionalAttributeError { attr_type, reason } => {
                write!(f, "Optional attribute error for {attr_type:?}: {reason}")
            }
            BgpValidationWarning::DuplicateAttribute { attr_type } => {
                write!(f, "Duplicate attribute: {attr_type:?}")
            }
            BgpValidationWarning::InvalidNetworkField { reason } => {
                write!(f, "Invalid network field: {reason}")
            }
            BgpValidationWarning::MalformedAttributeList { reason } => {
                write!(f, "Malformed attribute list: {reason}")
            }
            BgpValidationWarning::PartialAttributeError { attr_type, reason } => {
                write!(f, "Partial attribute error for {attr_type:?}: {reason}")
            }
            BgpValidationWarning::MalformedNlri { nlri_type, reason, .. } => {
                write!(f, "Malformed NLRI ({nlri_type}): {reason}")
            }
        }
    }
}

/// Result type for BGP attribute parsing that includes validation warnings
#[derive(Debug, Clone)]
pub struct BgpValidationResult<T> {
    pub value: T,
    pub warnings: Vec<BgpValidationWarning>,
}

impl<T> BgpValidationResult<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            warnings: Vec::new(),
        }
    }

    pub fn with_warnings(value: T, warnings: Vec<BgpValidationWarning>) -> Self {
        Self { value, warnings }
    }

    pub fn add_warning(&mut self, warning: BgpValidationWarning) {
        self.warnings.push(warning);
    }

    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}
