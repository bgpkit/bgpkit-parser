/*!
error module defines the error types used in bgpkit-parser.
*/
use crate::models::{AttrType, EntryType};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParserError {
    /// This error represents a [num_enum::TryFromPrimitiveError] error for any of a number of
    /// different types.
    ///
    /// ## Occurs during:
    ///  - Parsing of an MRT message body
    #[error("unrecognized value {value} for {type_name}")]
    UnrecognizedEnumVariant { type_name: &'static str, value: u64 },
    /// Indicates that the MRT message header type could not be determined while parsing a MRT
    /// header.
    ///
    /// ## Occurs during:
    ///  - Parsing of an MRT message header
    #[error("unrecognized type {0} in MRT header")]
    UnrecognizedMrtType(u16),
    /// This error represents a [ipnet::PrefixLenError] error. It occurs if an address mask is
    /// larger than the length of the address it is being applied to.
    ///
    /// ## Occurs during:
    ///  - Reading network prefixes (parsing of an MRT message body)
    #[error("invalid network prefix mask")]
    InvalidPrefixLength(#[from] ipnet::PrefixLenError),
    /// A general IO error triggered by the internal reader.
    ///
    /// ## Occurs during:
    ///  - Reading of an MRT record header
    ///  - Buffering of an MRT record body before parsing
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("unable to parse unsupported MRT type {mrt_type:?} subtype {subtype}")]
    UnsupportedMrtType { mrt_type: EntryType, subtype: u16 },
    #[error("unable to parse unsupported attribute type {0:?}")]
    UnsupportedAttributeType(AttrType),
    /// Indicates internal length inconsistencies within an MRT message. This includes fixed-length
    /// and length-prefixed data requiring more space than is available within the enclosing
    /// container.
    ///
    /// This error is not caused by IO errors such as an unexpected EOF error.
    #[error(
        "encountered truncated value during {name}; expected {expected} bytes, but got {remaining}"
    )]
    TruncatedField {
        name: &'static str,
        expected: usize,
        remaining: usize,
    },

    // TODO: Investigate usages of remaining error variants:
    #[error("todo")]
    ParseError(String),
}

impl<T> From<TryFromPrimitiveError<T>> for ParserError
where
    T: TryFromPrimitive,
    T::Primitive: Into<u64>,
{
    #[inline]
    fn from(value: TryFromPrimitiveError<T>) -> Self {
        ParserError::UnrecognizedEnumVariant {
            type_name: T::NAME,
            value: value.number.into(),
        }
    }
}
