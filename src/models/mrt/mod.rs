//! MRT message and relevant structs.

pub mod bgp4mp;
pub mod tabledump;

pub use bgp4mp::*;
use std::io;
use std::io::Write;
pub use tabledump::*;

/// MrtRecord is a wrapper struct that contains a header and a message.
///
/// A MRT record is constructed as the following:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Header... (variable)                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Message... (variable)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// See [CommonHeader] for the content in header, and [MrtMessage] for the
/// message format.
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MrtRecord {
    pub common_header: CommonHeader,
    pub message: MrtMessage,
}

/// MRT common header.
///
/// A CommonHeader ([RFC6396 section 2][header-link]) is constructed as the following:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Type              |            Subtype            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Length                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Or with extended timestamp:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Type              |            Subtype            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Length                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Microsecond Timestamp                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// The headers include the following:
/// - timestamp: 32 bits
/// - entry_type: [EntryType] enum
/// - entry_subtype: entry subtype
/// - length: length of the message in octets
/// - (`ET` type only) microsecond_timestamp: microsecond part of the timestamp.
///   only applicable to the MRT message type with `_ET` suffix, such as
///   `BGP4MP_ET`
///
/// [header-link]: https://datatracker.ietf.org/doc/html/rfc6396#section-2
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CommonHeader {
    pub timestamp: u32,
    pub microsecond_timestamp: Option<u32>,
    pub entry_type: EntryType,
    pub entry_subtype: u16,
    pub length: u32,
}

impl CommonHeader {
    /// Writes the binary representation of the header to the given writer.
    pub fn write_header<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.timestamp.to_be_bytes())?;
        writer.write_all(&(self.entry_type as u16).to_be_bytes())?;
        writer.write_all(&self.entry_subtype.to_be_bytes())?;

        match self.microsecond_timestamp {
            None => writer.write_all(&self.length.to_be_bytes()),
            Some(microseconds) => {
                // When the microsecond timestamp is present, the length must be adjusted to account
                // for the stace used by the extra timestamp data.
                writer.write_all(&(self.length + 4).to_be_bytes())?;
                writer.write_all(&microseconds.to_be_bytes())
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MrtMessage {
    TableDumpMessage(TableDumpMessage),
    TableDumpV2Message(TableDumpV2Message),
    Bgp4Mp(Bgp4Mp),
}

/// MRT entry type.
///
/// EntryType indicates the type of the current MRT record. Type 0 to 10 are deprecated.
///
/// Excerpt from [RFC6396 section 4](https://datatracker.ietf.org/doc/html/rfc6396#section-4):
/// ```text
/// The following MRT Types are currently defined for the MRT format.
/// The MRT Types that contain the "_ET" suffix in their names identify
/// those types that use an Extended Timestamp MRT Header.  The Subtype
/// and Message fields in these types remain as defined for the MRT Types
/// of the same name without the "_ET" suffix.
///
///     11   OSPFv2
///     12   TABLE_DUMP
///     13   TABLE_DUMP_V2
///     16   BGP4MP
///     17   BGP4MP_ET
///     32   ISIS
///     33   ISIS_ET
///     48   OSPFv3
///     49   OSPFv3_ET
/// ```
#[derive(Debug, Primitive, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum EntryType {
    // START DEPRECATED
    NULL = 0,
    START = 1,
    DIE = 2,
    I_AM_DEAD = 3,
    PEER_DOWN = 4,
    BGP = 5,
    RIP = 6,
    IDRP = 7,
    RIPNG = 8,
    BGP4PLUS = 9,
    BGP4PLUS_01 = 10,
    // END DEPRECATED
    OSPFv2 = 11,
    TABLE_DUMP = 12,
    TABLE_DUMP_V2 = 13,
    BGP4MP = 16,
    BGP4MP_ET = 17,
    ISIS = 32,
    ISIS_ET = 33,
    OSPFv3 = 48,
    OSPFv3_ET = 49,
}
