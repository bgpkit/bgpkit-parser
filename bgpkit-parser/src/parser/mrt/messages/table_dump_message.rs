use crate::error::*;
use crate::parser::bgp::attributes::AttributeParser;
use crate::parser::ReadUtils;
use bgp_models::prelude::*;
use byteorder::{ReadBytesExt, BE};
use std::io::Cursor;
use std::net::IpAddr;

/// Parse MRT TABLE_DUMP type message.
///
/// https://www.rfc-editor.org/rfc/rfc6396#section-4.2
///
/// ```text
/// The TABLE_DUMP Type does not permit 4-byte Peer AS numbers, nor does
//  it allow the AFI of the peer IP to differ from the AFI of the Prefix
//  field.  The TABLE_DUMP_V2 Type MUST be used in these situations.
/// ```
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         View Number           |       Sequence Number         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Prefix (variable)                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Prefix Length |    Status     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Originated Time                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Peer IP Address (variable)                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Peer AS             |       Attribute Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   BGP Attribute... (variable)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn parse_table_dump_message(
    sub_type: u16,
    data: &[u8],
) -> Result<TableDumpMessage, ParserError> {
    // ####
    // Step 0. prepare
    //   - define AS number length
    //   - determine address family
    //   - create data slice reader cursor

    // for TABLE_DUMP type, the AS number length is always 2-byte.
    let asn_len = AsnLength::Bits16;
    // determine address family based on the sub_type value defined in the MRT [CommonHeader].
    let afi = match sub_type {
        1 => Afi::Ipv4,
        2 => Afi::Ipv6,
        _ => {
            return Err(ParserError::ParseError(format!(
                "Invalid subtype found for TABLE_DUMP (V1) message: {}",
                sub_type
            )))
        }
    };

    // create a reader for the passed in data slice.
    let mut input = Cursor::new(data);

    // ####
    // Step 1. read simple fields
    //   - view number
    //   - sequence number
    //   - prefix
    //   - prefix-length
    //   - status
    //   - originated time
    //   - peer IP address
    //   - peer ASN
    //   - attribute length

    let view_number = input.read_u16::<BE>()?;
    let sequence_number = input.read_u16::<BE>()?;
    let prefix = match &afi {
        Afi::Ipv4 => input.read_ipv4_prefix().map(ipnet::IpNet::V4),
        Afi::Ipv6 => input.read_ipv6_prefix().map(ipnet::IpNet::V6),
    }?;
    let status = input.read_8b()?;
    let time = input.read_32b()? as u64;

    let peer_address: IpAddr = input.read_address(&afi)?;
    let peer_asn = input.read_asn(&asn_len)?;
    let attribute_length = input.read_u16::<BE>()? as usize;

    // ####
    // Step 2. read the attributes
    //   - create subslice based on the cursor's current position
    //   - pass the data into the parser function

    let attr_parser = AttributeParser::new(false);
    let current_position = input.position() as usize;
    let attr_data_slice = &input.into_inner()[current_position..];
    // TODO: relax this assertion with error matching later
    assert_eq!(attr_data_slice.len(), attribute_length);
    let attributes = attr_parser.parse_attributes(attr_data_slice, &asn_len, None, None, None)?;

    Ok(TableDumpMessage {
        view_number,
        sequence_number,
        prefix: NetworkPrefix::new(prefix, 0),
        status,
        originated_time: time,
        peer_address,
        peer_asn,
        attributes,
    })
}
