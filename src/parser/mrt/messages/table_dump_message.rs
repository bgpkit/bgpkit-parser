use crate::error::*;
use byteorder::{BigEndian, ReadBytesExt};
use ipnetwork::IpNetwork;
use crate::parser::ReadUtils;
use std::{
    io::Read,
    net::IpAddr,
};
use bgp_models::mrt::tabledump::TableDumpMessage;
use bgp_models::network::{AddrMeta, Afi, AsnLength, NetworkPrefix};
use crate::parser::bgp::attributes::AttributeParser;

/// TABLE_DUMP v1 only support 2-byte asn
fn parse_sub_type(sub_type: u16) -> Result<AddrMeta, ParserError> {
    let asn_len = AsnLength::Bits16;
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
    Ok(AddrMeta { afi, asn_len })
}

///
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
pub fn parse_table_dump_message<T: Read>(
    sub_type: u16,
    input: &mut T,
) -> Result<TableDumpMessage, ParserError> {
    let meta = parse_sub_type(sub_type)?;

    let view_number = input.read_u16::<BigEndian>()?;
    let sequence_number = input.read_u16::<BigEndian>()?;
    let prefix = match meta.afi {
        Afi::Ipv4 => input.read_ipv4_prefix().map(IpNetwork::V4),
        Afi::Ipv6 => input.read_ipv6_prefix().map(IpNetwork::V6),
    }?;
    let status = input.read_u8()?;
    let time = input.read_u32::<BigEndian>()? as u64;

    let peer_address: IpAddr = input.read_address(&meta.afi)?;
    let peer_asn = input.read_asn(&meta.asn_len)?;
    let attribute_length = input.read_u16::<BigEndian>()?;
    let attr_parser = AttributeParser::new(false);

    let mut attr_input = input.take(attribute_length as u64);
    let attributes = attr_parser.parse_attributes(&mut attr_input, &meta.asn_len, None, None, None)?;

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
