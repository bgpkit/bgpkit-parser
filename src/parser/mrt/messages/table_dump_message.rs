use crate::error::*;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use bgp_models::mrt::tabledump::TableDumpMessage;
use bgp_models::network::{AddrMeta, Afi, AsnLength, NetworkPrefix};
use crate::parser::bgp::attributes::AttributeParser;
use crate::parser::DataBytes;

/// TABLE_DUMP v1 only support 2-byte asn
fn parse_sub_type(sub_type: u16) -> Result<AddrMeta, ParserErrorKind> {
    let asn_len = AsnLength::Bits16;
    let afi = match sub_type {
        1 => Afi::Ipv4,
        2 => Afi::Ipv6,
        _ => {
            return Err(ParserErrorKind::ParseError(format!(
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
pub fn parse_table_dump_message(
    sub_type: u16,
    input: &mut DataBytes,
) -> Result<TableDumpMessage, ParserErrorKind> {
    let meta = parse_sub_type(sub_type)?;

    let view_number = input.read_16b()?;
    let sequence_number = input.read_16b()?;
    let prefix = match meta.afi {
        Afi::Ipv4 => input.read_ipv4_prefix().map(IpNetwork::V4),
        Afi::Ipv6 => input.read_ipv6_prefix().map(IpNetwork::V6),
    }?;
    let status = input.read_8b()?;
    let time = input.read_32b()? as u64;

    let peer_address: IpAddr = input.read_address(&meta.afi)?;
    let peer_asn = input.read_asn(&meta.asn_len)?;
    let attribute_length = input.read_16b()? as usize;
    let attr_parser = AttributeParser::new(false);

    let attributes = attr_parser.parse_attributes(input, &meta.asn_len, None, None, None, attribute_length)?;

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
