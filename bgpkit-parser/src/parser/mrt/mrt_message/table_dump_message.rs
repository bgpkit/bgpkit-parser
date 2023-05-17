use crate::error::*;
use crate::models::*;
use crate::parser::bgp::attributes::parse_attributes;
use crate::parser::ReadUtils;
use bytes::{BufMut, Bytes, BytesMut};
use ipnet::IpNet;
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
    mut data: Bytes,
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

    let view_number = data.read_u16()?;
    let sequence_number = data.read_u16()?;
    let prefix = match &afi {
        Afi::Ipv4 => data.read_ipv4_prefix().map(ipnet::IpNet::V4),
        Afi::Ipv6 => data.read_ipv6_prefix().map(ipnet::IpNet::V6),
    }?;

    let status = data.read_u8()?;
    let time = data.read_u32()? as u64;

    let peer_address: IpAddr = data.read_address(&afi)?;
    let peer_asn = data.read_asn(&asn_len)?;

    let attribute_length = data.read_u16()? as usize;

    // ####
    // Step 2. read the attributes
    //   - create subslice based on the cursor's current position
    //   - pass the data into the parser function

    data.has_n_remaining(attribute_length)?;
    let attr_data_slice = data.split_to(attribute_length);
    let attributes = parse_attributes(attr_data_slice, &asn_len, false, None, None, None)?;

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

impl TableDumpMessage {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put_u16(self.view_number);
        bytes.put_u16(self.sequence_number);
        // TODO: prefix
        match &self.prefix.prefix {
            IpNet::V4(p) => {
                bytes.put_u32(p.addr().into());
                bytes.put_u8(p.prefix_len());
            }
            IpNet::V6(p) => {
                bytes.put_u128(p.addr().into());
                bytes.put_u8(p.prefix_len());
            }
        }
        bytes.put_u8(self.status);
        bytes.put_u32(self.originated_time as u32);

        // peer address and peer asn
        match self.peer_address {
            IpAddr::V4(a) => {
                bytes.put_u32(a.into());
            }
            IpAddr::V6(a) => {
                bytes.put_u128(a.into());
            }
        }
        bytes.put_u16(self.peer_asn.asn as u16);

        // encode attributes
        let mut attr_bytes = BytesMut::new();
        // TODO encode attributes to attr_bytes
        for attr in &self.attributes {
            // attr_bytes.extend(attr.encode());
        }

        bytes.put_u16(attr_bytes.len() as u16);
        bytes.put_slice(&attr_bytes);

        bytes.freeze()
    }
}
