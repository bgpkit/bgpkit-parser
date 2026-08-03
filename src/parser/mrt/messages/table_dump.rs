use crate::encoder::sink::with_u16_len;
use crate::error::*;
use crate::models::*;
use crate::parser::bgp::attributes::parse_attributes;
use crate::parser::ReadUtils;
use bytes::{BufMut, Bytes, BytesMut};
use ipnet::IpNet;
use std::net::IpAddr;

/// Parse MRT TABLE_DUMP type message.
///
/// <https://www.rfc-editor.org/rfc/rfc6396#section-4.2>
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
    data: Bytes,
) -> Result<TableDumpMessage, ParserError> {
    let mut messages = parse_table_dump_messages(sub_type, data)?;
    if messages.len() != 1 {
        return Err(ParserError::ParseError(format!(
            "expected one TABLE_DUMP entry, found {}",
            messages.len()
        )));
    }
    Ok(messages.remove(0))
}

/// Parse all entries carried by one physical TABLE_DUMP record.
///
/// RFC 6396 records contain one entry. Early MRT implementations batched
/// multiple entries behind one view/sequence header.
pub fn parse_table_dump_messages(
    sub_type: u16,
    mut data: Bytes,
) -> Result<Vec<TableDumpMessage>, ParserError> {
    // ####
    // Step 0. prepare
    //   - define AS number length
    //   - determine address family
    //   - create data slice reader cursor

    // determine address family based on the sub_type value defined in the MRT [CommonHeader].
    let afi = match sub_type {
        1 => Afi::Ipv4,
        2 => Afi::Ipv6,
        _ => {
            return Err(ParserError::ParseError(format!(
                "Invalid subtype found for TABLE_DUMP (V1) message: {sub_type}"
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
    let mut messages = Vec::new();

    while !data.is_empty() {
        messages.push(parse_table_dump_entry(
            &mut data,
            &afi,
            view_number,
            sequence_number,
        )?);
    }

    if messages.is_empty() {
        return Err(ParserError::TruncatedMsg(
            "TABLE_DUMP record contains no entries".to_string(),
        ));
    }

    Ok(messages)
}

fn parse_table_dump_entry(
    data: &mut Bytes,
    afi: &Afi,
    view_number: u16,
    sequence_number: u16,
) -> Result<TableDumpMessage, ParserError> {
    let prefix = match &afi {
        Afi::Ipv4 => data.read_ipv4_prefix().map(ipnet::IpNet::V4),
        Afi::Ipv6 => data.read_ipv6_prefix().map(ipnet::IpNet::V6),
        Afi::LinkState => {
            // Link-State doesn't use traditional prefixes, but we need a placeholder
            // Use 0.0.0.0/0 as a placeholder for now
            Ok(ipnet::IpNet::V4(
                ipnet::Ipv4Net::new(std::net::Ipv4Addr::new(0, 0, 0, 0), 0).unwrap(),
            ))
        }
    }?;

    let status = data.read_u8()?;
    let time = data.read_u32()? as u64;

    let peer_ip: IpAddr = data.read_address(afi)?;
    let peer_asn = Asn::new_16bit(data.read_u16()?);

    let attribute_length = data.read_u16()? as usize;

    // ####
    // Step 2. read the attributes
    //   - create subslice based on the cursor's current position
    //   - pass the data into the parser function

    data.has_n_remaining(attribute_length)?;
    let attr_data_slice = data.split_to(attribute_length);

    // for TABLE_DUMP type, the AS number length is always 2-byte.
    let mut attributes =
        parse_attributes(attr_data_slice, &AsnLength::Bits16, false, None, None, None)?;

    // validate mandatory attributes (TABLE_DUMP is always an announcement)
    attributes.check_mandatory_attributes(true, *afi == Afi::Ipv4);

    Ok(TableDumpMessage {
        view_number,
        sequence_number,
        prefix: NetworkPrefix::new(prefix, None),
        status,
        originated_time: time,
        peer_ip,
        peer_asn,
        attributes,
    })
}

impl TableDumpMessage {
    pub fn encode(&self) -> Result<Bytes, EncodingError> {
        let mut bytes = BytesMut::new();
        bytes.put_u16(self.view_number);
        bytes.put_u16(self.sequence_number);
        self.encode_entry_to(&mut bytes)?;
        Ok(bytes.freeze())
    }

    fn encode_entry_to(&self, bytes: &mut BytesMut) -> Result<(), EncodingError> {
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
        match self.peer_ip {
            IpAddr::V4(a) => {
                bytes.put_u32(a.into());
            }
            IpAddr::V6(a) => {
                bytes.put_u128(a.into());
            }
        }
        bytes.put_u16(self.peer_asn.into());

        // encode attributes; asn_len is always 16-bit for TABLE_DUMP
        with_u16_len(bytes, "TABLE_DUMP attribute length", |b| {
            self.attributes.encode_to(AsnLength::Bits16, b)
        })?;
        Ok(())
    }
}

pub(crate) fn encode_table_dump_batch(
    messages: &[TableDumpMessage],
    sub_type: u16,
) -> Result<Bytes, EncodingError> {
    let Some(first) = messages.first() else {
        return Err(EncodingError::unencodable(
            "TABLE_DUMP batch",
            "batch is empty",
        ));
    };

    let expected_ipv4 = match sub_type {
        1 => true,
        2 => false,
        _ => {
            return Err(EncodingError::unencodable(
                "TABLE_DUMP batch",
                format!("invalid subtype {sub_type}"),
            ));
        }
    };

    let mut bytes = BytesMut::new();
    bytes.put_u16(first.view_number);
    bytes.put_u16(first.sequence_number);
    for message in messages {
        if message.view_number != first.view_number
            || message.sequence_number != first.sequence_number
        {
            return Err(EncodingError::unencodable(
                "TABLE_DUMP batch",
                "all entries must have the same view and sequence numbers",
            ));
        }
        if matches!(message.prefix.prefix, IpNet::V4(_)) != expected_ipv4
            || matches!(message.peer_ip, IpAddr::V4(_)) != expected_ipv4
        {
            return Err(EncodingError::unencodable(
                "TABLE_DUMP batch",
                "entry address family does not match the MRT subtype",
            ));
        }
        message.encode_entry_to(&mut bytes)?;
    }
    Ok(bytes.freeze())
}

/// Return true when a historical batched TABLE_DUMP body is structurally
/// complete except for the final four attribute bytes.
///
/// This recovers files written by an old MRT writer, likely MRT Toolkit. The
/// surviving MRT Toolkit source already has the fix: `bgp_table_dump_write`
/// includes the 4-byte View Number and Sequence Number in the declared length.
/// The fixture `bview.20000111.0032.gz` omits those four bytes from the length.
///
/// [original MRT writer]: https://fossies.org/linux/misc/old/mrt-2.2.2a-src.tar.gz/mrt-2.2.2a/src/lib/bgp_proto/bgp_dump2.c
pub(crate) fn needs_legacy_length_correction(sub_type: u16, data: &[u8]) -> bool {
    let address_len = match sub_type {
        1 => 4usize,
        2 => 16usize,
        _ => return false,
    };
    if data.len() < 4 {
        return false;
    }

    // Prefix, prefix length, status, originated time, peer IP, peer ASN,
    // and the attribute-length field.
    let fixed_entry_len = address_len * 2 + 10;
    let mut offset = 4usize;
    while offset < data.len() {
        let Some(attr_len_offset) = offset.checked_add(fixed_entry_len - 2) else {
            return false;
        };
        if attr_len_offset + 2 > data.len() {
            return false;
        }
        let attr_len =
            u16::from_be_bytes([data[attr_len_offset], data[attr_len_offset + 1]]) as usize;
        let Some(entry_end) = offset
            .checked_add(fixed_entry_len)
            .and_then(|value| value.checked_add(attr_len))
        else {
            return false;
        };
        if entry_end == data.len() + 4 {
            return true;
        }
        if entry_end <= offset || entry_end > data.len() {
            return false;
        }
        offset = entry_end;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};
    use std::net::{Ipv4Addr, Ipv6Addr};

    const VIEW_NUMBER: u16 = 0;
    const SEQUENCE_NUMBER: u16 = 0;
    const IPV4_PREFIX: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
    const IPV6_PREFIX: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
    const PREFIX_LEN: u8 = 0;
    const STATUS: u8 = 0;
    const TIME: u64 = 0;
    const PEER_IPV4: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
    const PEER_IPV6: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
    const PEER_ASN_16BIT: u16 = 0;
    const ATTRIBUTE_LENGTH: usize = 0;
    const DUMMY_ATTRIBUTES: &[u8] = &[];

    #[test]
    fn test_parse_table_dump_message_ipv4() {
        let mut bytes_mut = BytesMut::new();
        // Populate the bytes_mut with the same sequence that parse_table_dump_message() expects to parse
        bytes_mut.put_u16(VIEW_NUMBER);
        bytes_mut.put_u16(SEQUENCE_NUMBER);
        bytes_mut.put_u32(IPV4_PREFIX.into());
        bytes_mut.put_u8(PREFIX_LEN);
        bytes_mut.put_u8(STATUS);
        bytes_mut.put_u32(TIME as u32);
        bytes_mut.put_u32(PEER_IPV4.into());
        bytes_mut.put_u16(PEER_ASN_16BIT);
        bytes_mut.put_u16(ATTRIBUTE_LENGTH as u16);
        bytes_mut.put_slice(DUMMY_ATTRIBUTES);

        // Convert from BytesMut to Bytes
        let bytes = bytes_mut.freeze();

        let table_dump_message_res = parse_table_dump_message(1, bytes.clone());
        assert!(
            table_dump_message_res.is_ok(),
            "Failed to parse TABLE_DUMP_V1 message"
        );

        let table_dump_message = table_dump_message_res.unwrap();
        assert_eq!(
            table_dump_message.view_number, VIEW_NUMBER,
            "VIEW_NUMBER mismatch"
        );
        assert_eq!(
            table_dump_message.sequence_number, SEQUENCE_NUMBER,
            "SEQUENCE_NUMBER mismatch"
        );
        // Add more assertions here as per your actual requirements
        let encoded = table_dump_message.encode().unwrap();
        assert_eq!(encoded, bytes);
    }
    #[test]
    fn test_parse_table_dump_message_ipv6() {
        let mut bytes_mut = BytesMut::new();
        // Populate the bytes_mut with the same sequence that parse_table_dump_message() expects to parse
        bytes_mut.put_u16(VIEW_NUMBER);
        bytes_mut.put_u16(SEQUENCE_NUMBER);
        bytes_mut.put_u128(IPV6_PREFIX.into());
        bytes_mut.put_u8(PREFIX_LEN);
        bytes_mut.put_u8(STATUS);
        bytes_mut.put_u32(TIME as u32);
        bytes_mut.put_u128(PEER_IPV6.into());
        bytes_mut.put_u16(PEER_ASN_16BIT);
        bytes_mut.put_u16(ATTRIBUTE_LENGTH as u16);
        bytes_mut.put_slice(DUMMY_ATTRIBUTES);

        // Convert from BytesMut to Bytes
        let bytes = bytes_mut.freeze();

        let table_dump_message_res = parse_table_dump_message(2, bytes.clone());
        assert!(
            table_dump_message_res.is_ok(),
            "Failed to parse TABLE_DUMP_V1 message"
        );

        let table_dump_message = table_dump_message_res.unwrap();
        assert_eq!(
            table_dump_message.view_number, VIEW_NUMBER,
            "VIEW_NUMBER mismatch"
        );
        assert_eq!(
            table_dump_message.sequence_number, SEQUENCE_NUMBER,
            "SEQUENCE_NUMBER mismatch"
        );
        // Add more assertions here as per your actual requirements

        // test encoding
        let encoded = table_dump_message.encode().unwrap();
        assert_eq!(encoded, bytes);
    }

    #[test]
    fn test_parse_table_dump_message_invalid_subtype() {
        // Create a simple byte array for testing
        let mut bytes_mut = BytesMut::new();
        bytes_mut.put_u16(VIEW_NUMBER);
        bytes_mut.put_u16(SEQUENCE_NUMBER);
        let bytes = bytes_mut.freeze();

        // Test with an invalid sub_type (not 1 or 2)
        let result = parse_table_dump_message(0, bytes.clone());
        assert!(result.is_err(), "Expected error for invalid sub_type");

        if let Err(ParserError::ParseError(msg)) = result {
            assert!(
                msg.contains("Invalid subtype"),
                "Expected error message to mention invalid subtype"
            );
        } else {
            panic!("Expected ParseError for invalid sub_type");
        }

        // Test with another invalid sub_type
        let result = parse_table_dump_message(3, bytes);
        assert!(result.is_err(), "Expected error for invalid sub_type");

        if let Err(ParserError::ParseError(msg)) = result {
            assert!(
                msg.contains("Invalid subtype"),
                "Expected error message to mention invalid subtype"
            );
        } else {
            panic!("Expected ParseError for invalid sub_type");
        }
    }

    #[test]
    fn test_table_dump_message_encode_with_attributes() {
        use crate::models::{Asn, AttributeValue, Attributes, Origin};
        use std::str::FromStr;

        let prefix = IpNet::from_str("192.168.0.0/24").unwrap();
        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());

        let table_dump = TableDumpMessage {
            view_number: 1,
            sequence_number: 2,
            prefix: NetworkPrefix::new(prefix, None),
            status: 1,
            originated_time: 12345,
            peer_ip: IpAddr::V4("10.0.0.1".parse().unwrap()),
            peer_asn: Asn::from(65000),
            attributes,
        };

        // This should exercise the attr.encode(AsnLength::Bits16).unwrap() line
        let _encoded = table_dump.encode().unwrap();
    }

    #[test]
    fn parses_and_encodes_batched_table_dump_messages() {
        use crate::models::{AttributeValue, Origin};
        use std::str::FromStr;

        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        let first = TableDumpMessage {
            view_number: 7,
            sequence_number: 9,
            prefix: NetworkPrefix::from_str("192.0.2.0/24").unwrap(),
            status: 1,
            originated_time: 12345,
            peer_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            peer_asn: Asn::new_16bit(64512),
            attributes: attributes.clone(),
        };
        let second = TableDumpMessage {
            prefix: NetworkPrefix::from_str("198.51.100.0/24").unwrap(),
            ..first.clone()
        };

        let wire = encode_table_dump_batch(&[first.clone(), second.clone()], 1).unwrap();
        let parsed = parse_table_dump_messages(1, wire.clone()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].prefix, first.prefix);
        assert_eq!(parsed[1].prefix, second.prefix);
        assert!(!needs_legacy_length_correction(1, &wire));
        assert!(needs_legacy_length_correction(1, &wire[..wire.len() - 4]));
        assert!(!needs_legacy_length_correction(1, &wire[..wire.len() - 3]));
    }
}
