use crate::bgp::attributes::parse_attributes;
use crate::bmp::messages::BmpMessage;
use crate::models::{
    Afi, AsnLength, MrtMessage, MrtRecord, NetworkPrefix, RibAfiEntries, RibEntry, Safi,
    TableDumpV2Message, TableDumpV2Type,
};
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, Bytes};
use log::warn;

/// RIB AFI-specific entries
///
/// https://tools.ietf.org/html/rfc6396#section-4.3
pub fn parse_rib_afi_entries(
    data: &mut Bytes,
    rib_type: TableDumpV2Type,
) -> Result<RibAfiEntries, ParserError> {
    let afi: Afi;
    let safi: Safi;
    match rib_type {
        TableDumpV2Type::RibIpv4Unicast | TableDumpV2Type::RibIpv4UnicastAddPath => {
            afi = Afi::Ipv4;
            safi = Safi::Unicast
        }
        TableDumpV2Type::RibIpv4Multicast | TableDumpV2Type::RibIpv4MulticastAddPath => {
            afi = Afi::Ipv4;
            safi = Safi::Multicast
        }
        TableDumpV2Type::RibIpv6Unicast | TableDumpV2Type::RibIpv6UnicastAddPath => {
            afi = Afi::Ipv6;
            safi = Safi::Unicast
        }
        TableDumpV2Type::RibIpv6Multicast | TableDumpV2Type::RibIpv6MulticastAddPath => {
            afi = Afi::Ipv6;
            safi = Safi::Multicast
        }
        _ => {
            return Err(ParserError::ParseError(format!(
                "wrong RIB type for parsing: {:?}",
                rib_type
            )))
        }
    };

    let add_path = matches!(
        rib_type,
        TableDumpV2Type::RibIpv4UnicastAddPath
            | TableDumpV2Type::RibIpv4MulticastAddPath
            | TableDumpV2Type::RibIpv6UnicastAddPath
            | TableDumpV2Type::RibIpv6MulticastAddPath
    );

    let sequence_number = data.read_u32()?;

    // NOTE: here we parse the prefix as only length and prefix, the path identifier for add_path
    //       entry is not handled here. We follow RFC6396 here https://www.rfc-editor.org/rfc/rfc6396.html#section-4.3.2
    let prefix = data.read_nlri_prefix(&afi, false)?;

    let entry_count = data.read_u16()?;
    let mut rib_entries = Vec::with_capacity((entry_count * 2) as usize);

    // get the u8 slice of the rest of the data
    // let attr_data_slice = &input.into_inner()[(input.position() as usize)..];

    for _i in 0..entry_count {
        let entry = match parse_rib_entry(data, add_path, &afi, &safi, prefix) {
            Ok(entry) => entry,
            Err(e) => {
                warn!("early break due to error {}", e.to_string());
                break;
            }
        };
        rib_entries.push(entry);
    }

    Ok(RibAfiEntries {
        rib_type,
        sequence_number,
        prefix,
        rib_entries,
    })
}

/// RIB entry: one prefix per entry
pub fn parse_rib_entry(
    input: &mut Bytes,
    add_path: bool,
    afi: &Afi,
    safi: &Safi,
    prefix: NetworkPrefix,
) -> Result<RibEntry, ParserError> {
    if input.remaining() < 8 {
        // total length - current position less than 16 --
        // meaning less than 16 bytes available to read
        return Err(ParserError::TruncatedMsg("truncated msg".to_string()));
    }

    let peer_index = input.read_u16()?;
    let originated_time = input.read_u32()?;
    if add_path {
        let _path_id = input.read_u32()?;
    }
    let attribute_length = input.read_u16()? as usize;

    if input.remaining() < attribute_length {
        return Err(ParserError::TruncatedMsg("truncated msg".to_string()));
    }

    let attr_data_slice = input.split_to(attribute_length);
    let attributes = parse_attributes(
        attr_data_slice,
        &AsnLength::Bits32,
        add_path,
        Some(*afi),
        Some(*safi),
        Some(&[prefix]),
    )?;

    Ok(RibEntry {
        peer_index,
        originated_time,
        attributes,
    })
}

impl RibAfiEntries {
    pub fn encode(&self) -> Bytes {
        todo!()
        // let mut bytes = Bytes::new();
        // bytes.extend_from_slice(&self.sequence_number.to_be_bytes());
        // bytes.extend_from_slice(&self.prefix.encode());
        // bytes.extend_from_slice(&(self.rib_entries.len() as u16).to_be_bytes());
        // for entry in &self.rib_entries {
        //     bytes.extend_from_slice(&entry.encode());
        // }
        // bytes
    }
}

impl TryFrom<MrtRecord> for RibAfiEntries {
    type Error = String;

    fn try_from(mrt_record: MrtRecord) -> Result<Self, Self::Error> {
        match mrt_record.message {
            MrtMessage::TableDumpMessage(_) => {}
            MrtMessage::TableDumpV2Message(m) => match m {
                TableDumpV2Message::PeerIndexTable(_) => {}
                TableDumpV2Message::RibAfi(_) => {}
                TableDumpV2Message::RibGeneric(_) => {}
            },
            MrtMessage::Bgp4Mp(_) => {}
        }
        todo!()
    }
}
