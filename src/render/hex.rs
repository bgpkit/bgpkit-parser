//! Hex rendering of MRT records.
//!
//! One record, one lowercase hex string — the paste format for
//! byte-level tools (e.g. wirescope's hex input). The record is
//! re-encoded through [`MrtRecord::encode`], which round-trips
//! byte-identically for standard records; records that cannot be
//! re-encoded surface the [`EncodingError`] to the caller.

use crate::error::EncodingError;
use crate::models::MrtRecord;

/// Render one MRT record as a single lowercase hex string (no separators).
///
/// The string covers the whole record — MRT common header, BGP4MP
/// subheader, and embedded BGP message — so pasting it into a layered
/// dissector preserves the session context.
pub fn format_record(record: &MrtRecord) -> Result<String, EncodingError> {
    let bytes = record.encode()?;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter() {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    /// Wire bytes for one BGP4MP_MESSAGE_AS4 record wrapping a minimal
    /// UPDATE. Hex rendering must reproduce these bytes exactly.
    fn wire() -> Vec<u8> {
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]); // ORIGIN igp
        attrs.extend_from_slice(&[0x40, 0x02, 0x06, 0x02, 0x01]);
        attrs.extend_from_slice(&65001u32.to_be_bytes()); // AS_PATH 65001
        attrs.extend_from_slice(&[0x40, 0x03, 0x04, 192, 0, 2, 254]);

        let mut update = Vec::new();
        update.extend_from_slice(&0u16.to_be_bytes());
        update.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        update.extend_from_slice(&attrs);
        update.extend_from_slice(&[24, 203, 0, 113]); // 203.0.113.0/24

        let mut bgp = vec![0xFF; 16];
        bgp.extend_from_slice(&((19 + update.len()) as u16).to_be_bytes());
        bgp.push(2);
        bgp.extend_from_slice(&update);

        let mut body = Vec::new();
        body.extend_from_slice(&64496u32.to_be_bytes());
        body.extend_from_slice(&64497u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[192, 0, 2, 1]);
        body.extend_from_slice(&[192, 0, 2, 2]);
        body.extend_from_slice(&bgp);

        let mut wire = Vec::new();
        wire.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        wire.extend_from_slice(&(EntryType::BGP4MP as u16).to_be_bytes());
        wire.extend_from_slice(&(Bgp4MpType::MessageAs4 as u16).to_be_bytes());
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(&body);
        wire
    }

    #[test]
    fn hex_render_round_trips_wire_bytes() {
        let wire = wire();
        let mut cursor = std::io::Cursor::new(wire.clone());
        let record = crate::parser::mrt::parse_mrt_record(&mut cursor).unwrap();

        let hex = format_record(&record).unwrap();
        let expected: String = wire.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
        assert!(!hex.contains(|c: char| c.is_uppercase()));
    }

    #[test]
    fn keepalive_record_renders() {
        let record = MrtRecord {
            common_header: CommonHeader {
                timestamp: 5,
                microsecond_timestamp: None,
                entry_type: EntryType::BGP4MP,
                entry_subtype: Bgp4MpType::MessageAs4 as u16,
                length: 0,
            },
            message: MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(Bgp4MpMessage {
                msg_type: Bgp4MpType::MessageAs4,
                peer_asn: Asn::new_32bit(64496),
                local_asn: Asn::new_32bit(64497),
                interface_index: 0,
                peer_ip: IpAddr::from_str("192.0.2.1").unwrap(),
                local_ip: IpAddr::from_str("192.0.2.2").unwrap(),
                bgp_message: BgpMessage::KeepAlive,
            })),
        };
        let hex = format_record(&record).unwrap();
        // header(12) + subheader(20) + BGP header(19) = 51 bytes = 102 chars
        assert_eq!(hex.len(), 102);
        assert!(hex.starts_with("0000000500100004"));
    }
}
