use crate::error::EncodingError;
use crate::models::{AsnLength, Bgp4MpEnum, Bgp4MpType, MrtMessage, TableDumpV2Message};
use bytes::{Bytes, BytesMut};

pub(crate) mod bgp4mp;
pub(crate) mod table_dump;
pub(crate) mod table_dump_v2;

impl MrtMessage {
    /// Append the wire representation of this MRT message body to `buf`.
    pub fn encode_to(&self, sub_type: u16, buf: &mut BytesMut) -> Result<(), EncodingError> {
        match self {
            MrtMessage::TableDumpMessage(m) => m.encode_to(buf),
            MrtMessage::TableDumpV2Message(m) => match m {
                TableDumpV2Message::PeerIndexTable(p) => p.encode_to(buf),
                TableDumpV2Message::RibAfi(r) => r.encode_to(buf),
                TableDumpV2Message::RibGeneric(_) => Err(EncodingError::unencodable(
                    "TABLE_DUMP_V2 RIB_GENERIC",
                    "RIB_GENERIC encoding is not supported",
                )),
                TableDumpV2Message::GeoPeerTable(g) => g.encode_to(buf),
            },
            MrtMessage::Bgp4Mp(m) => {
                let msg_type = Bgp4MpType::try_from(sub_type).map_err(|_| {
                    EncodingError::unencodable(
                        "BGP4MP subtype",
                        format!("unknown subtype {sub_type}"),
                    )
                })?;

                match m {
                    Bgp4MpEnum::StateChange(msg) => {
                        let asn_len = match matches!(msg_type, Bgp4MpType::StateChangeAs4) {
                            true => AsnLength::Bits32,
                            false => AsnLength::Bits16,
                        };
                        msg.encode_to(asn_len, buf);
                        Ok(())
                    }
                    Bgp4MpEnum::Message(msg) => {
                        let asn_len = match matches!(
                            msg_type,
                            Bgp4MpType::MessageAs4
                                | Bgp4MpType::MessageAs4Addpath
                                | Bgp4MpType::MessageLocalAs4Addpath
                                | Bgp4MpType::MessageAs4Local
                        ) {
                            true => AsnLength::Bits32,
                            false => AsnLength::Bits16,
                        };
                        msg.encode_to(asn_len, buf)
                    }
                }
            }
        }
    }

    /// Convenience: encode into a fresh buffer.
    pub fn encode(&self, sub_type: u16) -> Result<Bytes, EncodingError> {
        let mut buf = BytesMut::new();
        self.encode_to(sub_type, &mut buf)?;
        Ok(buf.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{GeoPeerTable, TableDumpV2Type};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_mrt_message_encode_geo_peer_table() {
        // Test MrtMessage::encode path for GeoPeerTable
        let geo_table = GeoPeerTable::new(
            Ipv4Addr::from_str("192.0.2.1").unwrap(),
            "test-view".to_string(),
            0.0,
            0.0,
        );

        let mrt_message =
            MrtMessage::TableDumpV2Message(TableDumpV2Message::GeoPeerTable(geo_table));

        let subtype = TableDumpV2Type::GeoPeerTable as u16;
        let encoded = mrt_message.encode(subtype).unwrap();

        // Should produce some encoded bytes
        assert!(!encoded.is_empty());
    }
}
