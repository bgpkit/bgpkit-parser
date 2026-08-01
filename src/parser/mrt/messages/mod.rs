use crate::error::EncodingError;
use crate::models::{AsnLength, Bgp4MpEnum, Bgp4MpType, MrtMessage, TableDumpV2Message};
use bytes::Bytes;

pub(crate) mod bgp4mp;
pub(crate) mod legacy_bgp;
pub(crate) mod table_dump;
pub(crate) mod table_dump_v2;

impl MrtMessage {
    pub fn encode(&self, sub_type: u16) -> Result<Bytes, EncodingError> {
        let msg_bytes: Bytes = match self {
            MrtMessage::TableDumpMessage(m) => m.encode()?,
            MrtMessage::TableDumpMessageBatch(messages) => {
                crate::parser::mrt::messages::table_dump::encode_table_dump_batch(
                    messages, sub_type,
                )?
            }
            MrtMessage::TableDumpV2Message(m) => match m {
                TableDumpV2Message::PeerIndexTable(p) => p.encode()?,
                TableDumpV2Message::RibAfi(r) => r.encode()?,
                TableDumpV2Message::RibGeneric(_) => {
                    return Err(EncodingError::unencodable(
                        "MRT TABLE_DUMP_V2 RIB_GENERIC message",
                        "encoding not implemented",
                    ));
                }
                TableDumpV2Message::GeoPeerTable(g) => g.encode()?,
            },
            MrtMessage::Bgp4Mp(m) => {
                let msg_type = Bgp4MpType::try_from(sub_type).map_err(|_| {
                    EncodingError::unencodable(
                        "BGP4MP subtype",
                        format!("invalid subtype {sub_type}"),
                    )
                })?;

                match m {
                    Bgp4MpEnum::StateChange(msg) => {
                        let asn_len = match matches!(msg_type, Bgp4MpType::StateChangeAs4) {
                            true => AsnLength::Bits32,
                            false => AsnLength::Bits16,
                        };
                        msg.encode(asn_len)
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
                        msg.encode(asn_len)?
                    }
                }
            }
            MrtMessage::LegacyBgp(m) => {
                crate::parser::mrt::messages::legacy_bgp::encode_legacy_bgp(m, sub_type)?
            }
        };

        Ok(msg_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Asn, Bgp4MpMessage, BgpMessage, GeoPeerTable, TableDumpV2Type};
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

    #[test]
    fn test_mrt_message_encode_rejects_invalid_bgp4mp_subtype() {
        let message = MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(Bgp4MpMessage {
            msg_type: Bgp4MpType::Message,
            peer_asn: Asn::new_32bit(65000),
            local_asn: Asn::new_32bit(65001),
            interface_index: 0,
            peer_ip: Ipv4Addr::LOCALHOST.into(),
            local_ip: Ipv4Addr::UNSPECIFIED.into(),
            bgp_message: BgpMessage::KeepAlive,
        }));

        assert_eq!(
            message.encode(u16::MAX),
            Err(EncodingError::Unencodable {
                field: "BGP4MP subtype",
                reason: format!("invalid subtype {}", u16::MAX),
            })
        );
    }
}
