//! Record-level diagnostic iterator for malformed MRT data investigation.

use crate::error::{BgpValidationWarning, ParserError};
use crate::models::*;
use crate::parser::mrt::mrt_record::{chunk_mrt_record_with_context, raw_record_uses_zebra_compat};
use crate::parser::mrt::RawMrtRecord;
use crate::parser::BgpkitParser;
use std::io::Read;

/// A record-level parsing outcome for malformed-data investigation.
#[derive(Debug)]
#[non_exhaustive]
pub enum DiagnosticEvent {
    /// A fully parsed record with no RFC 7606 validation findings.
    Record(MrtRecord),
    /// A parsed record with one or more recoverable validation findings.
    Validation {
        /// The parsed MRT record.
        record: MrtRecord,
        /// RFC 7606 validation findings in record traversal order.
        warnings: Vec<BgpValidationWarning>,
        /// The original MRT record bytes and header.
        raw_record: RawMrtRecord,
    },
    /// A record that could not be fully parsed.
    ParseError {
        /// The parsing failure.
        error: ParserError,
        /// The MRT common header when framing completed successfully.
        common_header: Option<CommonHeader>,
        /// All bytes consumed for this record, when available.
        raw_bytes: Option<Vec<u8>>,
    },
}

/// Iterator over record-level parsing diagnostics.
pub struct DiagnosticIterator<R> {
    parser: BgpkitParser<R>,
    terminated: bool,
}

impl<R> DiagnosticIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        Self {
            parser,
            terminated: false,
        }
    }
}

impl<R: Read> Iterator for DiagnosticIterator<R> {
    type Item = DiagnosticEvent;

    fn next(&mut self) -> Option<Self::Item> {
        // Text dumps have no MRT record boundary or raw MRT representation.
        if self.terminated || self.parser.text_dump_iter.is_some() {
            return None;
        }

        let raw_record = match chunk_mrt_record_with_context(&mut self.parser.reader) {
            Ok(raw_record) => raw_record,
            Err(error) if matches!(error.error, ParserError::EofExpected) => {
                self.terminated = true;
                return None;
            }
            Err(error) => {
                // A framing error may leave the reader between record boundaries. Do not
                // attempt to reinterpret the remaining bytes as another MRT header.
                self.terminated = true;
                return Some(DiagnosticEvent::ParseError {
                    error: error.error,
                    common_header: error.common_header,
                    raw_bytes: error.bytes,
                });
            }
        };

        let used_zebra_compat = raw_record_uses_zebra_compat(&raw_record);
        let record = match raw_record.clone().parse() {
            Ok(record) => record,
            Err(error) => {
                return Some(DiagnosticEvent::ParseError {
                    error,
                    common_header: Some(raw_record.common_header),
                    raw_bytes: Some(raw_record.raw_bytes().to_vec()),
                });
            }
        };
        if used_zebra_compat {
            self.parser.warn_zebra_compat_once();
        }

        let warnings = record_validation_warnings(&record);
        if warnings.is_empty() {
            Some(DiagnosticEvent::Record(record))
        } else {
            Some(DiagnosticEvent::Validation {
                record,
                warnings,
                raw_record,
            })
        }
    }
}

fn record_validation_warnings(record: &MrtRecord) -> Vec<BgpValidationWarning> {
    match &record.message {
        MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(message)) => update_warnings(&message.bgp_message),
        MrtMessage::LegacyBgp(LegacyBgp::Message(message)) => update_warnings(&message.bgp_message),
        MrtMessage::TableDumpMessage(message) => message.attributes.validation_warnings().to_vec(),
        MrtMessage::TableDumpMessageBatch(messages) => messages
            .iter()
            .flat_map(|message| message.attributes.validation_warnings().iter().cloned())
            .collect(),
        MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(rib)) => rib
            .rib_entries
            .iter()
            .flat_map(|entry| entry.attributes.validation_warnings().iter().cloned())
            .collect(),
        _ => Vec::new(),
    }
}

fn update_warnings(message: &BgpMessage) -> Vec<BgpValidationWarning> {
    match message {
        BgpMessage::Update(update) => update.attributes.validation_warnings().to_vec(),
        BgpMessage::RouteRefresh(refresh) => refresh.validation_warnings(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn update_record(attributes: Attributes) -> MrtRecord {
        MrtRecord {
            common_header: CommonHeader {
                timestamp: 1_700_000_000,
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
                bgp_message: BgpMessage::Update(BgpUpdateMessage {
                    withdrawn_prefixes: vec![],
                    attributes,
                    announced_prefixes: vec![NetworkPrefix::from_str("203.0.113.0/24").unwrap()],
                }),
            })),
        }
    }

    fn valid_attributes() -> Attributes {
        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        attributes.add_attr(
            AttributeValue::AsPath {
                path: AsPath::from_sequence([64500]),
                is_as4: false,
            }
            .into(),
        );
        attributes
            .add_attr(AttributeValue::NextHop(IpAddr::from_str("192.0.2.254").unwrap()).into());
        attributes
    }

    fn update_wire_body(withdrawn: &[u8], attributes: &[u8], announced: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
        body.extend_from_slice(withdrawn);
        body.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        body.extend_from_slice(attributes);
        body.extend_from_slice(announced);
        body
    }

    fn bgp4mp_update_wire(withdrawn: &[u8], attributes: &[u8], announced: &[u8]) -> Vec<u8> {
        let update_body = update_wire_body(withdrawn, attributes, announced);
        bgp4mp_message_wire(BgpMessageType::UPDATE, &update_body)
    }

    fn bgp4mp_route_refresh_wire(subtype: u8, orf_data: &[u8]) -> Vec<u8> {
        let mut refresh_body = vec![0x00, 0x01, subtype, 0x01];
        refresh_body.extend_from_slice(orf_data);
        bgp4mp_message_wire(BgpMessageType::ROUTE_REFRESH, &refresh_body)
    }

    fn bgp4mp_message_wire(msg_type: BgpMessageType, msg_body: &[u8]) -> Vec<u8> {
        let mut bgp_message = vec![0xff; 16];
        bgp_message.extend_from_slice(&((19 + msg_body.len()) as u16).to_be_bytes());
        bgp_message.push(msg_type as u8);
        bgp_message.extend_from_slice(msg_body);

        let mut body = Vec::new();
        body.extend_from_slice(&64496u32.to_be_bytes());
        body.extend_from_slice(&64497u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[192, 0, 2, 1]);
        body.extend_from_slice(&[192, 0, 2, 2]);
        body.extend_from_slice(&bgp_message);

        let header = CommonHeader {
            timestamp: 1_700_000_000,
            microsecond_timestamp: None,
            entry_type: EntryType::BGP4MP,
            entry_subtype: Bgp4MpType::MessageAs4 as u16,
            length: body.len() as u32,
        };
        let mut wire = header.encode().to_vec();
        wire.extend_from_slice(&body);
        wire
    }

    fn valid_update_attributes_wire() -> Vec<u8> {
        vec![
            0x40, 0x01, 0x01, 0x00, // ORIGIN = IGP
            0x40, 0x02, 0x00, // AS_PATH = empty
            0x40, 0x03, 0x04, 192, 0, 2, 254, // NEXT_HOP
        ]
    }

    fn assert_wire_validation(
        wire: Vec<u8>,
        expected_warning: impl Fn(&BgpValidationWarning) -> bool,
    ) {
        let mut iter = BgpkitParser::from_reader(Cursor::new(wire.clone())).into_diagnostic_iter();
        match iter.next().unwrap() {
            DiagnosticEvent::Validation {
                warnings,
                raw_record,
                ..
            } => {
                assert!(
                    warnings.iter().any(expected_warning),
                    "expected validation warning, got {warnings:?}"
                );
                assert_eq!(raw_record.raw_bytes().as_ref(), wire.as_slice());
            }
            event => panic!("expected validation event, got {event:?}"),
        }
        assert!(iter.next().is_none());
    }

    #[test]
    fn diagnostic_iterator_flags_unknown_route_refresh_subtype() {
        // RFC 7313 Section 5: subtype other than 0-2 is ignored on the wire
        let wire = bgp4mp_route_refresh_wire(3, &[]);
        assert_wire_validation(wire, |warning| {
            matches!(
                warning,
                BgpValidationWarning::UnknownRouteRefreshSubtype { subtype: 3 }
            )
        });
    }

    #[test]
    fn diagnostic_iterator_flags_borr_with_trailing_data() {
        // RFC 7313 Section 5: a BoRR/EoRR body must be exactly 4 bytes
        let wire = bgp4mp_route_refresh_wire(1, &[0xDE, 0xAD]);
        assert_wire_validation(wire, |warning| {
            matches!(
                warning,
                BgpValidationWarning::InvalidRouteRefreshLength {
                    subtype: 1,
                    length: 6
                }
            )
        });
    }

    #[test]
    fn diagnostic_iterator_passes_normal_route_refresh_with_orf_data_clean() {
        // A normal (subtype 0) refresh may carry ORF data (RFC 5291)
        let wire = bgp4mp_route_refresh_wire(0, &[0x01, 0x80, 0x00, 0x00]);
        let mut iter = BgpkitParser::from_reader(Cursor::new(wire)).into_diagnostic_iter();
        match iter.next().unwrap() {
            DiagnosticEvent::Record(record) => {
                assert!(matches!(
                    record.message,
                    MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(Bgp4MpMessage {
                        bgp_message: BgpMessage::RouteRefresh(_),
                        ..
                    }))
                ));
            }
            event => panic!("expected clean record event, got {event:?}"),
        }
        assert!(iter.next().is_none());
    }

    #[test]
    fn diagnostic_iterator_yields_clean_record() {
        let wire = update_record(valid_attributes()).encode().unwrap().to_vec();
        let mut iter = BgpkitParser::from_reader(Cursor::new(wire)).into_diagnostic_iter();

        assert!(matches!(iter.next(), Some(DiagnosticEvent::Record(_))));
        assert!(iter.next().is_none());
    }

    #[test]
    fn diagnostic_iterator_yields_validation_with_original_bytes() {
        let wire = update_record(Attributes::default())
            .encode()
            .unwrap()
            .to_vec();
        let mut iter = BgpkitParser::from_reader(Cursor::new(wire.clone())).into_diagnostic_iter();

        match iter.next().unwrap() {
            DiagnosticEvent::Validation {
                record,
                warnings,
                raw_record,
            } => {
                assert!(matches!(record.message, MrtMessage::Bgp4Mp(_)));
                assert!(warnings.iter().any(|warning| {
                    matches!(
                        warning,
                        BgpValidationWarning::MissingWellKnownAttribute {
                            attr_type: AttrType::ORIGIN
                        }
                    )
                }));
                assert_eq!(raw_record.raw_bytes().as_ref(), wire.as_slice());
            }
            event => panic!("expected validation event, got {event:?}"),
        }
    }

    #[test]
    fn diagnostic_iterator_preserves_body_error_and_continues() {
        let header = CommonHeader {
            timestamp: 2,
            microsecond_timestamp: None,
            entry_type: EntryType::TABLE_DUMP,
            entry_subtype: 0,
            length: 4,
        };
        let mut input = header.encode().to_vec();
        input.extend_from_slice(&[0xff; 4]);
        let invalid_record = input.clone();
        input.extend_from_slice(&update_record(valid_attributes()).encode().unwrap());

        let mut iter = BgpkitParser::from_reader(Cursor::new(input)).into_diagnostic_iter();
        match iter.next().unwrap() {
            DiagnosticEvent::ParseError {
                common_header,
                raw_bytes,
                ..
            } => {
                assert_eq!(common_header, Some(header));
                assert_eq!(raw_bytes.as_deref(), Some(invalid_record.as_slice()));
            }
            event => panic!("expected parse error event, got {event:?}"),
        }
        assert!(matches!(iter.next(), Some(DiagnosticEvent::Record(_))));
        assert!(iter.next().is_none());
    }

    #[test]
    fn diagnostic_iterator_preserves_partial_body_context() {
        let header = CommonHeader {
            timestamp: 3,
            microsecond_timestamp: None,
            entry_type: EntryType::BGP4MP,
            entry_subtype: 0,
            length: 4,
        };
        let mut input = header.encode().to_vec();
        input.extend_from_slice(&[0, 1]);

        match BgpkitParser::from_reader(Cursor::new(input.clone()))
            .into_diagnostic_iter()
            .next()
            .unwrap()
        {
            DiagnosticEvent::ParseError {
                common_header,
                raw_bytes,
                ..
            } => {
                assert_eq!(common_header, Some(header));
                assert_eq!(raw_bytes.as_deref(), Some(input.as_slice()));
            }
            event => panic!("expected parse error event, got {event:?}"),
        }
    }

    #[test]
    fn diagnostic_iterator_terminates_after_framing_error() {
        let header = CommonHeader {
            timestamp: 3,
            microsecond_timestamp: None,
            entry_type: EntryType::BGP4MP,
            entry_subtype: Bgp4MpType::MessageAs4 as u16,
            length: 16 * 1024 * 1024 + 1,
        };
        let mut input = header.encode().to_vec();
        input.extend_from_slice(&update_record(valid_attributes()).encode().unwrap());

        let mut iter = BgpkitParser::from_reader(Cursor::new(input)).into_diagnostic_iter();
        match iter.next().unwrap() {
            DiagnosticEvent::ParseError {
                common_header,
                raw_bytes,
                ..
            } => {
                assert_eq!(common_header, Some(header));
                assert_eq!(raw_bytes.as_deref(), Some(header.encode().as_ref()));
            }
            event => panic!("expected parse error event, got {event:?}"),
        }
        assert!(iter.next().is_none());
    }

    #[test]
    fn diagnostic_iterator_preserves_invalid_header_bytes() {
        let invalid_header = vec![
            0, 0, 0, 1, // timestamp
            0xff, 0xff, // unknown entry type
            0, 0, // subtype
            0, 0, 0, 0, // length
        ];

        match BgpkitParser::from_reader(Cursor::new(invalid_header.clone()))
            .into_diagnostic_iter()
            .next()
            .unwrap()
        {
            DiagnosticEvent::ParseError {
                common_header,
                raw_bytes,
                ..
            } => {
                assert!(common_header.is_none());
                assert_eq!(raw_bytes.as_deref(), Some(invalid_header.as_slice()));
            }
            event => panic!("expected parse error event, got {event:?}"),
        }
    }

    #[test]
    fn diagnostic_iterator_ignores_filters() {
        let wire = update_record(valid_attributes()).encode().unwrap().to_vec();
        let parser = BgpkitParser::from_reader(Cursor::new(wire))
            .add_filter("prefix", "198.51.100.0/24")
            .unwrap();

        assert!(matches!(
            parser.into_diagnostic_iter().next(),
            Some(DiagnosticEvent::Record(_))
        ));
    }

    #[test]
    fn diagnostic_iterator_reports_wire_level_nlri_warnings_and_continues() {
        let malformed_nlri = [0xc8, 0x01];
        let invalid_wire = bgp4mp_update_wire(
            &malformed_nlri,
            &valid_update_attributes_wire(),
            &malformed_nlri,
        );
        let mut input = invalid_wire.clone();
        input.extend_from_slice(&update_record(valid_attributes()).encode().unwrap());

        let mut iter = BgpkitParser::from_reader(Cursor::new(input)).into_diagnostic_iter();
        match iter.next().unwrap() {
            DiagnosticEvent::Validation {
                warnings,
                raw_record,
                ..
            } => {
                assert!(warnings.iter().any(|warning| {
                    matches!(
                        warning,
                        BgpValidationWarning::MalformedNlri {
                            nlri_type: "withdrawn",
                            raw_bytes,
                            ..
                        } if raw_bytes == &malformed_nlri
                    )
                }));
                assert!(warnings.iter().any(|warning| {
                    matches!(
                        warning,
                        BgpValidationWarning::MalformedNlri {
                            nlri_type: "announced",
                            raw_bytes,
                            ..
                        } if raw_bytes == &malformed_nlri
                    )
                }));
                assert_eq!(raw_record.raw_bytes().as_ref(), invalid_wire.as_slice());
            }
            event => panic!("expected validation event, got {event:?}"),
        }
        assert!(matches!(iter.next(), Some(DiagnosticEvent::Record(_))));
        assert!(iter.next().is_none());
    }

    #[test]
    fn diagnostic_iterator_reports_wire_level_attribute_warnings() {
        let announced = [0x18, 10, 0, 0];
        let mut flags_and_duplicate = valid_update_attributes_wire();
        flags_and_duplicate[0] = 0x80;
        flags_and_duplicate.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        assert_wire_validation(
            bgp4mp_update_wire(&[], &flags_and_duplicate, &announced),
            |warning| {
                matches!(
                    warning,
                    BgpValidationWarning::AttributeFlagsError {
                        attr_type: AttrType::ORIGIN,
                        ..
                    }
                )
            },
        );
        assert_wire_validation(
            bgp4mp_update_wire(&[], &flags_and_duplicate, &announced),
            |warning| {
                matches!(
                    warning,
                    BgpValidationWarning::DuplicateAttribute {
                        attr_type: AttrType::ORIGIN
                    }
                )
            },
        );

        let mut invalid_origin = valid_update_attributes_wire();
        invalid_origin[3] = 3;
        assert_wire_validation(
            bgp4mp_update_wire(&[], &invalid_origin, &announced),
            |warning| matches!(warning, BgpValidationWarning::MalformedAttributeList { .. }),
        );

        let malformed_as_path = vec![
            0x40, 0x01, 0x01, 0x00, // ORIGIN = IGP
            0x40, 0x02, 0x02, 0x02, 0x01, // AS_PATH segment lacks its ASN
            0x40, 0x03, 0x04, 192, 0, 2, 254, // NEXT_HOP
        ];
        assert_wire_validation(
            bgp4mp_update_wire(&[], &malformed_as_path, &announced),
            |warning| matches!(warning, BgpValidationWarning::MalformedAttributeList { .. }),
        );

        let invalid_next_hop = vec![
            0x40, 0x01, 0x01, 0x00, // ORIGIN = IGP
            0x40, 0x02, 0x00, // AS_PATH = empty
            0x40, 0x03, 0x03, 192, 0, 2, // NEXT_HOP has the wrong length
        ];
        assert_wire_validation(
            bgp4mp_update_wire(&[], &invalid_next_hop, &announced),
            |warning| {
                matches!(
                    warning,
                    BgpValidationWarning::AttributeLengthError {
                        attr_type: AttrType::NEXT_HOP,
                        ..
                    }
                )
            },
        );
    }

    #[test]
    fn diagnostic_iterator_collects_table_dump_batch_and_rib_warnings() {
        let table_dump_messages = vec![
            TableDumpMessage {
                view_number: 0,
                sequence_number: 1,
                prefix: NetworkPrefix::from_str("192.0.2.0/24").unwrap(),
                status: 1,
                originated_time: 1,
                peer_ip: IpAddr::from_str("192.0.2.1").unwrap(),
                peer_asn: Asn::new_16bit(64512),
                attributes: Attributes::default(),
            },
            TableDumpMessage {
                view_number: 0,
                sequence_number: 1,
                prefix: NetworkPrefix::from_str("198.51.100.0/24").unwrap(),
                status: 1,
                originated_time: 2,
                peer_ip: IpAddr::from_str("192.0.2.2").unwrap(),
                peer_asn: Asn::new_16bit(64513),
                attributes: Attributes::default(),
            },
        ];
        let table_dump_record = MrtRecord {
            common_header: CommonHeader {
                timestamp: 1,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP,
                entry_subtype: 1,
                length: 0,
            },
            message: MrtMessage::TableDumpMessageBatch(table_dump_messages),
        };
        let table_dump_wire = table_dump_record.encode().unwrap().to_vec();
        match BgpkitParser::from_reader(Cursor::new(table_dump_wire.clone()))
            .into_diagnostic_iter()
            .next()
            .unwrap()
        {
            DiagnosticEvent::Validation {
                record,
                warnings,
                raw_record,
            } => {
                assert!(matches!(
                    record.message,
                    MrtMessage::TableDumpMessageBatch(_)
                ));
                assert_eq!(warnings.len(), 6);
                assert_eq!(raw_record.raw_bytes().as_ref(), table_dump_wire.as_slice());
            }
            event => panic!("expected validation event, got {event:?}"),
        }

        let rib_record = MrtRecord {
            common_header: CommonHeader {
                timestamp: 2,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP_V2,
                entry_subtype: TableDumpV2Type::RibIpv4Unicast as u16,
                length: 0,
            },
            message: MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(RibAfiEntries {
                rib_type: TableDumpV2Type::RibIpv4Unicast,
                sequence_number: 1,
                prefix: NetworkPrefix::from_str("203.0.113.0/24").unwrap(),
                rib_entries: vec![RibEntry {
                    peer_index: 0,
                    originated_time: 1,
                    path_id: None,
                    attributes: Attributes::default(),
                }],
            })),
        };
        let rib_wire = rib_record.encode().unwrap().to_vec();
        match BgpkitParser::from_reader(Cursor::new(rib_wire.clone()))
            .into_diagnostic_iter()
            .next()
            .unwrap()
        {
            DiagnosticEvent::Validation {
                record,
                warnings,
                raw_record,
            } => {
                assert!(matches!(
                    record.message,
                    MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(_))
                ));
                assert_eq!(warnings.len(), 3);
                assert_eq!(raw_record.raw_bytes().as_ref(), rib_wire.as_slice());
            }
            event => panic!("expected validation event, got {event:?}"),
        }
    }
}
