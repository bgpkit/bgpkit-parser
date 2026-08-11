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
}

impl<R> DiagnosticIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        Self { parser }
    }
}

impl<R: Read> Iterator for DiagnosticIterator<R> {
    type Item = DiagnosticEvent;

    fn next(&mut self) -> Option<Self::Item> {
        // Text dumps have no MRT record boundary or raw MRT representation.
        if self.parser.text_dump_iter.is_some() {
            return None;
        }

        let raw_record = match chunk_mrt_record_with_context(&mut self.parser.reader) {
            Ok(raw_record) => raw_record,
            Err(error) if matches!(error.error, ParserError::EofExpected) => return None,
            Err(error) => {
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
}
