//! Record-level diagnostic iterator for malformed MRT data investigation.
//!
//! The iterator yields one event per record with the original raw bytes
//! always attached, so byte-level inspection (see
//! [`crate::parser::mrt::dissect`]) is possible for every record, not only
//! the anomalous ones. `Record` events carry the RFC 7606 validation
//! findings collected during parsing (empty when the record is clean);
//! `ParseError` events carry a best-effort partial dissection tree showing
//! how far the structure could be walked before the failure.
//!
//! For full Wireshark-style field trees on every record, upgrade the
//! iterator with [`DiagnosticIterator::with_dissection`].

use crate::error::{BgpValidationWarning, ParserError};
use crate::models::*;
use crate::parser::mrt::dissect::{dissect_mrt_bytes, dissect_mrt_record};
use crate::parser::mrt::mrt_record::{chunk_mrt_record_with_context, raw_record_uses_zebra_compat};
use crate::parser::mrt::RawMrtRecord;
use crate::parser::BgpkitParser;
use std::collections::HashMap;
use std::io::Read;

/// A record-level parsing outcome for malformed-data investigation.
#[derive(Debug)]
#[non_exhaustive]
pub enum DiagnosticEvent {
    /// A parsed record, with its raw bytes and any recoverable validation
    /// findings. An empty `warnings` vector means the record parsed clean.
    Record {
        /// The parsed MRT record.
        record: MrtRecord,
        /// The original MRT record bytes and header.
        raw: RawMrtRecord,
        /// RFC 7606 validation findings in record traversal order.
        warnings: Vec<BgpValidationWarning>,
    },
    /// A record that could not be fully parsed.
    ParseError {
        /// The parsing failure.
        error: ParserError,
        /// The MRT common header when framing completed successfully.
        common_header: Option<CommonHeader>,
        /// All bytes consumed for this record, when available.
        raw_bytes: Option<Vec<u8>>,
        /// Best-effort partial dissection tree: the fields that could be
        /// walked before the failure, showing where parsing stopped.
        partial: Option<DissectionNode>,
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

    /// Upgrade to an iterator that attaches a full dissection tree and
    /// byte spans to every event.
    ///
    /// This is the byte-inspection mode used by field-level tooling: each
    /// `Record` event gains a [`DissectionNode`] tree over the whole record
    /// (common header, BGP4MP subheader, embedded BGP message) and its
    /// warnings become [`SpannedWarning`]s anchored to the bytes they
    /// concern. Building the tree costs an extra walk per record, so it is
    /// opt-in and never paid by the lean iterator.
    pub fn with_dissection(self) -> DissectingDiagnosticIterator<R> {
        DissectingDiagnosticIterator { inner: self }
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
                    partial: error.bytes.as_deref().map(dissect_mrt_bytes),
                    raw_bytes: error.bytes,
                });
            }
        };

        let used_zebra_compat = raw_record_uses_zebra_compat(&raw_record);
        let record = match raw_record.clone().parse() {
            Ok(record) => record,
            Err(error) => {
                let raw_bytes = Some(raw_record.raw_bytes().to_vec());
                return Some(DiagnosticEvent::ParseError {
                    error,
                    common_header: Some(raw_record.common_header),
                    partial: raw_bytes.as_deref().map(dissect_mrt_bytes),
                    raw_bytes,
                });
            }
        };
        if used_zebra_compat {
            self.parser.warn_zebra_compat_once();
        }

        let warnings = record_validation_warnings(&record);
        Some(DiagnosticEvent::Record {
            record,
            raw: raw_record,
            warnings,
        })
    }
}

/// A record-level diagnostic with a full dissection tree attached.
#[derive(Debug)]
// The tree-carrying Record variant is intentionally the largest and the most
// common outcome; boxing its fields would add indirection to every consumer.
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
pub enum DissectedDiagnosticEvent {
    /// A parsed record with its dissection tree and spanned warnings.
    Record {
        /// The parsed MRT record.
        record: MrtRecord,
        /// The original MRT record bytes and header.
        raw: RawMrtRecord,
        /// Validation findings anchored to the byte ranges they concern.
        warnings: Vec<SpannedWarning>,
        /// Wireshark-style field tree over the whole record.
        tree: DissectionNode,
    },
    /// A record that could not be fully parsed; `partial` shows how far the
    /// structure could be walked.
    ParseError {
        /// The parsing failure.
        error: ParserError,
        /// The MRT common header when framing completed successfully.
        common_header: Option<CommonHeader>,
        /// All bytes consumed for this record, when available.
        raw_bytes: Option<Vec<u8>>,
        /// Best-effort partial dissection tree.
        partial: Option<DissectionNode>,
    },
}

/// Iterator produced by [`DiagnosticIterator::with_dissection`].
pub struct DissectingDiagnosticIterator<R> {
    inner: DiagnosticIterator<R>,
}

impl<R: Read> Iterator for DissectingDiagnosticIterator<R> {
    type Item = DissectedDiagnosticEvent;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|event| match event {
            DiagnosticEvent::Record {
                record,
                raw,
                warnings,
            } => {
                let tree = dissect_mrt_record(&raw);
                let warnings = span_record_warnings(&warnings, &tree);
                DissectedDiagnosticEvent::Record {
                    record,
                    raw,
                    warnings,
                    tree,
                }
            }
            DiagnosticEvent::ParseError {
                error,
                common_header,
                raw_bytes,
                partial,
            } => DissectedDiagnosticEvent::ParseError {
                error,
                common_header,
                raw_bytes,
                partial,
            },
        })
    }
}

/// Collect the RFC 7606 validation findings of an MRT record.
///
/// This is the taxonomy walk the [`DiagnosticIterator`] applies per record;
/// it is public so custom investigation pipelines can reuse it.
pub fn record_validation_warnings(record: &MrtRecord) -> Vec<BgpValidationWarning> {
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

/// Anchor validation warnings to the byte ranges they concern.
///
/// The parser does not track offsets on its hot path, so spans are
/// correlated here against the dissection tree: attribute-keyed warnings
/// point at the matching `bgp.attr.{code}` node (the Nth occurrence for
/// duplicate attributes), NLRI warnings at the NLRI section, and everything
/// else falls back to the enclosing section or the whole record.
pub fn span_record_warnings(
    warnings: &[BgpValidationWarning],
    tree: &DissectionNode,
) -> Vec<SpannedWarning> {
    let mut duplicate_counts: HashMap<u8, usize> = HashMap::new();
    warnings
        .iter()
        .map(|warning| SpannedWarning {
            span: locate_warning_span(warning, tree, &mut duplicate_counts),
            warning: warning.clone(),
        })
        .collect()
}

fn locate_warning_span(
    warning: &BgpValidationWarning,
    tree: &DissectionNode,
    duplicate_counts: &mut HashMap<u8, usize>,
) -> Span {
    use BgpValidationWarning as W;

    let attr_span = |code: u8, occurrence: usize| -> Option<Span> {
        let mut nodes = Vec::new();
        tree.find_all(&format!("bgp.attr.{code}"), &mut nodes);
        nodes.get(occurrence).map(|node| node.span())
    };
    let section_span = |field: &str| -> Option<Span> { tree.find(field).map(|node| node.span()) };

    let span = match warning {
        W::AttributeFlagsError { attr_type, .. }
        | W::AttributeLengthError { attr_type, .. }
        | W::OptionalAttributeError { attr_type, .. }
        | W::PartialAttributeError { attr_type, .. } => attr_span(u8::from(*attr_type), 0)
            .or_else(|| section_span("bgp.update.path_attributes")),
        W::DuplicateAttribute { attr_type } => {
            let code = u8::from(*attr_type);
            let count = duplicate_counts.entry(code).or_insert(0);
            *count += 1;
            attr_span(code, *count).or_else(|| section_span("bgp.update.path_attributes"))
        }
        W::InvalidOriginAttribute { .. } => attr_span(1, 0),
        W::InvalidNextHopAttribute { .. } => attr_span(3, 0),
        W::MalformedAsPath { .. } => attr_span(2, 0),
        W::UnrecognizedWellKnownAttribute { attr_type_code } => attr_span(*attr_type_code, 0),
        W::MissingWellKnownAttribute { .. } | W::MalformedAttributeList { .. } => {
            section_span("bgp.update.path_attributes")
        }
        W::InvalidNetworkField { .. } => {
            section_span("bgp.update.nlri").or_else(|| section_span("bgp.update.withdrawn_routes"))
        }
        W::MalformedNlri { nlri_type, .. } => match *nlri_type {
            "withdrawn" => section_span("bgp.update.withdrawn_routes"),
            "announced" => section_span("bgp.update.nlri"),
            "mp_reach" => attr_span(14, 0),
            "mp_unreach" => attr_span(15, 0),
            _ => None,
        },
        W::UnknownRouteRefreshSubtype { .. } | W::InvalidRouteRefreshLength { .. } => {
            section_span("bgp.route_refresh")
        }
    };
    span.unwrap_or_else(|| tree.span())
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
        attributes.add_attr(AttributeValue::AsPath(AsPath::from_sequence([64500])).into());
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
            DiagnosticEvent::Record { warnings, raw, .. } => {
                assert!(
                    warnings.iter().any(expected_warning),
                    "expected validation warning, got {warnings:?}"
                );
                assert_eq!(raw.raw_bytes().as_ref(), wire.as_slice());
            }
            event => panic!("expected record event with warnings, got {event:?}"),
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
            DiagnosticEvent::Record {
                record, warnings, ..
            } => {
                assert!(warnings.is_empty());
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

        match iter.next().unwrap() {
            DiagnosticEvent::Record {
                record, warnings, ..
            } => {
                assert!(warnings.is_empty());
                assert!(matches!(record.message, MrtMessage::Bgp4Mp(_)));
            }
            event => panic!("expected clean record event, got {event:?}"),
        }
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
            DiagnosticEvent::Record {
                record,
                warnings,
                raw,
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
                assert_eq!(raw.raw_bytes().as_ref(), wire.as_slice());
            }
            event => panic!("expected record event with warnings, got {event:?}"),
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
        assert!(matches!(iter.next(), Some(DiagnosticEvent::Record { .. })));
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
    fn diagnostic_iterator_parse_error_carries_partial_tree() {
        // A BGP4MP record whose UPDATE body is truncated: the partial tree
        // must still walk the header, subheader, and BGP message header.
        let mut bgp = vec![0xFF; 16];
        bgp.extend_from_slice(&21u16.to_be_bytes()); // claims 2 body bytes
        bgp.push(2);
        bgp.extend_from_slice(&[0x00]); // only 1 of 2 withdrawn-length bytes

        let mut body = Vec::new();
        body.extend_from_slice(&64496u32.to_be_bytes());
        body.extend_from_slice(&64497u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[192, 0, 2, 1]);
        body.extend_from_slice(&[192, 0, 2, 2]);
        body.extend_from_slice(&bgp);

        let mut wire = CommonHeader {
            timestamp: 1,
            microsecond_timestamp: None,
            entry_type: EntryType::BGP4MP,
            entry_subtype: Bgp4MpType::MessageAs4 as u16,
            length: body.len() as u32,
        }
        .encode()
        .to_vec();
        wire.extend_from_slice(&body);

        match BgpkitParser::from_reader(Cursor::new(wire))
            .into_diagnostic_iter()
            .next()
            .unwrap()
        {
            DiagnosticEvent::ParseError { partial, .. } => {
                let partial = partial.expect("partial tree on parse error");
                assert!(partial.find("mrt.header.type").is_some());
                assert!(partial.find("mrt.bgp4mp.peer_asn").is_some());
                assert!(partial.find("bgp.header.marker").is_some());
                assert!(partial.find("bgp.update.path_attributes").is_none());
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
                partial,
                ..
            } => {
                assert_eq!(common_header, None);
                assert_eq!(raw_bytes.as_deref(), Some(invalid_header.as_slice()));
                // The bytes still frame a 12-byte header, so the partial tree
                // walks the header fields but nothing beyond them.
                let partial = partial.unwrap();
                assert!(partial.find("mrt.header.type").is_some());
                assert!(partial.find("mrt.body").is_none());
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
            Some(DiagnosticEvent::Record { .. })
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
            DiagnosticEvent::Record { warnings, raw, .. } => {
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
                assert_eq!(raw.raw_bytes().as_ref(), invalid_wire.as_slice());
            }
            event => panic!("expected record event with warnings, got {event:?}"),
        }
        assert!(matches!(iter.next(), Some(DiagnosticEvent::Record { .. })));
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
            DiagnosticEvent::Record {
                record, warnings, ..
            } => {
                assert!(matches!(
                    record.message,
                    MrtMessage::TableDumpMessageBatch(_)
                ));
                assert_eq!(warnings.len(), 6);
            }
            event => panic!("expected record event, got {event:?}"),
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
        match BgpkitParser::from_reader(Cursor::new(rib_wire))
            .into_diagnostic_iter()
            .next()
            .unwrap()
        {
            DiagnosticEvent::Record { warnings, .. } => {
                assert_eq!(warnings.len(), 3);
            }
            event => panic!("expected record event, got {event:?}"),
        }
    }

    #[test]
    fn with_dissection_attaches_tree_and_spans() {
        // Attribute flags error on ORIGIN: the spanned warning must point at
        // the first ORIGIN attribute node's byte range.
        let announced = [0x18, 10, 0, 0];
        let mut bad_flags = valid_update_attributes_wire();
        bad_flags[0] = 0x80;
        let wire = bgp4mp_update_wire(&[], &bad_flags, &announced);

        let mut iter = BgpkitParser::from_reader(Cursor::new(wire))
            .into_diagnostic_iter()
            .with_dissection();
        match iter.next().unwrap() {
            DissectedDiagnosticEvent::Record { warnings, tree, .. } => {
                // MRT header, BGP4MP subheader, and BGP layers all present
                assert!(tree.find("mrt.header.type").is_some());
                assert!(tree.find("mrt.bgp4mp.peer_asn").is_some());
                assert!(tree.find("bgp.header.type").is_some());
                assert!(tree.find("bgp.attr.1").is_some());

                let origin = tree.find("bgp.attr.1").unwrap();
                assert_eq!(warnings.len(), 1);
                assert!(matches!(
                    warnings[0].warning,
                    BgpValidationWarning::AttributeFlagsError { .. }
                ));
                assert_eq!(warnings[0].span, origin.span());
            }
            event => panic!("expected dissected record event, got {event:?}"),
        }
    }

    #[test]
    fn with_dissection_spans_nlri_warning() {
        let malformed_nlri = [0xc8, 0x01];
        let mut body = Vec::new();
        body.extend_from_slice(&(malformed_nlri.len() as u16).to_be_bytes());
        body.extend_from_slice(&malformed_nlri);
        body.extend_from_slice(&(valid_update_attributes_wire().len() as u16).to_be_bytes());
        body.extend_from_slice(&valid_update_attributes_wire());
        let wire = bgp4mp_message_wire(BgpMessageType::UPDATE, &body);

        let mut iter = BgpkitParser::from_reader(Cursor::new(wire))
            .into_diagnostic_iter()
            .with_dissection();
        match iter.next().unwrap() {
            DissectedDiagnosticEvent::Record { warnings, tree, .. } => {
                let withdrawn = tree.find("bgp.update.withdrawn_routes").unwrap();
                let warning = warnings
                    .iter()
                    .find(|w| {
                        matches!(
                            w.warning,
                            BgpValidationWarning::MalformedNlri {
                                nlri_type: "withdrawn",
                                ..
                            }
                        )
                    })
                    .expect("withdrawn NLRI warning");
                assert_eq!(warning.span, withdrawn.span());
            }
            event => panic!("expected dissected record event, got {event:?}"),
        }
    }
}
