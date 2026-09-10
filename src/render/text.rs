//! Layered text rendering of MRT records.
//!
//! One record becomes one indented block: session context
//! (`TIME`/`TYPE`/`PEER`/`LOCAL`), then the message body — `UPDATE:` sections
//! for withdrawn/announced prefixes and every path attribute, `OPEN:`
//! capabilities, session states, RIB entries, or the peer table. RFC 7606
//! validation findings appear under `WARNINGS:` when present.
//!
//! The layout is our own (built from this crate's `Display` vocabulary);
//! inspired by bgpdump's human-readable output, not byte-compatible with
//! it.
//!
//! [`Style::ansi`] adds terminal colors for labels, section headers,
//! prefixes, and next hops; the plain blocks are unchanged by it, since
//! styling is a post-pass over the rendered text rather than part of it.

use crate::models::*;

const INDENT: &str = "  ";

/// Render a record block with a trailing `HEX:` line carrying the raw
/// bytes (e.g. from [`crate::render::hex::encode`]), so the block
/// can be pasted straight into a byte-level dissector.
pub fn format_record_with_hex(record: &MrtRecord, hex: &str) -> String {
    let mut out = format_record(record);
    out.push_str(&format!("{INDENT}HEX: {hex}\n"));
    out
}

/// Render one MRT record as a layered text block.
///
/// Pure function of the record; see the [module docs](self) for scope and
/// limitations (RIB peer indices, warning anchoring).
pub fn format_record(record: &MrtRecord) -> String {
    let mut out = String::with_capacity(512);
    let ts = match record.common_header.microsecond_timestamp {
        Some(us) => format!("{}.{:06}", record.common_header.timestamp, us),
        None => record.common_header.timestamp.to_string(),
    };
    out.push_str(&format!("TIME: {ts}\n"));
    out.push_str(&format!(
        "TYPE: {:?}/{}\n",
        record.common_header.entry_type,
        entry_subtype_name(record)
    ));

    match &record.message {
        MrtMessage::Bgp4Mp(msg) => render_bgp4mp(&mut out, msg),
        MrtMessage::LegacyBgp(msg) => render_legacy_bgp(&mut out, msg),
        MrtMessage::TableDumpMessage(msg) => render_table_dump(&mut out, msg),
        MrtMessage::TableDumpMessageBatch(messages) => {
            out.push_str(&format!("TABLE_DUMP: {} entries\n", messages.len()));
            for msg in messages {
                render_table_dump(&mut out, msg);
            }
        }
        MrtMessage::TableDumpV2Message(msg) => render_table_dump_v2(&mut out, msg),
    }
    out
}

/// ANSI styling for the text format.
///
/// Accents are drawn from the basic ANSI set (bold where noted) instead of fixed RGB values, so
/// they follow the reader's terminal theme and stay legible on light and dark backgrounds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Style {
    ansi: bool,
}

impl Style {
    /// Plain text, no escape sequences (the default).
    pub const fn plain() -> Self {
        Self { ansi: false }
    }

    /// ANSI SGR accents, for a terminal.
    pub const fn ansi() -> Self {
        Self { ansi: true }
    }
}

const ANSI_LABEL: &str = "\x1b[1;34m";
const ANSI_SECTION: &str = "\x1b[1;35m";
const ANSI_PREFIX: &str = "\x1b[32m";
const ANSI_NEXT_HOP: &str = "\x1b[33m";
const ANSI_RESET: &str = "\x1b[0m";

/// Headers whose indented lines are prefix lists.
const PREFIX_SECTIONS: [&str; 3] = ["WITHDRAWN", "ANNOUNCED", "ANNOUNCED (labeled)"];
/// Headers rendered in the section accent; every other `NAME: value` line is a property.
const SECTION_LABELS: [&str; 17] = [
    "UPDATE",
    "OPEN",
    "KEEPALIVE",
    "NOTIFICATION",
    "ROUTE_REFRESH",
    "STATE_CHANGE",
    "ATTRIBUTES",
    "WARNINGS",
    "CAPABILITIES",
    "LINK_STATE_NLRI",
    "FLOWSPEC_NLRI",
    "TABLE_DUMP",
    "PEER_INDEX_TABLE",
    "GEO_PEER_TABLE",
    "RIB_ENTRY",
    "RIB_AFI",
    "RIB_GENERIC",
];
/// Properties whose value is a next hop.
const NEXT_HOP_LABELS: [&str; 2] = ["NEXT_HOP", "MP_REACH_NLRI"];
/// Properties whose value is a prefix (table-dump RIB entries label it instead of listing it).
const PREFIX_LABELS: [&str; 1] = ["PREFIX"];

/// Render one MRT record as a layered text block, styled for a terminal.
///
/// Styling is applied to the block [`format_record`] produces, so the text itself (and the
/// unstyled output) is unaffected.
pub fn format_record_with_style(record: &MrtRecord, style: Style) -> String {
    let plain = format_record(record);
    if style.ansi {
        colorize(&plain)
    } else {
        plain
    }
}

/// Render a record block with a trailing `HEX:` line (see [`format_record_with_hex`]),
/// styled for a terminal.
pub fn format_record_with_hex_and_style(record: &MrtRecord, hex: &str, style: Style) -> String {
    let plain = format_record_with_hex(record, hex);
    if style.ansi {
        colorize(&plain)
    } else {
        plain
    }
}

/// Accent the labels, section headers, prefixes and next hops of a plain block.
///
/// A line that matches nothing is copied through untouched, so a newly added line can only lose
/// its accent, never gain broken output.
fn colorize(plain: &str) -> String {
    let mut out = String::with_capacity(plain.len() + plain.len() / 4);
    let mut prefix_section = false;
    for line in plain.split_inclusive('\n') {
        let (content, newline) = match line.strip_suffix('\n') {
            Some(content) => (content, "\n"),
            None => (line, ""),
        };
        let trimmed = content.trim_start();
        let indent = content.len() - trimmed.len();
        let painted = if trimmed.is_empty() {
            None
        } else if indent >= 4 && prefix_section {
            // prefix entries only; they carry colons of their own inside IPv6 addresses
            Some(format!("{ANSI_PREFIX}{trimmed}{ANSI_RESET}"))
        } else if let Some((label, value)) = trimmed.split_once(':') {
            let label = label.trim_end();
            let value = value.strip_prefix(' ').unwrap_or(value);
            if value.is_empty() {
                prefix_section = PREFIX_SECTIONS.contains(&label);
                let accent = if prefix_section || SECTION_LABELS.contains(&label) {
                    ANSI_SECTION
                } else {
                    ANSI_LABEL
                };
                Some(format!("{accent}{label}:{ANSI_RESET}"))
            } else if SECTION_LABELS.contains(&label) {
                // RIB_AFI/RIB_GENERIC summaries carry `PREFIX: <prefix>` inside the heading
                Some(match value.split_once("PREFIX: ") {
                    Some((head, tail)) => {
                        let (prefix, rest) = tail.split_once(' ').unwrap_or((tail, ""));
                        let rest = match rest.is_empty() {
                            true => String::new(),
                            false => format!(" {rest}"),
                        };
                        format!(
                            "{ANSI_SECTION}{label}:{ANSI_RESET} {head}PREFIX: {ANSI_PREFIX}{prefix}{ANSI_RESET}{rest}"
                        )
                    }
                    None => format!("{ANSI_SECTION}{label}:{ANSI_RESET} {value}"),
                })
            } else if PREFIX_LABELS.contains(&label) {
                Some(format!(
                    "{ANSI_LABEL}{label}:{ANSI_RESET} {ANSI_PREFIX}{value}{ANSI_RESET}"
                ))
            } else if NEXT_HOP_LABELS.contains(&label) {
                Some(format!(
                    "{ANSI_LABEL}{label}:{ANSI_RESET} {ANSI_NEXT_HOP}{value}{ANSI_RESET}"
                ))
            } else if !label.contains(' ') {
                Some(format!("{ANSI_LABEL}{label}:{ANSI_RESET} {value}"))
            } else {
                // a sentence (e.g. a validation warning), not an identifier
                None
            }
        } else {
            None
        };
        match painted {
            Some(painted) => {
                out.push_str(&" ".repeat(indent));
                out.push_str(&painted);
            }
            None => out.push_str(content),
        }
        out.push_str(newline);
    }
    out
}

fn render_legacy_bgp(out: &mut String, msg: &LegacyBgp) {
    // Deprecated MRT type-5 records (RFC 6396 Appendix B) carry the same
    // endpoint metadata and BGP payloads as BGP4MP; render them fully.
    match msg {
        LegacyBgp::Message(m) => {
            out.push_str(&format!(
                "PEER: {} AS{}\nLOCAL: {} AS{}\n",
                m.peer_ip, m.peer_asn, m.local_ip, m.local_asn
            ));
            render_bgp_message(out, &m.bgp_message);
        }
        LegacyBgp::StateChange(m) => {
            out.push_str(&format!("PEER: {} AS{}\n", m.peer_ip, m.peer_asn));
            out.push_str("STATE_CHANGE:\n");
            out.push_str(&format!(
                "{INDENT}OLD_STATE: {:?}\n{INDENT}NEW_STATE: {:?}\n",
                m.old_state, m.new_state
            ));
        }
    }
}

fn entry_subtype_name(record: &MrtRecord) -> String {
    match &record.message {
        MrtMessage::Bgp4Mp(msg) => format!("{:?}", msg.msg_type()),
        _ => record.common_header.entry_subtype.to_string(),
    }
}

fn render_bgp4mp(out: &mut String, msg: &Bgp4MpEnum) {
    match msg {
        Bgp4MpEnum::StateChange(m) => {
            out.push_str(&format!(
                "PEER: {} AS{}\nLOCAL: {} AS{}\n",
                m.peer_ip, m.peer_asn, m.local_addr, m.local_asn
            ));
            out.push_str("STATE_CHANGE:\n");
            out.push_str(&format!(
                "{INDENT}OLD_STATE: {:?}\n{INDENT}NEW_STATE: {:?}\n",
                m.old_state, m.new_state
            ));
        }
        Bgp4MpEnum::Message(m) => {
            out.push_str(&format!(
                "PEER: {} AS{}\nLOCAL: {} AS{}\n",
                m.peer_ip, m.peer_asn, m.local_ip, m.local_asn
            ));
            render_bgp_message(out, &m.bgp_message);
        }
    }
}

fn render_bgp_message(out: &mut String, msg: &BgpMessage) {
    match msg {
        BgpMessage::Open(open) => {
            out.push_str("OPEN:\n");
            out.push_str(&format!(
                "{INDENT}VERSION: {}\n{INDENT}MY_AS: {}\n{INDENT}HOLD_TIME: {}s\n{INDENT}BGP_ID: {}\n",
                open.version, open.asn, open.hold_time, open.bgp_identifier
            ));
            if open.opt_params.is_empty() {
                return;
            }
            out.push_str(&format!("{INDENT}CAPABILITIES:\n"));
            for param in &open.opt_params {
                if let ParamValue::Capacities(caps) = &param.param_value {
                    for cap in caps {
                        out.push_str(&format!("{INDENT}{INDENT}{}\n", capability_summary(cap)));
                    }
                }
            }
        }
        BgpMessage::Update(update) => {
            out.push_str("UPDATE:\n");
            render_update(out, update);
        }
        BgpMessage::Notification(n) => {
            out.push_str("NOTIFICATION:\n");
            out.push_str(&format!(
                "{INDENT}ERROR: {:?} ({} bytes of data)\n",
                n.error,
                n.data.len()
            ));
        }
        BgpMessage::KeepAlive => {
            out.push_str("KEEPALIVE:\n");
        }
        BgpMessage::RouteRefresh(r) => {
            out.push_str("ROUTE_REFRESH:\n");
            out.push_str(&format!(
                "{INDENT}AFI: {} SAFI: {} SUBTYPE: {}\n",
                r.afi, r.safi, r.subtype
            ));
        }
    }
}

fn capability_summary(cap: &Capability) -> String {
    match &cap.value {
        CapabilityValue::MultiprotocolExtensions(mp) => {
            format!("{:?}: {:?}/{:?}", cap.ty, mp.afi, mp.safi)
        }
        CapabilityValue::FourOctetAs(foa) => format!("{:?}: AS{}", cap.ty, foa.asn),
        CapabilityValue::AddPath(ap) => format!(
            "{:?}: {} address families",
            cap.ty,
            ap.address_families.len()
        ),
        _ => format!("{:?}", cap.ty),
    }
}

fn render_update(out: &mut String, update: &BgpUpdateMessage) {
    // Withdrawn prefixes: the standard field plus any carried in
    // MP_UNREACH_NLRI, so the transcript never silently drops routes.
    // Labeled (MPLS) announcements, link-state NLRI, and FlowSpec rules
    // live in their own MP collections and get dedicated sections.
    let mut withdrawn: Vec<&NetworkPrefix> = update.withdrawn_prefixes.iter().collect();
    let mut announced: Vec<&NetworkPrefix> = update.announced_prefixes.iter().collect();
    let mut labeled_announced: Vec<&LabeledNetworkPrefix> = Vec::new();
    let mut link_state_count = 0usize;
    let mut flowspec_count = 0usize;
    for attr in update.attributes.iter() {
        match attr {
            AttributeValue::MpUnreachNlri(nlri) => {
                withdrawn.extend(nlri.prefixes.iter());
                link_state_count += nlri.link_state_nlris.as_ref().map_or(0, Vec::len);
                flowspec_count += nlri.flowspec_nlris.as_ref().map_or(0, Vec::len);
            }
            AttributeValue::MpReachNlri(nlri) => {
                announced.extend(nlri.prefixes.iter());
                labeled_announced.extend(nlri.labeled_prefixes.iter().flatten());
                link_state_count += nlri.link_state_nlris.as_ref().map_or(0, Vec::len);
                flowspec_count += nlri.flowspec_nlris.as_ref().map_or(0, Vec::len);
            }
            _ => {}
        }
    }

    if !withdrawn.is_empty() {
        out.push_str(&format!("{INDENT}WITHDRAWN:\n"));
        for prefix in withdrawn {
            out.push_str(&format!("{INDENT}{INDENT}{prefix}\n"));
        }
    }
    if !announced.is_empty() {
        out.push_str(&format!("{INDENT}ANNOUNCED:\n"));
        for prefix in announced {
            out.push_str(&format!("{INDENT}{INDENT}{prefix}\n"));
        }
    }
    if !labeled_announced.is_empty() {
        // RFC 3107/8277 labeled routes; withdrawals carry no labels and
        // arrive through the plain prefix lists above.
        out.push_str(&format!("{INDENT}ANNOUNCED (labeled):\n"));
        for labeled in labeled_announced {
            let labels: Vec<String> = labeled
                .labels
                .iter()
                .map(|label| label.value().to_string())
                .collect();
            let path_id = labeled
                .path_id
                .map_or_else(String::new, |id| format!(" path-id {id}"));
            out.push_str(&format!(
                "{INDENT}{INDENT}{} labels=[{}]{path_id}\n",
                labeled.prefix,
                labels.join(", ")
            ));
        }
    }
    if link_state_count > 0 {
        out.push_str(&format!(
            "{INDENT}LINK_STATE_NLRI: {link_state_count} entries (BGP-LS)\n"
        ));
    }
    if flowspec_count > 0 {
        out.push_str(&format!(
            "{INDENT}FLOWSPEC_NLRI: {flowspec_count} rules (RFC 8955)\n"
        ));
    }

    let mut attrs = update.attributes.iter().peekable();
    if attrs.peek().is_some() {
        out.push_str(&format!("{INDENT}ATTRIBUTES:\n"));
        for attr in attrs {
            if let Some(line) = render_attribute(attr) {
                out.push_str(&format!("{INDENT}{INDENT}{line}\n"));
            }
        }
    }

    let warnings = update.attributes.validation_warnings();
    if !warnings.is_empty() {
        out.push_str(&format!("{INDENT}WARNINGS:\n"));
        for warning in warnings {
            out.push_str(&format!("{INDENT}{INDENT}{warning}\n"));
        }
    }
}

/// One line per attribute. The MP prefix lists are folded into the
/// WITHDRAWN/ANNOUNCED sections above; the attribute summary line (family,
/// next hop) is retained here.
fn render_attribute(value: &AttributeValue) -> Option<String> {
    let line = match value {
        AttributeValue::Origin(v) => format!("ORIGIN: {v}"),
        AttributeValue::AsPath(v) => format!("AS_PATH: {v}"),
        AttributeValue::As4Path(v) => format!("AS4_PATH: {v}"),
        AttributeValue::NextHop(v) => format!("NEXT_HOP: {v}"),
        AttributeValue::MultiExitDiscriminator(v) => format!("MULTI_EXIT_DISC: {v}"),
        AttributeValue::LocalPreference(v) => format!("LOCAL_PREF: {v}"),
        AttributeValue::OnlyToCustomer(v) => format!("ONLY_TO_CUSTOMER: {v}"),
        AttributeValue::AtomicAggregate => "ATOMIC_AGGREGATE".to_string(),
        AttributeValue::Aggregator { asn, id } => format!("AGGREGATOR: AS{asn} by {id}"),
        AttributeValue::As4Aggregator { asn, id } => {
            format!("AS4_AGGREGATOR: AS{asn} by {id}")
        }
        AttributeValue::Communities(v) => {
            let rendered: Vec<String> = v.iter().map(|c| c.to_string()).collect();
            format!("COMMUNITIES: {}", rendered.join(" "))
        }
        AttributeValue::LargeCommunities(v) => {
            let rendered: Vec<String> = v.iter().map(|c| c.to_string()).collect();
            format!("LARGE_COMMUNITIES: {}", rendered.join(" "))
        }
        AttributeValue::ExtendedCommunities(v) => {
            let rendered: Vec<String> = v.iter().map(|c| c.to_string()).collect();
            format!("EXTENDED_COMMUNITIES: {}", rendered.join(" "))
        }
        AttributeValue::Ipv6AddressSpecificExtendedCommunities(v) => {
            let rendered: Vec<String> = v.iter().map(|c| c.to_string()).collect();
            format!("IPV6_EXTENDED_COMMUNITIES: {}", rendered.join(" "))
        }
        AttributeValue::OriginatorId(v) => format!("ORIGINATOR_ID: {v}"),
        AttributeValue::Clusters(v) => {
            let rendered: Vec<String> = v.iter().map(|c| c.to_string()).collect();
            format!("CLUSTER_LIST: {}", rendered.join(" "))
        }
        AttributeValue::MpReachNlri(nlri) => {
            let next_hop = match &nlri.next_hop {
                Some(nh) => format!(" next-hop {nh}"),
                None => String::new(),
            };
            format!("MP_REACH_NLRI: {:?}/{:?}{next_hop}", nlri.afi, nlri.safi)
        }
        AttributeValue::MpUnreachNlri(nlri) => {
            format!("MP_UNREACH_NLRI: {:?}/{:?}", nlri.afi, nlri.safi)
        }
        AttributeValue::Aigp(v) => format!("AIGP: {v:?}"),
        AttributeValue::BfdDiscriminator(v) => format!("BFD_DISCRIMINATOR: {v:?}"),
        AttributeValue::TrafficEngineering(v) => format!("TRAFFIC_ENGINEERING: {v:?}"),
        AttributeValue::TunnelEncapsulation(v) => format!("TUNNEL_ENCAPSULATION: {v:?}"),
        AttributeValue::LinkState(v) => format!("BGP_LS: {v:?}"),
        AttributeValue::BgpPrefixSid(v) => format!("BGP_PREFIX_SID: {v:?}"),
        AttributeValue::Bier(v) => format!("BIER: {v:?}"),
        AttributeValue::Sfp(v) => format!("SFP: {v:?}"),
        AttributeValue::AttrSet(v) => {
            format!("ATTR_SET: attributes of AS{}", v.origin_as)
        }
        AttributeValue::Development(v) => format!("DEVELOPMENT: {} bytes", v.len()),
        AttributeValue::Raw(v) => {
            format!("RAW ATTRIBUTE (type {}): {} bytes", v.code, v.bytes.len())
        }
        AttributeValue::Deprecated(v) => {
            format!("DEPRECATED (type {}): {} bytes", v.code, v.bytes.len())
        }
        AttributeValue::Unknown(v) => {
            format!("UNKNOWN (type {}): {} bytes", v.code, v.bytes.len())
        }
    };
    Some(line)
}

fn render_table_dump(out: &mut String, msg: &TableDumpMessage) {
    out.push_str(&format!(
        "RIB_ENTRY:\n{INDENT}PREFIX: {}\n{INDENT}PEER: {} AS{}\n{INDENT}ORIGINATED: {}\n",
        msg.prefix, msg.peer_ip, msg.peer_asn, msg.originated_time
    ));
    render_attributes_block(out, &msg.attributes, 1);
}

fn render_table_dump_v2(out: &mut String, msg: &TableDumpV2Message) {
    match msg {
        TableDumpV2Message::PeerIndexTable(pit) => {
            out.push_str(&format!(
                "PEER_INDEX_TABLE: {} peers\n",
                pit.id_peer_map.len()
            ));
            // Peer order follows the collector's index assignment.
            let mut peers: Vec<_> = pit.id_peer_map.iter().collect();
            peers.sort_by_key(|(id, _)| **id);
            for (id, peer) in peers {
                out.push_str(&format!(
                    "{INDENT}PEER[{id}]: {} AS{}\n",
                    peer.peer_ip, peer.peer_asn
                ));
            }
        }
        TableDumpV2Message::RibAfi(rib) => {
            out.push_str(&format!(
                "RIB_AFI: {:?} PREFIX: {} ({} entries)\n",
                rib.rib_type,
                rib.prefix,
                rib.rib_entries.len()
            ));
            for entry in &rib.rib_entries {
                out.push_str(&format!(
                    "{INDENT}RIB_ENTRY:\n{INDENT}{INDENT}PEER_INDEX: {}\n{INDENT}{INDENT}ORIGINATED: {}\n",
                    entry.peer_index, entry.originated_time
                ));
                render_attributes_block(out, &entry.attributes, 2);
            }
        }
        TableDumpV2Message::RibGeneric(rib) => {
            out.push_str(&format!(
                "RIB_GENERIC: {:?}/{:?} PREFIX: {} ({} entries)\n",
                rib.afi,
                rib.safi,
                rib.nlri,
                rib.rib_entries.len()
            ));
            for entry in &rib.rib_entries {
                out.push_str(&format!(
                    "{INDENT}RIB_ENTRY:\n{INDENT}{INDENT}PEER_INDEX: {}\n{INDENT}{INDENT}ORIGINATED: {}\n",
                    entry.peer_index, entry.originated_time
                ));
                render_attributes_block(out, &entry.attributes, 2);
            }
        }
        TableDumpV2Message::GeoPeerTable(gpt) => {
            out.push_str(&format!("GEO_PEER_TABLE: {} peers\n", gpt.geo_peers.len()));
        }
    }
}

fn render_attributes_block(out: &mut String, attributes: &Attributes, depth: usize) {
    let pad = INDENT.repeat(depth + 1);
    let mut iter = attributes.iter().peekable();
    // An empty attribute list can still carry validation findings (RIB
    // entries run check_mandatory_attributes during parsing), so the
    // warnings section renders regardless of the attribute count.
    if iter.peek().is_some() {
        out.push_str(&format!("{}ATTRIBUTES:\n", INDENT.repeat(depth)));
    }
    for attr in iter {
        if let Some(line) = render_attribute(attr) {
            out.push_str(&format!("{pad}{line}\n"));
        }
    }
    let warnings = attributes.validation_warnings();
    if !warnings.is_empty() {
        out.push_str(&format!("{}WARNINGS:\n", INDENT.repeat(depth)));
        for warning in warnings {
            out.push_str(&format!("{pad}{warning}\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BgpValidationWarning;
    use crate::models::capabilities::{
        BgpCapabilityType, FourOctetAsCapability, MultiprotocolExtensionsCapability,
    };
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn update_record(attributes: Attributes) -> MrtRecord {
        MrtRecord {
            common_header: CommonHeader {
                timestamp: 1_666_542_810,
                microsecond_timestamp: Some(970_000),
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
                    withdrawn_prefixes: vec![NetworkPrefix::from_str("203.0.113.0/24").unwrap()],
                    attributes,
                    announced_prefixes: vec![NetworkPrefix::from_str("198.51.100.0/24").unwrap()],
                }),
            })),
        }
    }

    fn full_attributes() -> Attributes {
        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        attributes.add_attr(
            AttributeValue::AsPath(AsPath::from_segments(vec![
                AsPathSegment::sequence([65001, 65002]),
                AsPathSegment::set([65010, 65011]),
            ]))
            .into(),
        );
        attributes
            .add_attr(AttributeValue::NextHop(IpAddr::from_str("192.0.2.254").unwrap()).into());
        attributes.add_attr(AttributeValue::LocalPreference(100).into());
        attributes.add_attr(AttributeValue::OnlyToCustomer(64512.into()).into());
        attributes.add_attr(
            AttributeValue::Communities(vec![
                Community::Custom(Asn::new_32bit(64512), 100),
                Community::NoExport,
            ])
            .into(),
        );
        attributes.add_attr(
            AttributeValue::LargeCommunities(vec![LargeCommunity::new(64496, [1, 2])]).into(),
        );
        attributes
    }

    #[test]
    fn renders_hex_line_variant() {
        let text = format_record_with_hex(&update_record(full_attributes()), "deadbeef");
        assert!(text.trim_end().ends_with("  HEX: deadbeef"));
        // everything before the HEX line is the plain block
        let plain = format_record(&update_record(full_attributes()));
        assert!(text.starts_with(&plain));
    }

    #[test]
    fn renders_layered_update_block() {
        let text = format_record(&update_record(full_attributes()));
        let expected = "\
TIME: 1666542810.970000
TYPE: BGP4MP/MessageAs4
PEER: 192.0.2.1 AS64496
LOCAL: 192.0.2.2 AS64497
UPDATE:
  WITHDRAWN:
    203.0.113.0/24
  ANNOUNCED:
    198.51.100.0/24
  ATTRIBUTES:
    ORIGIN: IGP
    AS_PATH: 65001 65002 {65010,65011}
    NEXT_HOP: 192.0.2.254
    LOCAL_PREF: 100
    ONLY_TO_CUSTOMER: 64512
    COMMUNITIES: 64512:100 no-export
    LARGE_COMMUNITIES: 64496:1:2
";
        assert_eq!(text, expected);
    }

    #[test]
    fn renders_warnings_section() {
        let mut attributes = full_attributes();
        attributes.add_validation_warning(BgpValidationWarning::DuplicateAttribute {
            attr_type: AttrType::ORIGIN,
        });
        let text = format_record(&update_record(attributes));
        assert!(text.contains("  WARNINGS:\n"));
        assert!(text.contains("Duplicate attribute: ORIGIN"));
        // the warning follows the attributes section
        let attr_pos = text.find("LARGE_COMMUNITIES").unwrap();
        let warn_pos = text.find("WARNINGS").unwrap();
        assert!(warn_pos > attr_pos);
    }

    #[test]
    fn renders_mp_reach_prefixes_in_sections() {
        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        attributes.add_attr(
            AttributeValue::MpReachNlri(Nlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: Some(NextHopAddress::Ipv6("2001:db8::1".parse().unwrap())),
                prefixes: vec![NetworkPrefix::from_str("2001:db8::/32").unwrap()],
                labeled_prefixes: None,
                link_state_nlris: None,
                flowspec_nlris: None,
            })
            .into(),
        );
        let text = format_record(&update_record(attributes));
        assert!(text.contains("    198.51.100.0/24\n    2001:db8::/32\n"));
        assert!(text.contains("MP_REACH_NLRI: Ipv6/Unicast next-hop 2001:db8::1"));
    }

    /// Strip ANSI SGR sequences, to compare styled output with its plain form.
    fn strip_sgr(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find('\x1b') {
            out.push_str(&rest[..start]);
            match rest[start..].find('m') {
                Some(end) => rest = &rest[start + end + 1..],
                None => return out,
            }
        }
        out.push_str(rest);
        out
    }

    #[test]
    fn style_plain_is_byte_identical() {
        let record = update_record(full_attributes());
        assert_eq!(
            format_record_with_style(&record, Style::plain()),
            format_record(&record)
        );
        assert_eq!(
            format_record_with_hex_and_style(&record, "deadbeef", Style::plain()),
            format_record_with_hex(&record, "deadbeef")
        );
    }

    #[test]
    fn style_accents_labels_sections_prefixes_and_next_hops() {
        let mut attributes = full_attributes();
        attributes.add_attr(
            AttributeValue::MpReachNlri(Nlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                // a comma-joined RFC 2545 pair, as RIS Live projects it
                next_hop: Some(NextHopAddress::Ipv6LinkLocal(
                    "2001:db8::1".parse().unwrap(),
                    "fe80::1".parse().unwrap(),
                )),
                prefixes: vec![NetworkPrefix::from_str("2001:db8:1::/48").unwrap()],
                labeled_prefixes: None,
                link_state_nlris: None,
                flowspec_nlris: None,
            })
            .into(),
        );
        let record = update_record(attributes);
        let plain = format_record(&record);
        let styled = format_record_with_style(&record, Style::ansi());

        // styling wraps spans, it never rewrites the text
        assert_ne!(styled, plain);
        assert_eq!(strip_sgr(&styled), plain);

        assert!(styled.contains(&format!("{ANSI_LABEL}TIME:{ANSI_RESET} 1666542810.970000")));
        assert!(styled.contains(&format!("{ANSI_LABEL}PEER:{ANSI_RESET} 192.0.2.1 AS64496")));
        assert!(styled.contains(&format!("{ANSI_SECTION}UPDATE:{ANSI_RESET}")));
        assert!(styled.contains(&format!("{ANSI_SECTION}ANNOUNCED:{ANSI_RESET}")));
        assert!(styled.contains(&format!("{ANSI_SECTION}ATTRIBUTES:{ANSI_RESET}")));
        assert!(styled.contains(&format!("    {ANSI_PREFIX}198.51.100.0/24{ANSI_RESET}")));
        assert!(styled.contains(&format!("{ANSI_LABEL}ORIGIN:{ANSI_RESET} IGP")));
        assert!(styled.contains(&format!(
            "{ANSI_LABEL}MP_REACH_NLRI:{ANSI_RESET} {ANSI_NEXT_HOP}Ipv6/Unicast next-hop 2001:db8::1,fe80::1{ANSI_RESET}"
        )));
    }

    #[test]
    fn style_accents_table_dump_prefixes() {
        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        let rib = MrtRecord {
            common_header: CommonHeader {
                timestamp: 6,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP_V2,
                entry_subtype: 2,
                length: 0,
            },
            message: MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(RibAfiEntries {
                rib_type: TableDumpV2Type::RibIpv4Unicast,
                sequence_number: 1,
                prefix: NetworkPrefix::from_str("198.51.100.0/24").unwrap(),
                rib_entries: vec![RibEntry {
                    peer_index: 0,
                    originated_time: 1_666_542_000,
                    path_id: None,
                    attributes,
                }],
            })),
        };
        let styled = format_record_with_style(&rib, Style::ansi());
        // the RIB_AFI summary embeds the prefix in its heading line
        assert!(styled.contains(&format!(
            "PREFIX: {ANSI_PREFIX}198.51.100.0/24{ANSI_RESET} (1 entries)"
        )));

        // a legacy type-5 RIB entry labels the prefix instead of listing it
        let entry = MrtRecord {
            common_header: CommonHeader {
                timestamp: 6,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP,
                entry_subtype: 12,
                length: 0,
            },
            message: MrtMessage::TableDumpMessage(TableDumpMessage {
                view_number: 0,
                sequence_number: 1,
                prefix: NetworkPrefix::from_str("198.51.100.0/24").unwrap(),
                status: 1,
                originated_time: 1_666_542_000,
                peer_ip: IpAddr::from_str("192.0.2.1").unwrap(),
                peer_asn: Asn::new_16bit(64496),
                attributes: Attributes::default(),
            }),
        };
        let styled = format_record_with_style(&entry, Style::ansi());
        assert!(styled.contains(&format!(
            "{ANSI_LABEL}PREFIX:{ANSI_RESET} {ANSI_PREFIX}198.51.100.0/24{ANSI_RESET}\n"
        )));
    }

    #[test]
    fn style_leaves_sentence_lines_plain() {
        let mut attributes = full_attributes();
        attributes.add_validation_warning(BgpValidationWarning::DuplicateAttribute {
            attr_type: AttrType::ORIGIN,
        });
        let styled = format_record_with_style(&update_record(attributes), Style::ansi());
        // a warning is a sentence, not an identifier: no accent, no escape sequences
        assert!(styled.contains("    Duplicate attribute: ORIGIN\n"));
    }

    #[test]
    fn renders_state_change_open_and_keepalive() {
        let state = MrtRecord {
            common_header: CommonHeader {
                timestamp: 2,
                microsecond_timestamp: None,
                entry_type: EntryType::BGP4MP,
                entry_subtype: Bgp4MpType::StateChange as u16,
                length: 0,
            },
            message: MrtMessage::Bgp4Mp(Bgp4MpEnum::StateChange(Bgp4MpStateChange {
                msg_type: Bgp4MpType::StateChange,
                peer_asn: Asn::new_16bit(64496),
                local_asn: Asn::new_16bit(64497),
                interface_index: 0,
                peer_ip: IpAddr::from_str("192.0.2.1").unwrap(),
                local_addr: IpAddr::from_str("192.0.2.2").unwrap(),
                old_state: BgpState::Idle,
                new_state: BgpState::Established,
            })),
        };
        let text = format_record(&state);
        assert!(text.contains("PEER: 192.0.2.1 AS64496"));
        assert!(text.contains("LOCAL: 192.0.2.2 AS64497"));
        assert!(text.contains("STATE_CHANGE:"));
        assert!(text.contains("OLD_STATE: Idle"));
        assert!(text.contains("NEW_STATE: Established"));

        let keepalive = MrtRecord {
            common_header: CommonHeader {
                timestamp: 3,
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
        assert!(format_record(&keepalive).contains("KEEPALIVE:"));

        let open = MrtRecord {
            common_header: CommonHeader {
                timestamp: 4,
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
                bgp_message: BgpMessage::Open(BgpOpenMessage {
                    version: 4,
                    asn: Asn::new_16bit(64496),
                    hold_time: 180,
                    bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
                    extended_length: false,
                    opt_params: vec![OptParam {
                        param_type: 2,
                        param_value: ParamValue::Capacities(vec![
                            Capability {
                                ty: BgpCapabilityType::MULTIPROTOCOL_EXTENSIONS_FOR_BGP_4,
                                value: CapabilityValue::MultiprotocolExtensions(
                                    MultiprotocolExtensionsCapability::new(
                                        Afi::Ipv4,
                                        Safi::Unicast,
                                    ),
                                ),
                            },
                            Capability {
                                ty: BgpCapabilityType::SUPPORT_FOR_4_OCTET_AS_NUMBER_CAPABILITY,
                                value: CapabilityValue::FourOctetAs(FourOctetAsCapability::new(
                                    64496,
                                )),
                            },
                        ]),
                    }],
                }),
            })),
        };
        let text = format_record(&open);
        assert!(text.contains("OPEN:"));
        assert!(text.contains("MY_AS: 64496"));
        assert!(text.contains("MULTIPROTOCOL_EXTENSIONS_FOR_BGP_4: Ipv4/Unicast"));
        assert!(text.contains("SUPPORT_FOR_4_OCTET_AS_NUMBER_CAPABILITY: AS64496"));
    }

    #[test]
    fn renders_labeled_linkstate_and_flowspec_sections() {
        use crate::models::{LabeledNetworkPrefix, MplsLabel};

        let labeled = LabeledNetworkPrefix {
            prefix: "192.0.2.0/24".parse().unwrap(),
            labels: smallvec::SmallVec::from_vec(vec![
                MplsLabel::try_new(24001).unwrap(),
                MplsLabel::try_new(16).unwrap(),
            ]),
            path_id: Some(7),
        };
        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        attributes.add_attr(
            AttributeValue::MpReachNlri(Nlri {
                afi: Afi::Ipv4,
                safi: Safi::MplsLabel,
                next_hop: Some(NextHopAddress::Ipv4("192.0.2.254".parse().unwrap())),
                prefixes: vec![],
                labeled_prefixes: Some(vec![labeled]),
                link_state_nlris: Some(vec![]),
                flowspec_nlris: Some(vec![]),
            })
            .into(),
        );
        let text = format_record(&update_record(attributes));
        assert!(text.contains("  ANNOUNCED (labeled):\n"));
        assert!(text.contains("    192.0.2.0/24 labels=[24001, 16] path-id 7\n"));
        // empty link-state/flowspec collections produce no sections
        assert!(!text.contains("LINK_STATE_NLRI"));
        assert!(!text.contains("FLOWSPEC_NLRI"));
    }

    #[test]
    fn renders_rib_warnings_with_empty_attributes() {
        // RIB parsers run check_mandatory_attributes during parsing, so an
        // entry can reach the renderer with an empty attribute list but
        // non-empty findings — the warnings section must render without an
        // ATTRIBUTES section. (Warnings are attached here directly because
        // the record is built structurally, not parsed from the wire.)
        let mut empty_with_warnings = Attributes::default();
        empty_with_warnings.add_validation_warning(
            BgpValidationWarning::MissingWellKnownAttribute {
                attr_type: AttrType::ORIGIN,
            },
        );
        let rib = MrtRecord {
            common_header: CommonHeader {
                timestamp: 9,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP_V2,
                entry_subtype: 2,
                length: 0,
            },
            message: MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(RibAfiEntries {
                rib_type: TableDumpV2Type::RibIpv4Unicast,
                sequence_number: 1,
                prefix: NetworkPrefix::from_str("198.51.100.0/24").unwrap(),
                rib_entries: vec![RibEntry {
                    peer_index: 0,
                    originated_time: 1,
                    path_id: None,
                    attributes: empty_with_warnings,
                }],
            })),
        };
        let text = format_record(&rib);
        assert!(text.contains("WARNINGS:"));
        assert!(text.contains("Missing well-known mandatory attribute: ORIGIN"));
        assert!(!text.contains("ATTRIBUTES:"));
    }

    #[test]
    fn renders_legacy_bgp_records() {
        let legacy = MrtRecord {
            common_header: CommonHeader {
                timestamp: 7,
                microsecond_timestamp: None,
                entry_type: EntryType::BGP,
                entry_subtype: 5,
                length: 0,
            },
            message: MrtMessage::LegacyBgp(LegacyBgp::Message(LegacyBgpMessage {
                peer_asn: Asn::new_16bit(5409),
                peer_ip: IpAddr::from_str("195.211.222.254").unwrap(),
                local_asn: Asn::new_16bit(12654),
                local_ip: IpAddr::from_str("193.0.0.1").unwrap(),
                bgp_message: BgpMessage::KeepAlive,
            })),
        };
        let text = format_record(&legacy);
        assert!(text.contains("PEER: 195.211.222.254 AS5409"));
        assert!(text.contains("LOCAL: 193.0.0.1 AS12654"));
        assert!(text.contains("KEEPALIVE:"));

        let state = MrtRecord {
            common_header: CommonHeader {
                timestamp: 8,
                microsecond_timestamp: None,
                entry_type: EntryType::BGP,
                entry_subtype: 6,
                length: 0,
            },
            message: MrtMessage::LegacyBgp(LegacyBgp::StateChange(LegacyBgpStateChange {
                peer_asn: Asn::new_16bit(5409),
                peer_ip: IpAddr::from_str("195.211.222.254").unwrap(),
                old_state: BgpState::Established,
                new_state: BgpState::Idle,
            })),
        };
        let text = format_record(&state);
        assert!(text.contains("PEER: 195.211.222.254 AS5409"));
        // a legacy state change carries only the peer endpoint
        assert!(!text.contains("LOCAL:"));
        assert!(text.contains("STATE_CHANGE:"));
        assert!(text.contains("OLD_STATE: Established"));
        assert!(text.contains("NEW_STATE: Idle"));
    }

    #[test]
    fn renders_peer_index_table_and_rib_entries() {
        let mut peers = std::collections::HashMap::new();
        peers.insert(
            0u16,
            Peer::new(
                Ipv4Addr::new(10, 0, 0, 1),
                IpAddr::from_str("192.0.2.1").unwrap(),
                Asn::new_32bit(64496),
            ),
        );
        let pit = MrtRecord {
            common_header: CommonHeader {
                timestamp: 5,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP_V2,
                entry_subtype: 1,
                length: 0,
            },
            message: MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(
                PeerIndexTable {
                    collector_bgp_id: Ipv4Addr::new(10, 0, 0, 254),
                    view_name: "".to_string(),
                    id_peer_map: peers,
                    peer_ip_id_map: std::collections::HashMap::new(),
                },
            )),
        };
        let text = format_record(&pit);
        assert!(text.contains("PEER_INDEX_TABLE: 1 peers"));
        assert!(text.contains("PEER[0]: 192.0.2.1 AS64496"));

        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        attributes.add_attr(AttributeValue::AsPath(AsPath::from_sequence([64500])).into());
        let rib = MrtRecord {
            common_header: CommonHeader {
                timestamp: 6,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP_V2,
                entry_subtype: 2,
                length: 0,
            },
            message: MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(RibAfiEntries {
                rib_type: TableDumpV2Type::RibIpv4Unicast,
                sequence_number: 1,
                prefix: NetworkPrefix::from_str("198.51.100.0/24").unwrap(),
                rib_entries: vec![RibEntry {
                    peer_index: 0,
                    originated_time: 1_666_542_000,
                    path_id: None,
                    attributes,
                }],
            })),
        };
        let text = format_record(&rib);
        assert!(text.contains("PREFIX: 198.51.100.0/24 (1 entries)"));
        assert!(text.contains("PEER_INDEX: 0"));
        assert!(text.contains("AS_PATH: 64500"));
    }
}
