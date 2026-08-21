//! Behavior of `--format text` building blocks: record-level rendering and
//! the documented filter semantics (records with an empty elem projection —
//! KEEPALIVE, OPEN, NOTIFICATION, state changes — are dropped when filters
//! are active; RIB records do produce elems and can match).

use bgpkit_parser::models::*;
use bgpkit_parser::render::text::format_record;
use bgpkit_parser::BgpkitParser;
use std::io::Cursor;
use std::str::FromStr;

/// One BGP4MP_MESSAGE_AS4 record wrapping the given BGP message.
fn bgp4mp_record(timestamp: u32, bgp_message: BgpMessage) -> Vec<u8> {
    let mut bgp = vec![0xFF; 16];
    let body = match &bgp_message {
        BgpMessage::Update(update) => update.encode(AsnLength::Bits32).unwrap(),
        BgpMessage::KeepAlive => Vec::new().into(),
        _ => unreachable!("test only builds updates and keepalives"),
    };
    bgp.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    bgp.push(bgp_message.msg_type() as u8);
    bgp.extend_from_slice(&body);

    let mut mrt_body = Vec::new();
    mrt_body.extend_from_slice(&64496u32.to_be_bytes());
    mrt_body.extend_from_slice(&64497u32.to_be_bytes());
    mrt_body.extend_from_slice(&0u16.to_be_bytes());
    mrt_body.extend_from_slice(&1u16.to_be_bytes());
    mrt_body.extend_from_slice(&[192, 0, 2, 1]);
    mrt_body.extend_from_slice(&[192, 0, 2, 2]);
    mrt_body.extend_from_slice(&bgp);

    let mut wire = Vec::new();
    wire.extend_from_slice(&timestamp.to_be_bytes());
    wire.extend_from_slice(&(EntryType::BGP4MP as u16).to_be_bytes());
    wire.extend_from_slice(&(Bgp4MpType::MessageAs4 as u16).to_be_bytes());
    wire.extend_from_slice(&(mrt_body.len() as u32).to_be_bytes());
    wire.extend_from_slice(&mrt_body);
    wire
}

fn keepalive_record(timestamp: u32) -> Vec<u8> {
    bgp4mp_record(timestamp, BgpMessage::KeepAlive)
}

fn update_record_wire(timestamp: u32) -> Vec<u8> {
    let mut attributes = Attributes::default();
    attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
    attributes.add_attr(AttributeValue::AsPath(AsPath::from_sequence([65000])).into());
    attributes.add_attr(AttributeValue::NextHop("192.0.2.254".parse().unwrap()).into());
    bgp4mp_record(
        timestamp,
        BgpMessage::Update(BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes,
            announced_prefixes: vec![NetworkPrefix::from_str("198.51.100.0/24").unwrap()],
        }),
    )
}

fn record_type_summaries(input: Vec<u8>) -> Vec<String> {
    BgpkitParser::from_reader(Cursor::new(input))
        .into_record_iter()
        .map(|record| format_record(&record))
        .map(|text| {
            text.lines()
                .find(|line| line.starts_with("UPDATE:") || line.starts_with("KEEPALIVE:"))
                .unwrap()
                .to_string()
        })
        .collect()
}

#[test]
fn text_format_renders_stream_of_records() {
    let mut input = keepalive_record(1);
    input.extend_from_slice(&update_record_wire(2));
    input.extend_from_slice(&keepalive_record(3));

    assert_eq!(
        record_type_summaries(input),
        vec!["KEEPALIVE:", "UPDATE:", "KEEPALIVE:"]
    );
}

#[test]
fn filters_drop_no_elem_records_from_record_iteration() {
    // Documented semantics: filters match on the elem projection, so
    // records that produce no elems (KEEPALIVE here) are dropped while
    // filters are active — the UPDATE record survives via its prefix.
    let mut input = keepalive_record(1);
    input.extend_from_slice(&update_record_wire(2));
    input.extend_from_slice(&keepalive_record(3));

    let parser = BgpkitParser::from_reader(Cursor::new(input))
        .add_filter("prefix", "198.51.100.0/24")
        .unwrap();
    let summaries: Vec<String> = parser
        .into_record_iter()
        .map(|record| format_record(&record))
        .map(|text| {
            text.lines()
                .find(|line| line.starts_with("UPDATE:") || line.starts_with("KEEPALIVE:"))
                .unwrap()
                .to_string()
        })
        .collect();

    assert_eq!(summaries, vec!["UPDATE:"]);
}
