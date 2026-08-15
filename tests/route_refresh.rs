//! Regression test for BGP ROUTE-REFRESH (message type 5, RFC 2918) support.
//!
//! The record below is MRT record 4978 (of 7565) extracted from
//! <https://data.ris.ripe.net/rrc00/2012.07/updates.20120718.2020.gz>
//! (source file SHA-256
//! `8b008f9e1b167af23bcea1b8cb7e95fecbe49abca736c99543fdbebea9aa96cf`).
//! It is a BGP4MP MESSAGE_AS4 record carrying an IPv4-unicast ROUTE-REFRESH
//! from peer AS49065 to RIS AS12654, and used to fail parsing with
//! "Unknown BGP Message Type".

use bgpkit_parser::models::{AsnLength, Bgp4MpEnum, BgpMessage, MrtMessage};
use bgpkit_parser::parser::bgp::parse_bgp_message;
use bgpkit_parser::BgpkitParser;
use bytes::Bytes;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};

#[rustfmt::skip]
const ROUTE_REFRESH_RECORD: [u8; 55] = [
    // MRT common header
    0x50, 0x07, 0x1b, 0x38, // timestamp 1342643000
    0x00, 0x10, 0x00, 0x04, // type 16 (BGP4MP), subtype 4 (MESSAGE_AS4)
    0x00, 0x00, 0x00, 0x2b, // length 43
    // BGP4MP MESSAGE_AS4
    0x00, 0x00, 0xbf, 0xa9, // peer ASN 49065
    0x00, 0x00, 0x31, 0x6e, // local ASN 12654
    0x00, 0x00, 0x00, 0x01, // interface index 0, AFI 1 (IPv4)
    0xd9, 0x40, 0x90, 0x01, // peer IP 217.64.144.1
    0xc1, 0x00, 0x04, 0x1c, // local IP 193.0.4.28
    // BGP message
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // marker
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // marker
    0x00, 0x17, // length 23
    0x05, // type 5 (ROUTE-REFRESH)
    0x00, 0x01, // AFI 1 (IPv4)
    0x00, // reserved / subtype
    0x01, // SAFI 1 (unicast)
];

fn parser() -> BgpkitParser<Cursor<Vec<u8>>> {
    BgpkitParser::from_reader(Cursor::new(ROUTE_REFRESH_RECORD.to_vec()))
}

#[test]
fn parses_route_refresh_record() {
    let records: Vec<_> = parser()
        .into_fallible_record_iter()
        .map(|result| result.unwrap())
        .collect();
    assert_eq!(records.len(), 1);

    let record = &records[0];
    assert_eq!(record.common_header.timestamp, 1_342_643_000);
    let message = match &record.message {
        MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(message)) => message,
        message => panic!("unexpected MRT message: {message:?}"),
    };
    assert_eq!(u32::from(message.peer_asn), 49_065);
    assert_eq!(message.peer_ip, IpAddr::V4(Ipv4Addr::new(217, 64, 144, 1)));
    assert_eq!(u32::from(message.local_asn), 12_654);
    assert_eq!(message.local_ip, IpAddr::V4(Ipv4Addr::new(193, 0, 4, 28)));

    let refresh = match &message.bgp_message {
        BgpMessage::RouteRefresh(refresh) => refresh,
        message => panic!("unexpected BGP message: {message:?}"),
    };
    assert_eq!(refresh.afi, 1);
    assert_eq!(refresh.subtype, 0);
    assert_eq!(refresh.safi, 1);
    assert!(refresh.data.is_empty());
}

#[test]
fn route_refresh_record_yields_no_elems() {
    assert_eq!(parser().into_elem_iter().count(), 0);
}

/// PacketLife.net capture (see `tests/fixtures/packetlife/README.md`): one TCP
/// segment carrying a 19-byte KEEPALIVE followed by a 46-byte ROUTE-REFRESH
/// with an RFC 5291 ORF prefix advertisement.
const PACKETLIFE_ORF_PCAP: &str =
    "tests/fixtures/packetlife/bgp_orf_prefix_advertisement.pcapng.cap";

#[test]
fn parses_orf_prefix_advertisement_from_packetlife_pcap() {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), PACKETLIFE_ORF_PCAP);
    let capture = std::fs::read(path).unwrap();

    // The BGP stream starts at the first 16-byte marker inside the single
    // TCP segment of the capture: KEEPALIVE (19 bytes) + ROUTE-REFRESH (46).
    let marker_offset = capture
        .windows(16)
        .position(|window| window == [0xFF; 16])
        .unwrap();
    let wire = &capture[marker_offset..marker_offset + 19 + 46];
    let mut stream = Bytes::copy_from_slice(wire);

    let keepalive = parse_bgp_message(&mut stream, false, &AsnLength::Bits32).unwrap();
    assert_eq!(keepalive, BgpMessage::KeepAlive);

    let message = parse_bgp_message(&mut stream, false, &AsnLength::Bits32).unwrap();
    let refresh = match &message {
        BgpMessage::RouteRefresh(refresh) => refresh,
        message => panic!("unexpected BGP message: {message:?}"),
    };
    assert_eq!(refresh.afi, 1);
    assert_eq!(refresh.subtype, 0);
    assert_eq!(refresh.safi, 1);

    // RFC 5291 ORF payload, retained raw: when-to-refresh IMMEDIATE (1), ORF
    // type 128 (pre-standard Address Prefix ORF), 19 bytes of entries.
    assert_eq!(refresh.data.len(), 23);
    assert_eq!(refresh.data[0], 0x01);
    assert_eq!(refresh.data[1], 0x80);
    assert_eq!(u16::from_be_bytes([refresh.data[2], refresh.data[3]]), 19);

    // The ROUTE-REFRESH re-encodes byte-identically to the capture.
    let encoded = message.encode(AsnLength::Bits32).unwrap();
    assert_eq!(encoded, &wire[19..]);
}
