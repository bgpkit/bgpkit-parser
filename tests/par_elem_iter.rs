//! `into_par_elem_iter` must yield exactly the elem stream of the sequential
//! default iterator, in the same order, for every thread count.

use bgpkit_parser::models::*;
use bgpkit_parser::BgpkitParser;
use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

const RIB: &str = "tests/fixtures/ripe/rrc00/2000.01/bview.20000111.0032.gz";
const UPDATES: &str = "tests/fixtures/ripe/rrc00/2000.03/updates.20000325.0345.gz";
const UPDATES_2010: &str = "tests/fixtures/ripe/rrc15/2010.02/updates.20100227.1600.gz";

/// Every field of every elem, in order: Debug covers the fields Display leaves out.
fn render(elems: impl Iterator<Item = BgpElem>) -> Vec<String> {
    elems.map(|elem| format!("{elem}\n{elem:?}")).collect()
}

fn decompressed(path: &str) -> Vec<u8> {
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).expect("fixture opens"))
        .read_to_end(&mut data)
        .expect("fixture decompresses");
    data
}

fn assert_parity(name: &str, data: &[u8]) {
    let expected = render(
        BgpkitParser::from_reader(Cursor::new(data.to_vec()))
            .disable_warnings()
            .into_elem_iter(),
    );
    assert!(!expected.is_empty(), "{name} produced no elems");
    for threads in [1, 2, 8] {
        let got = render(
            BgpkitParser::from_reader(Cursor::new(data.to_vec()))
                .disable_warnings()
                .into_par_elem_iter(threads),
        );
        assert_eq!(
            expected.len(),
            got.len(),
            "{name}: elem count differs at {threads} threads"
        );
        if let Some(i) = (0..expected.len()).find(|&i| expected[i] != got[i]) {
            panic!(
                "{name}: elem {i} differs at {threads} threads:\n  sequential: {}\n  parallel:   {}",
                expected[i], got[i]
            );
        }
    }
}

#[test]
fn par_elem_iter_matches_sequential_on_a_rib() {
    assert_parity(RIB, &decompressed(RIB));
}

#[test]
fn par_elem_iter_matches_sequential_on_updates() {
    assert_parity(UPDATES, &decompressed(UPDATES));
    assert_parity(UPDATES_2010, &decompressed(UPDATES_2010));
}

#[test]
fn par_elem_iter_matches_sequential_on_a_truncated_tail() {
    for path in [UPDATES, RIB] {
        let mut data = decompressed(path);
        // cut into the middle of a record body near the end of the file
        data.truncate(data.len() - 37);
        assert_parity(&format!("{path} (truncated)"), &data);
    }
}

/// The fixture through the reader the CLI uses (a `Box<dyn Read + Send>` that
/// decompresses on the producer thread).
#[test]
fn par_elem_iter_matches_sequential_through_oneio() {
    let expected = render(BgpkitParser::new(UPDATES).unwrap().into_elem_iter());
    let got = render(BgpkitParser::new(UPDATES).unwrap().into_par_elem_iter(4));
    assert_eq!(expected, got);
}

/// Dropping the iterator part way through must stop and join its threads
/// rather than hang or leak.
#[test]
fn par_elem_iter_can_be_dropped_early() {
    let data = decompressed(RIB);
    for take in [0, 1, 1000] {
        let taken = BgpkitParser::from_reader(Cursor::new(data.clone()))
            .into_par_elem_iter(8)
            .take(take)
            .count();
        assert_eq!(take, taken);
    }
}

fn peer_table(peers: &[(&str, u32)]) -> PeerIndexTable {
    let mut table = PeerIndexTable::default();
    for (ip, asn) in peers {
        table
            .add_peer(Peer::new(
                Ipv4Addr::new(192, 0, 2, 1),
                IpAddr::from_str(ip).unwrap(),
                Asn::new_32bit(*asn),
            ))
            .unwrap();
    }
    table
}

fn encode(subtype: TableDumpV2Type, message: TableDumpV2Message) -> Vec<u8> {
    let message = MrtMessage::TableDumpV2Message(message);
    let length = message.encode(subtype as u16).unwrap().len() as u32;
    MrtRecord {
        common_header: CommonHeader {
            timestamp: 1_700_000_000,
            microsecond_timestamp: None,
            entry_type: EntryType::TABLE_DUMP_V2,
            entry_subtype: subtype as u16,
            length,
        },
        message,
    }
    .encode()
    .unwrap()
    .to_vec()
}

fn rib_records(out: &mut Vec<u8>, batch: u8, count: u16) {
    for i in 0..count {
        let prefix = format!("10.{batch}.{}.{}/32", i / 256, i % 256);
        let entries = (0..2u16)
            .map(|peer_index| RibEntry {
                peer_index,
                originated_time: 1_699_999_000 + u32::from(i),
                path_id: None,
                attributes: Attributes::from_iter(vec![
                    AttributeValue::Origin(Origin::IGP),
                    AttributeValue::AsPath(AsPath::from_sequence([
                        65000 + u32::from(peer_index),
                        13335,
                    ])),
                    AttributeValue::NextHop(IpAddr::from_str("192.0.2.254").unwrap()),
                ]),
            })
            .collect();
        out.extend(encode(
            TableDumpV2Type::RibIpv4Unicast,
            TableDumpV2Message::RibAfi(RibAfiEntries {
                rib_type: TableDumpV2Type::RibIpv4Unicast,
                sequence_number: u32::from(i),
                prefix: NetworkPrefix::from_str(&prefix).unwrap(),
                rib_entries: entries,
            }),
        ));
    }
}

/// A second `PEER_INDEX_TABLE` mid-file must apply to the records after it and
/// only to those, even while records framed under the first table are still
/// being parsed.
#[test]
fn par_elem_iter_handles_two_peer_index_tables() {
    let first = [("10.255.0.1", 64501), ("10.255.0.2", 64502)];
    let second = [("10.255.1.1", 64601), ("10.255.1.2", 64602)];
    let per_batch = 3000u16;

    let mut data = Vec::new();
    data.extend(encode(
        TableDumpV2Type::PeerIndexTable,
        TableDumpV2Message::PeerIndexTable(peer_table(&first)),
    ));
    rib_records(&mut data, 1, per_batch);
    data.extend(encode(
        TableDumpV2Type::PeerIndexTable,
        TableDumpV2Message::PeerIndexTable(peer_table(&second)),
    ));
    rib_records(&mut data, 2, per_batch);

    let sequential: Vec<BgpElem> = BgpkitParser::from_reader(Cursor::new(data.clone()))
        .into_elem_iter()
        .collect();
    let batch_len = usize::from(per_batch) * 2;
    assert_eq!(sequential.len(), batch_len * 2);
    let peers = |elems: &[BgpElem]| {
        let mut ips: Vec<String> = elems.iter().map(|e| e.peer_ip.to_string()).collect();
        ips.sort();
        ips.dedup();
        ips
    };
    assert_eq!(
        peers(&sequential[..batch_len]),
        ["10.255.0.1", "10.255.0.2"]
    );
    assert_eq!(
        peers(&sequential[batch_len..]),
        ["10.255.1.1", "10.255.1.2"]
    );

    for threads in [2, 3, 8, 16] {
        let parallel: Vec<BgpElem> = BgpkitParser::from_reader(Cursor::new(data.clone()))
            .into_par_elem_iter(threads)
            .collect();
        assert_eq!(
            render(sequential.clone().into_iter()),
            render(parallel.into_iter()),
            "two peer tables diverged at {threads} threads"
        );
    }
}
