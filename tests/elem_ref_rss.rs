//! Dedicated single-test process verifying that `BgpkitParser::next_record_elems` keeps process
//! RSS flat as element count scales from 10k to 1M elements.
//!
//! Kept in its own integration-test binary so concurrent tests in other files (e.g., HTTPS/TLS
//! downloads and bzip2 decompression) do not share `/proc/self/statm`.

use bgpkit_parser::models::{
    AsPath, AsPathSegment, Asn, AttributeValue, Attributes, CommonHeader, Community, EntryType,
    LargeCommunity, MrtMessage, MrtRecord, NetworkPrefix, Origin, Peer, PeerIndexTable,
    RibAfiEntries, RibEntry, TableDumpV2Message, TableDumpV2Type,
};
use bgpkit_parser::{AsPathView, AsnsView, BgpkitParser, CommunitiesView, ElemRef};
use std::hint::black_box;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// Streaming reader that emits one `PeerIndexTable` record followed by `repeat_records` copies of
/// a `RIB_AFI` record without holding more than one record template in memory itself.
struct RepeatingRibReader {
    pit_bytes: Vec<u8>,
    rib_bytes: Vec<u8>,
    in_pit: bool,
    pos: usize,
    remaining_records: usize,
}

impl RepeatingRibReader {
    fn new(entries_per_record: usize, repeat_records: usize) -> Self {
        let mut peer_table = PeerIndexTable::default();
        for i in 0..entries_per_record {
            peer_table
                .add_peer(Peer::new(
                    Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8),
                    IpAddr::V4(Ipv4Addr::new(198, 18, (i / 256) as u8, (i % 256) as u8)),
                    Asn::new_32bit(65_000 + i as u32),
                ))
                .unwrap();
        }
        let pit_record = MrtRecord {
            common_header: CommonHeader {
                timestamp: 1_700_000_000,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP_V2,
                entry_subtype: TableDumpV2Type::PeerIndexTable as u16,
                length: 0,
            },
            message: MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(peer_table)),
        };

        let mut rib_entries = Vec::with_capacity(entries_per_record);
        for i in 0..entries_per_record {
            let mut attrs = Attributes::default();
            attrs.add_attr(AttributeValue::Origin(Origin::IGP).into());
            attrs.add_attr(
                AttributeValue::AsPath(AsPath::from_segments(vec![
                    AsPathSegment::sequence([65_000 + i as u32, 3356, 174, 13335]),
                    AsPathSegment::set([15169, 8075]),
                ]))
                .into(),
            );
            attrs
                .add_attr(AttributeValue::NextHop(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))).into());
            attrs.add_attr(AttributeValue::MultiExitDiscriminator(100 + i as u32).into());
            attrs.add_attr(AttributeValue::LocalPreference(200).into());
            attrs.add_attr(
                AttributeValue::Communities(vec![
                    Community::NoExport,
                    Community::Custom(Asn::new_16bit(3356), i as u16),
                ])
                .into(),
            );
            attrs.add_attr(
                AttributeValue::LargeCommunities(vec![LargeCommunity::new(13335, [1, i as u32])])
                    .into(),
            );
            rib_entries.push(RibEntry {
                peer_index: i as u16,
                originated_time: 1_700_000_000,
                path_id: None,
                attributes: attrs,
            });
        }

        let rib_record = MrtRecord {
            common_header: CommonHeader {
                timestamp: 1_700_000_001,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP_V2,
                entry_subtype: TableDumpV2Type::RibIpv4Unicast as u16,
                length: 0,
            },
            message: MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(RibAfiEntries {
                rib_type: TableDumpV2Type::RibIpv4Unicast,
                sequence_number: 1,
                prefix: NetworkPrefix::from_str("1.1.1.0/24").unwrap(),
                rib_entries,
            })),
        };

        Self {
            pit_bytes: pit_record.encode().unwrap().to_vec(),
            rib_bytes: rib_record.encode().unwrap().to_vec(),
            in_pit: true,
            pos: 0,
            remaining_records: repeat_records,
        }
    }
}

impl Read for RepeatingRibReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.in_pit {
            let avail = &self.pit_bytes[self.pos..];
            let n = avail.len().min(buf.len());
            buf[..n].copy_from_slice(&avail[..n]);
            self.pos += n;
            if self.pos == self.pit_bytes.len() {
                self.in_pit = false;
                self.pos = 0;
            }
            return Ok(n);
        }
        if self.remaining_records == 0 {
            return Ok(0);
        }
        let avail = &self.rib_bytes[self.pos..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.pos += n;
        if self.pos == self.rib_bytes.len() {
            self.pos = 0;
            self.remaining_records -= 1;
        }
        Ok(n)
    }
}

#[cfg(target_os = "linux")]
fn current_rss_bytes() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: usize = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

#[test]
fn rss_stays_flat_across_one_million_borrowed_elems() {
    // Structural assertions: borrowed view types carry no Drop / owned Vec.
    assert!(!std::mem::needs_drop::<ElemRef<'_>>());
    assert!(!std::mem::needs_drop::<AsPathView<'_>>());
    assert!(!std::mem::needs_drop::<AsnsView<'_>>());
    assert!(!std::mem::needs_drop::<CommunitiesView<'_>>());
    // The peer travels inline so one borrowed element type serves dumps and updates.
    assert!(std::mem::size_of::<ElemRef<'_>>() <= 96);

    // Stream 1,000,000 RIB elements (10,000 records x 100 entries) reading every field.
    let reader = RepeatingRibReader::new(100, 10_000);
    let mut parser = BgpkitParser::from_reader(reader);

    let mut count = 0usize;
    let mut acc = 0u64;
    #[cfg(target_os = "linux")]
    let mut rss_at_10k: Option<usize> = None;

    while let Some(mut record) = parser.next_record_elems() {
        for elem in record.iter() {
            acc = acc.wrapping_add(u32::from(elem.peer_asn()) as u64);
            acc = acc.wrapping_add(elem.prefix().prefix.prefix_len() as u64);
            for asn in elem.as_path() {
                acc = acc.wrapping_add(u32::from(asn) as u64);
            }
            for origin in elem.origin_asns() {
                acc = acc.wrapping_add(u32::from(origin) as u64);
            }
            for c in elem.communities().as_plain() {
                black_box(c);
                acc = acc.wrapping_add(1);
            }
            for lc in elem.communities().as_large() {
                acc = acc.wrapping_add(lc.global_admin as u64);
            }
            if let Some(nh) = elem.next_hop() {
                black_box(nh);
            }
            acc = acc.wrapping_add(elem.med().unwrap_or(0) as u64);
            acc = acc.wrapping_add(elem.local_pref().unwrap_or(0) as u64);
            acc = acc.wrapping_add(elem.timestamp() as u64);
            black_box(elem.elem_type());

            count += 1;
            #[cfg(target_os = "linux")]
            if count == 10_000 {
                rss_at_10k = current_rss_bytes();
            }
        }
    }

    black_box(acc);
    assert_eq!(count, 1_000_000);

    #[cfg(target_os = "linux")]
    if let (Some(rss_10k), Some(rss_1m)) = (rss_at_10k, current_rss_bytes()) {
        let growth = rss_1m.saturating_sub(rss_10k);
        assert!(
            growth <= 2 * 1024 * 1024,
            "RSS grew by {growth} bytes between 10k elems ({rss_10k} B) and 1M elems ({rss_1m} B)"
        );
    }
}
