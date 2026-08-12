use bgpkit_parser::{BgpkitParser, RecoveryConfig, RecoveryEvent, RecoveryEvidence, RecoveryGap};
use flate2::read::GzDecoder;
use std::io::{Cursor, Read};

const FIXTURE: &str = "tests/fixtures/ripe/rrc00/2000.03/updates.20000325.0345.gz";

fn fixture_path() -> String {
    format!("{}/{}", env!("CARGO_MANIFEST_DIR"), FIXTURE)
}

#[test]
fn recovers_damaged_ripe_type_5_fixture() {
    let mut records = 0usize;
    let mut gaps = Vec::<RecoveryGap>::new();

    for event in BgpkitParser::new(&fixture_path())
        .unwrap()
        .into_recovering_record_iter(RecoveryConfig::default())
    {
        match event.unwrap() {
            RecoveryEvent::Item(_) => records += 1,
            RecoveryEvent::Gap(gap) => gaps.push(gap),
        }
    }

    assert_eq!(records, 2_580);
    assert_eq!(gaps.len(), 2);
    assert_eq!(gaps.iter().map(RecoveryGap::skipped_bytes).sum::<u64>(), 24);
    assert_eq!(
        gaps.iter()
            .map(|gap| (
                gap.start_offset,
                gap.end_offset,
                gap.evidence,
                gap.confirmed_records,
            ))
            .collect::<Vec<_>>(),
        vec![
            (188, 198, RecoveryEvidence::LegacyMrtChain, 3),
            (4_554, 4_568, RecoveryEvidence::LegacyMrtChain, 3),
        ]
    );
}

#[test]
fn recovering_elem_iter_matches_fixture_totals() {
    let mut elements = 0usize;
    let mut gaps = 0usize;

    for event in BgpkitParser::new(&fixture_path())
        .unwrap()
        .into_recovering_elem_iter(RecoveryConfig::default())
    {
        match event.unwrap() {
            RecoveryEvent::Item(_) => elements += 1,
            RecoveryEvent::Gap(_) => gaps += 1,
        }
    }

    assert_eq!(elements, 5_378);
    assert_eq!(gaps, 2);
}

/// A truncated final record — the most common real-world corruption — must yield every
/// intact record plus a terminal gap, not a hard error that discards the whole file.
#[test]
fn truncated_fixture_tail_yields_terminal_gap() {
    let mut bytes = Vec::new();
    GzDecoder::new(std::fs::File::open(fixture_path()).unwrap())
        .read_to_end(&mut bytes)
        .unwrap();
    bytes.truncate(bytes.len() - 20);
    let total = bytes.len() as u64;

    let mut records = 0usize;
    let mut gaps = Vec::<RecoveryGap>::new();
    for event in BgpkitParser::from_reader(Cursor::new(bytes))
        .into_recovering_record_iter(RecoveryConfig::default())
    {
        match event.unwrap() {
            RecoveryEvent::Item(_) => records += 1,
            RecoveryEvent::Gap(gap) => gaps.push(gap),
        }
    }

    assert_eq!(records, 2_579);
    assert_eq!(gaps.len(), 3);
    let terminal = gaps.last().unwrap();
    assert_eq!(terminal.evidence, RecoveryEvidence::EndOfStream);
    assert_eq!(terminal.end_offset, total);
}
