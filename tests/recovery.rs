use bgpkit_parser::{
    BgpkitParser, Elementor, RecoveryConfig, RecoveryEvent, RecoveryEvidence, RecoveryGap,
};

const FIXTURE: &str = "tests/fixtures/ripe/rrc00/2000.03/updates.20000325.0345.gz";

#[test]
fn recovers_damaged_ripe_type_5_fixture() {
    let source = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), FIXTURE);
    let mut records = 0usize;
    let mut elements = 0usize;
    let mut gaps = Vec::<RecoveryGap>::new();
    let mut elementor = Elementor::new();

    for event in BgpkitParser::new(&source)
        .unwrap()
        .into_recovering_record_iter(RecoveryConfig::default())
    {
        match event.unwrap() {
            RecoveryEvent::Item(record) => {
                records += 1;
                elements += elementor.record_to_elems(record).len();
            }
            RecoveryEvent::Gap(gap) => gaps.push(gap),
        }
    }

    assert_eq!(records, 2_580);
    assert_eq!(elements, 5_378);
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
