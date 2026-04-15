use bgpkit_parser::parser::bgp::messages::parse_bgp_update_message;
use bgpkit_parser::models::*;
use bytes::Bytes;

#[test]
fn test_validation_combinations() {
    let asn_len = AsnLength::Bits32;

    // Helper to build an attribute block
    fn build_attrs(has_origin: bool, has_as_path: bool, has_next_hop: bool, mp_reach: Option<Vec<u8>>, mp_unreach: Option<Vec<u8>>) -> Vec<u8> {
        let mut attrs = Vec::new();
        if has_origin {
            attrs.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]); // ORIGIN = IGP
        }
        if has_as_path {
            attrs.extend_from_slice(&[0x40, 0x02, 0x00]); // AS_PATH = empty
        }
        if has_next_hop {
            attrs.extend_from_slice(&[0x40, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04]); // NEXT_HOP = 1.2.3.4
        }
        if let Some(data) = mp_reach {
            let len = data.len();
            attrs.extend_from_slice(&[0x80, 0x0E, len as u8]);
            attrs.extend_from_slice(&data);
        }
        if let Some(data) = mp_unreach {
            let len = data.len();
            attrs.extend_from_slice(&[0x80, 0x0F, len as u8]);
            attrs.extend_from_slice(&data);
        }
        attrs
    }

    // Helper to build a full UPDATE message
    fn build_update(withdrawn: Vec<u8>, attrs: Vec<u8>, nlri: Vec<u8>) -> Bytes {
        let mut msg = Vec::new();
        msg.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
        msg.extend_from_slice(&withdrawn);
        msg.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&attrs);
        msg.extend_from_slice(&nlri);
        Bytes::from(msg)
    }

    let dummy_mp_reach = vec![0x00, 0x01, 0x01, 0x04, 0x01, 0x01, 0x01, 0x01, 0x00]; // IPv4 Unicast, NH=1.1.1.1, no prefixes
    let dummy_mp_unreach = vec![0x00, 0x01, 0x01]; // IPv4 Unicast

    let scenarios = vec![
        // --- Standard IPv4 Scenarios ---
        ("IPv4 Announce + NH", build_update(vec![], build_attrs(true, true, true, None, None), vec![0x18, 0x0A, 0x00, 0x00]), 0),
        ("IPv4 Announce - NH", build_update(vec![], build_attrs(true, true, false, None, None), vec![0x18, 0x0A, 0x00, 0x00]), 1),
        ("IPv4 Withdraw Only", build_update(vec![0x18, 0x0A, 0x00, 0x00], vec![], vec![]), 0),
        ("IPv4 Withdraw + NH", build_update(vec![0x18, 0x0A, 0x00, 0x00], build_attrs(false, false, true, None, None), vec![]), 0),

        // --- MP-BGP Scenarios ---
        ("MP_REACH - NH", build_update(vec![], build_attrs(true, true, false, Some(dummy_mp_reach.clone()), None), vec![]), 0),
        ("MP_REACH + NH", build_update(vec![], build_attrs(true, true, true, Some(dummy_mp_reach.clone()), None), vec![]), 0),
        ("MP_UNREACH Only", build_update(vec![], build_attrs(false, false, false, None, Some(dummy_mp_unreach.clone())), vec![]), 0),

        // --- Mixed Scenarios (IPv4 Withdraw + MP_REACH Announcement) ---
        ("IPv4 Withdraw + MP_REACH (AS+ORIGIN)", build_update(vec![0x18, 0x0A, 0x00, 0x00], build_attrs(true, true, false, Some(dummy_mp_reach.clone()), None), vec![]), 0),
        ("IPv4 Withdraw + MP_REACH (ORIGIN only)", build_update(vec![0x18, 0x0A, 0x00, 0x00], build_attrs(true, false, false, Some(dummy_mp_reach.clone()), None), vec![]), 1),
        ("IPv4 Withdraw + MP_REACH (AS+ORIGIN+NH)", build_update(vec![0x18, 0x0A, 0x00, 0x00], build_attrs(true, true, true, Some(dummy_mp_reach.clone()), None), vec![]), 0),

        // --- Mixed Scenarios (IPv4 Announce + MP_REACH Announcement) ---
        ("IPv4 Announce + MP_REACH + NH", build_update(vec![], build_attrs(true, true, true, Some(dummy_mp_reach.clone()), None), vec![0x18, 0x0A, 0x00, 0x00]), 0),
        ("IPv4 Announce + MP_REACH - NH", build_update(vec![], build_attrs(true, true, false, Some(dummy_mp_reach.clone()), None), vec![0x18, 0x0A, 0x00, 0x00]), 1),
    ];

    for (name, msg, expected_warnings) in scenarios {
        let res = parse_bgp_update_message(msg, false, &asn_len);
        match res {
            Ok(update) => {
                let warnings = update.attributes.validation_warnings();
                assert_eq!(warnings.len(), expected_warnings, "Scenario '{}' failed. Warnings: {:?}", name, warnings);
            }
            Err(e) => panic!("Scenario '{}' failed to parse: {}", name, e),
        }
    }
}
