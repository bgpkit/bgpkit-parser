use bgp_models::bgp::attributes::{AsPathSegment, AtomicAggregate, AttrType, Attribute, Community, Origin, AsPath};
use bgp_models::bgp::BgpMessage;
use bgp_models::mrt::bgp4mp::{Bgp4Mp, Bgp4MpMessage, Bgp4MpStateChange};
use bgp_models::mrt::{MrtMessage, MrtRecord};
use std::collections::HashMap;
use bgp_models::mrt::tabledump::{Peer, RibEntry, TableDumpMessage, TableDumpV2Message};
use bgp_models::network::{Asn, NextHopAddress};
use log::warn;

pub struct BgpdumpFormatter {
    peer_table: Option<HashMap<u32, Peer>>,
}

impl BgpdumpFormatter {
    pub fn new() -> BgpdumpFormatter {
        BgpdumpFormatter { peer_table: None }
    }

    fn format_state_change(&self, _msg: &Bgp4MpStateChange) -> Vec<String> {
        todo!("state change display not implemented")
    }

    fn format_message(&self, msg: &Bgp4MpMessage) -> Vec<String> {
        match &msg.bgp_message {
            BgpMessage::Open(_) => {
                vec![format!("U|O")]
            }
            BgpMessage::Update(m) => {
                let mut elems = vec![];
                let mp = attr_map_to_str_map(&m.attributes);
                let mut path_str = "".to_string();
                // if let Some(p) = mp.get(&AttrType::AS_PATH) {
                //     path_str = p.clone();
                // }
                // if let Some(p) = mp.get(&AttrType::AS4_PATH) {
                //     path_str = p.clone();
                // }
                let aspath = merge_aspath_as4path(m.attributes.get(&AttrType::AS_PATH), m.attributes.get(&AttrType::AS4_PATH));
                if let Some(p) = aspath {
                    path_str = aspath_to_string(&p)
                }

                let mut aggr_str = "".to_string();
                if let Some(a) = mp.get(&AttrType::AGGREGATOR) {
                    aggr_str = a.clone();
                }
                if let Some(a) = mp.get(&AttrType::AS4_AGGREGATOR) {
                    aggr_str = a.clone();
                }

                let origin = mp.get(&AttrType::ORIGIN).unwrap_or(&"".to_string()).clone();
                let nexthop = mp.get(&AttrType::NEXT_HOP)
                    .unwrap_or(&"".to_string())
                    .clone();
                let local_pref = mp.get(&AttrType::LOCAL_PREFERENCE)
                    .unwrap_or(&"0".to_string())
                    .clone();
                let med = mp.get(&AttrType::MULTI_EXIT_DISCRIMINATOR)
                    .unwrap_or(&"0".to_string())
                    .clone();
                let communities = mp.get(&AttrType::COMMUNITIES)
                    .unwrap_or(&"".to_string())
                    .clone();
                let atomic = mp.get(&AttrType::ATOMIC_AGGREGATE)
                    .unwrap_or(&"NAG".to_string())
                    .clone();


                if let Some(Attribute::MpReachableNlri(nlri)) = m.attributes.get(&AttrType::MP_REACHABLE_NLRI) {
                    elems.extend(nlri.prefixes.iter().map(|p| {
                        format!(
                            "A|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|",
                            msg.peer_ip.to_string(),
                            msg.peer_asn.to_string(),
                            p,
                            &path_str,
                            &origin,
                            &nexthop,
                            &local_pref,
                            &med,
                            &communities,
                            &atomic,
                            &aggr_str
                        )
                    }));
                }

                if let Some(Attribute::MpUnreachableNlri(nlri)) = m.attributes.get(&AttrType::MP_UNREACHABLE_NLRI) {
                    elems.extend(nlri.prefixes.iter().map(|p| {
                        format!(
                            "W|{}|{}|{}",
                            msg.peer_ip.to_string(),
                            msg.peer_asn.to_string(),
                            p,
                        )
                    }));
                }

                elems.extend(m.announced_prefixes.iter().map(|p| {
                    format!(
                        "A|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|",
                        msg.peer_ip.to_string(),
                        msg.peer_asn.to_string(),
                        p,
                        &path_str,
                        &origin,
                        &nexthop,
                        &local_pref,
                        &med,
                        &communities,
                        &atomic,
                        &aggr_str
                    )
                }));

                elems.extend(m.withdrawn_prefixes.iter().map(|p|{
                    format!(
                        "W|{}|{}|{}",
                        msg.peer_ip.to_string(),
                        msg.peer_asn.to_string(),
                        p,
                    )
                }));


                elems
            }
            BgpMessage::Notification(_) => {
                vec![format!("U|N")]
            }
            BgpMessage::KeepAlive(_) => {
                vec![format!("U|K")]
            }
        }
    }

    pub fn to_elems(&mut self, mrt_record: &MrtRecord) -> Vec<String> {
        let mrt = mrt_record;
        let timestamp = &mrt.common_header.timestamp;
        let timestamp_micro = &mrt.common_header.microsecond_timestamp;
        match &mrt.message {
            MrtMessage::TableDumpMessage(msg) => {
                let header = format!("TABLE_DUMP|{}|B", timestamp);
                let mut entries: Vec<String> = vec![];

                let mp = attr_map_to_str_map(&msg.attributes);
                let mut path_str = "".to_string();
                if let Some(p) = mp.get(&AttrType::AS_PATH) {
                    path_str = p.clone();
                }

                let origin = mp.get(&AttrType::ORIGIN).unwrap_or(&"".to_string()).clone();
                let mut nexthop_str = mp.get(&AttrType::NEXT_HOP)
                    .unwrap_or(&"".to_string())
                    .clone();
                if nexthop_str ==""{
                    if let Some(Attribute::MpReachableNlri(nlri)) = msg.attributes.get(&AttrType::MP_REACHABLE_NLRI) {
                        if let Some(next_hop) = &nlri.next_hop {
                            nexthop_str = match next_hop{
                                NextHopAddress::Ipv4(v) => { v.to_string()}
                                NextHopAddress::Ipv6(v) => { v.to_string()}
                                NextHopAddress::Ipv6LinkLocal(v1, v2) => { v1.to_string()}
                            };
                        }
                    }
                }
                let local_pref = mp.get(&AttrType::LOCAL_PREFERENCE)
                    .unwrap_or(&"0".to_string())
                    .clone();
                let med = mp.get(&AttrType::MULTI_EXIT_DISCRIMINATOR)
                    .unwrap_or(&"0".to_string())
                    .clone();
                let communities = mp.get(&AttrType::COMMUNITIES)
                    .unwrap_or(&"".to_string())
                    .clone();
                let atomic = mp.get(&AttrType::ATOMIC_AGGREGATE)
                    .unwrap_or(&"NAG".to_string())
                    .clone();

                let mut aggr_str = "".to_string();
                if let Some(a) = mp.get(&AttrType::AGGREGATOR) {
                    aggr_str = a.clone();
                }
                if let Some(a) = mp.get(&AttrType::AS4_AGGREGATOR) {
                    aggr_str = a.clone();
                }
                match msg {
                    &_ => {}
                }
                vec![
                    format!("{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|",
                        header,
                                     msg.peer_address, msg.peer_asn, msg.prefix,
                                     path_str,
                                     &origin,
                                     &nexthop_str,
                                     &local_pref,
                                     &med,
                                     &communities,
                                     &atomic,
                                     &aggr_str
                )
                ]
            }

            MrtMessage::TableDumpV2Message(msg) => {
                let header = format!("TABLE_DUMP2|{}|B", timestamp);
                let mut entries: Vec<String> = vec![];
                match msg {
                    TableDumpV2Message::PeerIndexTable(p) => {
                        self.peer_table = Some(p.peers_map.clone());
                    }
                    TableDumpV2Message::RibAfiEntries(t) => {
                        for e in &t.rib_entries {
                            let pid = e.peer_index;
                            let peer = self.peer_table.as_ref().unwrap().get(&(pid as u32)).unwrap();

                            let prefix_str = format!("{}",t.prefix);

                            let mp = attr_map_to_str_map(&e.attributes);
                            let mut path_str = "".to_string();
                            let aspath = merge_aspath_as4path(e.attributes.get(&AttrType::AS_PATH), e.attributes.get(&AttrType::AS4_PATH));
                            if let Some(p) = aspath {
                                path_str = aspath_to_string(&p)
                            }


                            let origin = mp.get(&AttrType::ORIGIN).unwrap_or(&"".to_string()).clone();
                            let mut nexthop_str = mp.get(&AttrType::NEXT_HOP)
                                .unwrap_or(&"".to_string())
                                .clone();
                            if nexthop_str ==""{
                                if let Some(Attribute::MpReachableNlri(nlri)) = e.attributes.get(&AttrType::MP_REACHABLE_NLRI) {
                                    if let Some(next_hop) = &nlri.next_hop {
                                        nexthop_str = match next_hop{
                                            NextHopAddress::Ipv4(v) => { v.to_string()}
                                            NextHopAddress::Ipv6(v) => { v.to_string()}
                                            NextHopAddress::Ipv6LinkLocal(v1, v2) => { v1.to_string()}
                                        };
                                    }
                                }
                            }
                            let local_pref = mp.get(&AttrType::LOCAL_PREFERENCE)
                                .unwrap_or(&"0".to_string())
                                .clone();
                            let med = mp.get(&AttrType::MULTI_EXIT_DISCRIMINATOR)
                                .unwrap_or(&"0".to_string())
                                .clone();
                            let communities = mp.get(&AttrType::COMMUNITIES)
                                .unwrap_or(&"".to_string())
                                .clone();
                            let atomic = mp.get(&AttrType::ATOMIC_AGGREGATE)
                                .unwrap_or(&"NAG".to_string())
                                .clone();

                            let mut aggr_str = "".to_string();
                            if let Some(a) = mp.get(&AttrType::AGGREGATOR) {
                                aggr_str = a.clone();
                            }
                            if let Some(a) = mp.get(&AttrType::AS4_AGGREGATOR) {
                                aggr_str = a.clone();
                            }

                            entries.push(format!("{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|",
                                                 peer.peer_address, peer.peer_asn, prefix_str,
                                                 path_str,
                                                 &origin,
                                                 &nexthop_str,
                                                 &local_pref,
                                                 &med,
                                                 &communities,
                                                 &atomic,
                                                 &aggr_str
                            ));
                        }
                    }
                    TableDumpV2Message::RibGenericEntries(t) => {}
                }

                entries.iter().map(|e| format!("{}|{}", header, e)).collect::<Vec<String>>()
            }

            MrtMessage::Bgp4Mp(msg) => {
                let header = if let Some(micro) = timestamp_micro {
                    let m = (micro.clone() as f64)/1000000.0;
                    let t_micro: f64 = timestamp.clone() as f64 + m;
                    format!("BGP4MP_ET|{:.6}", t_micro)
                } else {
                    format!("BGP4MP|{}", timestamp)
                };

                match msg {
                    Bgp4Mp::Bgp4MpStateChange(v) | Bgp4Mp::Bgp4MpStateChangeAs4(v) => {
                        self.format_state_change(v)
                    }
                    Bgp4Mp::Bgp4MpMessage(v)
                    | Bgp4Mp::Bgp4MpMessageLocal(v)
                    | Bgp4Mp::Bgp4MpMessageAs4(v)
                    | Bgp4Mp::Bgp4MpMessageAs4Local(v) => self.format_message(v),
                }
                .iter()
                .map(|s| format!("{}|{}", &header, s))
                .collect::<Vec<String>>()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;
    use bzip2::read::BzDecoder;
    use std::io::{BufRead, BufReader};
    use std::fs::File;
    use env_logger::Env;

    #[test]
    fn test_full_file_comparison_old() {
        use log::info;
        env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

        let file = File::open("examples/updates.20011026.1352.bz2").unwrap();
        let reader = BzDecoder::new(&file);
        let parser = Parser::new(reader);

        info!("reading via prism");
        let mut formatter = BgpdumpFormatter::new();
        let mut lines1: Vec<String> = parser.into_iter().map(|record|{
            formatter.to_elems(&record)
        }).flat_map(|x|x).collect::<Vec<String>>();

        info!("reading via bgpdump");
        let file2 = File::open("examples/updates.20011026.1352.bgpdump.txt.bz2").unwrap();
        let reader2 = BzDecoder::new(file2);
        let mut lines2 = BufReader::new(reader2).lines()
            .filter_map(|x|x.ok())
            .collect::<Vec<String>>();
        info!("sorting bgpdump results");
        lines1.sort();
        lines2.sort();
        info!("comapring results");

        let mut iter1 = lines1.iter();
        for line1 in lines2 {
            let line2 = iter1.next().unwrap().clone();
            assert_eq!(line1, line2);
        }
    }

    #[test]
    fn test_full_file_comparison_new() {
        use log::info;
        env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

        info!("reading via bgpdump");
        let file2 = File::open("examples/updates.20210101.0000.bgpdump.txt").unwrap();
        let mut lines2 = BufReader::new(file2).lines()
            .filter_map(|x|x.ok())
            .collect::<Vec<String>>();
        lines2.sort();
        let mut iter2 = lines2.iter();

        let file = File::open("examples/updates.20210101.0000.bz2").unwrap();
        let reader = BzDecoder::new(&file);
        let parser = Parser::new(reader);

        info!("reading via prism");
        let mut formatter = BgpdumpFormatter::new();
        let mut lines1: Vec<String> = parser.into_iter().map(|record|{
            formatter.to_elems(&record)
        }).flat_map(|x|x).collect::<Vec<String>>();

        lines1.sort();

        for prism_line in lines1 {
            let bgpdump_line = iter2.next().unwrap().clone();
            if prism_line != bgpdump_line {
                // dbg!(prism_line, bgpdump_line);
            }
            assert_eq!(prism_line, bgpdump_line)
        }
    }

    #[test]
    fn test_full_file_comparison_ribs_new() {
        use log::info;
        env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

        info!("reading via bgpdump");
        let file2 = File::open("examples/table-dump-v2-rib.20140604.1600.bgpdump.txt").unwrap();
        let mut lines2 = BufReader::new(file2).lines()
            .filter_map(|x|x.ok())
            .collect::<Vec<String>>();
        lines2.sort();
        let mut iter2 = lines2.iter();

        let file = File::open("examples/table-dump-v2-rib.20140604.1600.bz2").unwrap();
        let reader = BzDecoder::new(&file);
        let parser = Parser::new(reader);

        info!("reading via prism");
        let mut formatter = BgpdumpFormatter::new();
        let mut lines1: Vec<String> = parser.into_iter().map(|record|{
                formatter.to_elems(&record)
        }).flat_map(|x|x).collect::<Vec<String>>();

        lines1.sort();

        for prism_line in lines1 {
            let bgpdump_line = iter2.next().unwrap().clone();
            if prism_line != bgpdump_line {
                // dbg!(prism_line, bgpdump_line);
            }
            assert_eq!(prism_line, bgpdump_line)
        }
    }

    #[test]
    fn test_full_file_comparison_ribs_old() {
        use log::info;
        env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

        info!("reading via bgpdump");
        let file2 = File::open("examples/table-dump-rib.20011026.1648.bgpdump.txt").unwrap();
        let mut lines2 = BufReader::new(file2).lines()
            .filter_map(|x|x.ok())
            .collect::<Vec<String>>();
        lines2.sort();
        let mut iter2 = lines2.iter();

        let file = File::open("examples/table-dump-rib.20011026.1648.bz2").unwrap();
        let reader = BzDecoder::new(&file);
        let parser = Parser::new(reader);

        info!("reading via prism");
        let mut formatter = BgpdumpFormatter::new();
        let mut lines1: Vec<String> = parser.into_iter().map(|record|{
            formatter.to_elems(&record)
        }).flat_map(|x|x).collect::<Vec<String>>();

        lines1.sort();

        for prism_line in lines1 {
            let bgpdump_line = iter2.next().unwrap().clone();
            if prism_line != bgpdump_line {
                // dbg!(prism_line, bgpdump_line);
            }
            assert_eq!(prism_line, bgpdump_line)
        }
    }
}
