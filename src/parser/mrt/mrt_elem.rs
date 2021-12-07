#![allow(unused)]
//! This module handles converting MRT records into individual per-prefix BGP elements.
//!
//! Each MRT record may contain reachability information for multiple prefixes. This module breaks
//! down MRT records into corresponding BGP elements, and thus allowing users to more conveniently
//! process BGP information on a per-prefix basis.
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use bgp_models::prelude::*;
use itertools::Itertools;
use log::warn;
use crate::parser::bgp::messages::parse_bgp_update_message;

pub struct Elementor {
    peer_table: Option<PeerIndexTable>,
}

// use macro_rules! <name of macro>{<Body>}
macro_rules! get_attr_value {
    ($a:tt, $b:expr) => {
        if let Attribute::$a(x) = $b {
            Some(x)
        } else {
            None
        }
    };
}

fn get_relevant_attributes(
    attributes: Vec<Attribute>,
) -> (
    Option<AsPath>,
    Option<AsPath>,
    Option<Origin>,
    Option<IpAddr>,
    Option<u32>,
    Option<u32>,
    Option<Vec<MetaCommunity>>,
    Option<AtomicAggregate>,
    Option<(Asn, IpAddr)>,
    Option<Nlri>,
    Option<Nlri>,
) {
    let mut as_path = None;
    let mut as4_path = None;
    let mut origin = None;
    let mut next_hop = None;
    let mut local_pref = Some(0);
    let mut med = Some(0);
    let mut atomic = Some(AtomicAggregate::NAG);
    let mut aggregator = None;
    let mut announced = None;
    let mut withdrawn = None;

    let mut communities_vec: Vec<MetaCommunity> = vec![];

    for attr in attributes {
        match attr {
            Attribute::Origin(v) => {origin = Some(v)}
            Attribute::AsPath(v) => {as_path = Some(v)}
            Attribute::As4Path(v) => {as4_path = Some(v)}
            Attribute::NextHop(v) => {next_hop = Some(v)}
            Attribute::MultiExitDiscriminator(v) => {med = Some(v)}
            Attribute::LocalPreference(v) => {local_pref = Some(v)}
            Attribute::AtomicAggregate(v) => {atomic = Some(v)}
            Attribute::Communities(v) => {communities_vec.extend(v.into_iter().map(|x| MetaCommunity::Community(x)).collect::<Vec<MetaCommunity>>())}
            Attribute::ExtendedCommunities(v) => {communities_vec.extend(v.into_iter().map(|x| MetaCommunity::ExtendedCommunity(x)).collect::<Vec<MetaCommunity>>())}
            Attribute::LargeCommunities(v) => {communities_vec.extend(v.into_iter().map(|x| MetaCommunity::LargeCommunity(x)).collect::<Vec<MetaCommunity>>())}
            Attribute::Aggregator(v, v2) => {aggregator = Some((v,v2))}
            Attribute::MpReachNlri(nlri) => {announced = Some(nlri)}
            Attribute::MpUnreachNlri(nlri) => {withdrawn = Some(nlri)}
            Attribute::OriginatorId(_) | Attribute::Clusters(_)| Attribute::Development(_) => {}
        };
    }

    let communities = match communities_vec.len()>0 {
        true => Some(communities_vec),
        false => None,
    };

    (
        as_path,
        as4_path,
        origin,
        next_hop,
        local_pref,
        med,
        communities,
        atomic,
        aggregator,
        announced,
        withdrawn,
    )
}

impl Elementor {
    pub fn new() -> Elementor {
        Elementor { peer_table: None }
    }

    /// Convert a [BgpMessage] to a vector of [BgpElem]s.
    ///
    /// A [BgpMessage] may include `Update`, `Open`, `Notification` or `KeepAlive` messages,
    /// and only `Update` message contains [BgpElem]s.
    pub fn bgp_to_elems(msg: BgpMessage, timestamp: f64, peer_ip: &IpAddr, peer_asn: &Asn) -> Vec<BgpElem> {
        match msg {
            BgpMessage::Update(msg) => {
                Elementor::bgp_update_to_elems(msg, timestamp, peer_ip, peer_asn)
            }
            BgpMessage::Open(_) | BgpMessage::Notification(_) | BgpMessage::KeepAlive(_) => {
                vec![]
            }
        }
    }

    /// Convert a [BgpUpdateMessage] to a vector of [BgpElem]s.
    pub fn bgp_update_to_elems(msg: BgpUpdateMessage, timestamp: f64, peer_ip: &IpAddr, peer_asn: &Asn) -> Vec<BgpElem> {
        let mut elems = vec![];

        let (
            as_path,
            as4_path, // Table dump v1 does not have 4-byte AS number
            origin,
            next_hop,
            local_pref,
            med,
            communities,
            atomic,
            aggregator,
            announced,
            withdrawn,
        ) = get_relevant_attributes(msg.attributes);

        let path = match (as_path, as4_path) {
            (None, None) => None,
            (Some(v), None) => Some(v),
            (None, Some(v)) => Some(v),
            (Some(v1), Some(v2)) => {
                Some(AsPath::merge_aspath_as4path(&v1, &v2).unwrap())
            }
        };

        let origin_asns = match &path {
            None => None,
            Some(p) => p.get_origin()
        };

        elems.extend(msg.announced_prefixes.into_iter().map(|p| BgpElem {
            timestamp: timestamp.clone(),
            elem_type: ElemType::ANNOUNCE,
            peer_ip: peer_ip.clone(),
            peer_asn: peer_asn.clone(),
            prefix: p,
            next_hop: next_hop.clone(),
            as_path: path.clone(),
            origin_asns: origin_asns.clone(),
            origin: origin.clone(),
            local_pref: local_pref.clone(),
            med: med.clone(),
            communities: communities.clone(),
            atomic: atomic.clone(),
            aggr_asn: if let Some(v) = &aggregator {
                Some(v.0.clone())
            } else {
                None
            },
            aggr_ip: if let Some(v) = &aggregator {
                Some(v.1.clone())
            } else {
                None
            },
        }));

        if let Some(nlri) = announced {
            elems.extend(nlri.prefixes.into_iter().map(|p| BgpElem {
                timestamp: timestamp.clone(),
                elem_type: ElemType::ANNOUNCE,
                peer_ip: peer_ip.clone(),
                peer_asn: peer_asn.clone(),
                prefix: p,
                next_hop: next_hop.clone(),
                as_path: path.clone(),
                origin: origin.clone(),
                origin_asns: origin_asns.clone(),
                local_pref: local_pref.clone(),
                med: med.clone(),
                communities: communities.clone(),
                atomic: atomic.clone(),
                aggr_asn: if let Some(v) = &aggregator {
                    Some(v.0.clone())
                } else {
                    None
                },
                aggr_ip: if let Some(v) = &aggregator {
                    Some(v.1.clone())
                } else {
                    None
                },
            }));
        }

        elems.extend(msg.withdrawn_prefixes.into_iter().map(|p| BgpElem {
            timestamp: timestamp.clone(),
            elem_type: ElemType::WITHDRAW,
            peer_ip: peer_ip.clone(),
            peer_asn: peer_asn.clone(),
            prefix: p,
            next_hop: None,
            as_path: None,
            origin: None,
            origin_asns: None,
            local_pref: None,
            med: None,
            communities: None,
            atomic: None,
            aggr_asn: None,
            aggr_ip: None,
        }));
        if let Some(nlri) = withdrawn {
            elems.extend(nlri.prefixes.into_iter().map(|p| BgpElem {
                timestamp: timestamp.clone(),
                elem_type: ElemType::WITHDRAW,
                peer_ip: peer_ip.clone(),
                peer_asn: peer_asn.clone(),
                prefix: p,
                next_hop: None,
                as_path: None,
                origin: None,
                origin_asns: None,
                local_pref: None,
                med: None,
                communities: None,
                atomic: None,
                aggr_asn: None,
                aggr_ip: None,
            }));
        };
        elems
    }


    /// Convert a [MrtRecord] to a vector of [BgpElem]s.
    pub fn record_to_elems(&mut self, record: MrtRecord) -> Vec<BgpElem> {
        let mut elems = vec![];
        let t = record.common_header.timestamp.clone();
        let timestamp :f64 = if let Some(micro) = &record.common_header.microsecond_timestamp {
            let m = (micro.clone() as f64)/1000000.0;
            t as f64 + m
        } else {
            f64::from(t)
        };

        match record.message {
            MrtMessage::TableDumpMessage(msg) => {
                let (
                    as_path,
                    _as4_path, // Table dump v1 does not have 4-byte AS number
                    origin,
                    next_hop,
                    local_pref,
                    med,
                    communities,
                    atomic,
                    aggregator,
                    _announced,
                    _withdrawn,
                ) = get_relevant_attributes(msg.attributes);

                let origin_asns = match &as_path {
                    None => None,
                    Some(p) => p.get_origin()
                };

                elems.push(BgpElem {
                    timestamp: timestamp.clone(),
                    elem_type: ElemType::ANNOUNCE,
                    peer_ip: msg.peer_address,
                    peer_asn: msg.peer_asn,
                    prefix: msg.prefix,
                    next_hop,
                    as_path,
                    origin,
                    origin_asns,
                    local_pref,
                    med,
                    communities,
                    atomic,
                    aggr_asn: if let Some(v) = aggregator {
                        Some(v.0)
                    } else {
                        None
                    },
                    aggr_ip: if let Some(v) = aggregator {
                        Some(v.1)
                    } else {
                        None
                    },
                });
            }

            MrtMessage::TableDumpV2Message(msg) => {
                match msg {
                    TableDumpV2Message::PeerIndexTable(p) => {
                        self.peer_table = Some(p);
                    }
                    TableDumpV2Message::RibAfiEntries(t) => {
                        let prefix = t.prefix.clone();
                        for e in t.rib_entries {
                            let pid = e.peer_index;
                            let peer = self
                                .peer_table
                                .as_ref()
                                .unwrap()
                                .peers_map
                                .get(&(pid as u32))
                                .unwrap();
                            let (
                                as_path,
                                as4_path, // Table dump v1 does not have 4-byte AS number
                                origin,
                                next_hop,
                                local_pref,
                                med,
                                communities,
                                atomic,
                                aggregator,
                                announced,
                                _withdrawn,
                            ) = get_relevant_attributes(e.attributes);

                            let path = match (as_path, as4_path) {
                                (None, None) => None,
                                (Some(v), None) => Some(v),
                                (None, Some(v)) => Some(v),
                                (Some(v1), Some(v2)) => {
                                    Some(AsPath::merge_aspath_as4path(&v1, &v2).unwrap())
                                }
                            };

                            let next = match next_hop {
                                None => {
                                    if let Some(v) = announced {
                                        if let Some(h) = v.next_hop {
                                            match h {
                                                NextHopAddress::Ipv4(v) => {
                                                    Some(IpAddr::from(v.clone()))
                                                }
                                                NextHopAddress::Ipv6(v) => {
                                                    Some(IpAddr::from(v.clone()))
                                                }
                                                NextHopAddress::Ipv6LinkLocal(v, _) => {
                                                    Some(IpAddr::from(v.clone()))
                                                }
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                }
                                Some(v) => Some(v),
                            };


                            let origin_asns = match &path {
                                None => None,
                                Some(p) => p.get_origin()
                            };

                            elems.push(BgpElem {
                                timestamp: timestamp.clone(),
                                elem_type: ElemType::ANNOUNCE,
                                peer_ip: peer.peer_address,
                                peer_asn: peer.peer_asn,
                                prefix: prefix.clone(),
                                next_hop: next,
                                as_path: path,
                                origin,
                                origin_asns,
                                local_pref,
                                med,
                                communities,
                                atomic,
                                aggr_asn: if let Some(v) = aggregator {
                                    Some(v.0)
                                } else {
                                    None
                                },
                                aggr_ip: if let Some(v) = aggregator {
                                    Some(v.1)
                                } else {
                                    None
                                },
                            });
                        }
                    }
                    TableDumpV2Message::RibGenericEntries(_t) => {
                        warn!("to_elem for TableDumpV2Message::RibGenericEntries not yet implemented");
                    }
                }
            }
            MrtMessage::Bgp4Mp(msg) => {
                match msg {
                    Bgp4Mp::Bgp4MpStateChange(_v) | Bgp4Mp::Bgp4MpStateChangeAs4(_v) => {}

                    Bgp4Mp::Bgp4MpMessage(v)
                    | Bgp4Mp::Bgp4MpMessageLocal(v)
                    | Bgp4Mp::Bgp4MpMessageAs4(v)
                    | Bgp4Mp::Bgp4MpMessageAs4Local(v) => {
                        elems.extend(
                            Elementor::bgp_to_elems(v.bgp_message, timestamp, &v.peer_ip, &v.peer_asn)
                        );
                    }
                }
            }
        }
        elems
    }
}

#[inline(always)]
pub fn option_to_string<T>(o: &Option<T>) -> String
where
    T: Display,
{
    if let Some(v) = o {
        v.to_string()
    } else {
        String::new()
    }
}