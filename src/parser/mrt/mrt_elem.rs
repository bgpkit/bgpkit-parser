#![allow(unused)]
//! This module handles converting MRT records into individual per-prefix BGP elements.
//!
//! Each MRT record may contain reachability information for multiple prefixes. This module breaks
//! down MRT records into corresponding BGP elements, and thus allowing users to more conveniently
//! process BGP information on a per-prefix basis.
use bgp_models::bgp::attributes::*;
use bgp_models::bgp::BgpMessage;
use bgp_models::mrt::bgp4mp::Bgp4Mp;
use bgp_models::mrt::tabledump::{Peer, TableDumpV2Message};
use bgp_models::mrt::{MrtMessage, MrtRecord};
use bgp_models::network::{Asn, NetworkPrefix, NextHopAddress};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use itertools::Itertools;
use log::warn;

/// Element type.
///
/// - ANNOUNCE: announcement/reachable prefix
/// - WITHDRAW: withdrawn/unreachable prefix
#[derive(Debug, Clone)]
pub enum ElemType {
    ANNOUNCE,
    WITHDRAW,
}

/// BgpElem represents per-prefix BGP element.
///
/// The information is for per announced/withdrawn prefix.
///
/// Note: it consumes more memory to construct BGP elements due to duplicate information
/// shared between multiple elements of one MRT record.
#[derive(Debug, Clone)]
pub struct BgpElem {
    pub timestamp: f64,
    pub elem_type: ElemType,
    pub peer_ip: IpAddr,
    pub peer_asn: Asn,
    pub prefix: NetworkPrefix,
    pub next_hop: Option<IpAddr>,
    pub as_path: Option<AsPath>,
    pub origin_asns: Option<Vec<Asn>>,
    pub origin: Option<Origin>,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    pub communities: Option<Vec<Community>>,
    pub atomic: Option<AtomicAggregate>,
    pub aggr_asn: Option<Asn>,
    pub aggr_ip: Option<IpAddr>,
}

pub struct Elementor {
    peer_table: Option<HashMap<u32, Peer>>,
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
    attributes: Attributes,
) -> (
    Option<AsPath>,
    Option<AsPath>,
    Option<Origin>,
    Option<IpAddr>,
    Option<u32>,
    Option<u32>,
    Option<Vec<Community>>,
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
    let mut communities = None;
    let mut atomic = Some(AtomicAggregate::NAG);
    let mut aggregator = None;
    let mut announced = None;
    let mut withdrawn = None;

    for (t, v) in attributes {
        match t {
            AttrType::ORIGIN => origin = get_attr_value!(Origin, v),
            AttrType::AS_PATH => as_path = get_attr_value!(AsPath, v),
            AttrType::NEXT_HOP => next_hop = get_attr_value!(NextHop, v),
            AttrType::MULTI_EXIT_DISCRIMINATOR => med = get_attr_value!(MultiExitDiscriminator, v),
            AttrType::LOCAL_PREFERENCE => local_pref = get_attr_value!(LocalPreference, v),
            AttrType::ATOMIC_AGGREGATE => {
                atomic = if let Attribute::AtomicAggregate(x) = v {
                    Some(x)
                } else {
                    Some(AtomicAggregate::NAG)
                }
            }
            AttrType::AGGREGATOR => {
                aggregator = if let Attribute::Aggregator(asn, ip) = v {
                    Some((asn, ip))
                } else {
                    None
                }
            }
            AttrType::COMMUNITIES => communities = get_attr_value!(Communities, v),
            AttrType::MP_REACHABLE_NLRI => announced = get_attr_value!(Nlri, v),
            AttrType::MP_UNREACHABLE_NLRI => withdrawn = get_attr_value!(Nlri, v),
            AttrType::AS4_PATH => as4_path = get_attr_value!(AsPath, v),
            AttrType::AS4_AGGREGATOR => {
                aggregator = if let Attribute::Aggregator(asn, ip) = v {
                    Some((asn, ip))
                } else {
                    None
                }
            }
            _ => {}
        };
    }

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
                        self.peer_table = Some(p.peers_map.clone());
                    }
                    TableDumpV2Message::RibAfiEntries(t) => {
                        let prefix = t.prefix.clone();
                        for e in t.rib_entries {
                            let pid = e.peer_index;
                            let peer = self
                                .peer_table
                                .as_ref()
                                .unwrap()
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
                        let peer_ip = v.peer_ip.clone();
                        let peer_asn = v.peer_asn.clone();
                        match v.bgp_message {
                            BgpMessage::Update(e) => {
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
                                ) = get_relevant_attributes(e.attributes);

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

                                elems.extend(e.announced_prefixes.into_iter().map(|p| BgpElem {
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

                                elems.extend(e.withdrawn_prefixes.into_iter().map(|p| BgpElem {
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
                                }
                            }
                            BgpMessage::Open(_) | BgpMessage::Notification(_) | BgpMessage::KeepAlive(_) => {
                                // ignore Open Notification, and KeepAlive messages
                            }
                        }
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

pub fn option_to_string_communities(o: &Option<Vec<Community>>) -> String {
    if let Some(v) = o {
        v.iter()
            .join(" ")
    } else {
        String::new()
    }
}

impl Display for BgpElem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let t = match self.elem_type {
            ElemType::ANNOUNCE => "A",
            ElemType::WITHDRAW => "W",
        };
        let format = format!(
            "|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|",
            t, &self.timestamp,
            &self.peer_ip,
            &self.peer_asn,
            &self.prefix,
            option_to_string(&self.as_path),
            option_to_string(&self.origin),
            option_to_string(&self.next_hop),
            option_to_string(&self.local_pref),
            option_to_string(&self.med),
            option_to_string_communities(&self.communities),
            option_to_string(&self.atomic),
            option_to_string(&self.aggr_asn),
            option_to_string(&self.aggr_ip),
        );
        write!(f, "{}", format)
    }
}