#![allow(unused)]
//! This module handles converting MRT records into individual per-prefix BGP elements.
//!
//! Each MRT record may contain reachability information for multiple prefixes. This module breaks
//! down MRT records into corresponding BGP elements, and thus allowing users to more conveniently
//! process BGP information on a per-prefix basis.
use crate::models::*;
use crate::parser::bgp::messages::parse_bgp_update_message;
use crate::ParserError;
use crate::ParserError::ParseError;
use itertools::Itertools;
use log::{error, warn};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Default, Debug, Clone)]
pub struct Elementor {
    pub peer_table: Option<PeerIndexTable>,
}

/// Error returned by [`Elementor::record_to_elems_iter`].
#[derive(Debug)]
pub enum ElemError {
    /// The record contains a [`PeerIndexTable`]. The contained table can be
    /// passed to [`Elementor::with_peer_table`] to create an initialized elementor.
    UnexpectedPeerIndexTable(PeerIndexTable),
    /// A peer table is required for processing TableDumpV2 RIB entries,
    /// but none has been set on this elementor.
    MissingPeerTable,
    /// The record contains a [`RibGenericEntries`] which is not yet supported.
    UnsupportedRibGeneric,
}

impl Display for ElemError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ElemError::UnexpectedPeerIndexTable(_) => {
                write!(f, "unexpected PeerIndexTable record")
            }
            ElemError::MissingPeerTable => {
                write!(
                    f,
                    "peer table not set; call set_peer_table or use with_peer_table first"
                )
            }
            ElemError::UnsupportedRibGeneric => {
                write!(f, "RibGenericEntries not yet supported")
            }
        }
    }
}

impl std::error::Error for ElemError {}

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

#[allow(clippy::type_complexity)]
fn get_relevant_attributes(
    attributes: Attributes,
) -> (
    Option<AsPath>,
    Option<AsPath>,
    Option<Origin>,
    Option<IpAddr>,
    Option<u32>,
    Option<u32>,
    Option<Vec<MetaCommunity>>,
    bool,
    Option<(Asn, BgpIdentifier)>,
    Option<Nlri>,
    Option<Nlri>,
    Option<Asn>,
    Option<Vec<AttrRaw>>,
    Option<Vec<AttrRaw>>,
) {
    let mut as_path = None;
    let mut as4_path = None;
    let mut origin = None;
    let mut next_hop = None;
    let mut local_pref = Some(0);
    let mut med = Some(0);
    let mut atomic = false;
    let mut aggregator = None;
    let mut announced = None;
    let mut withdrawn = None;
    let mut otc = None;
    let mut unknown = vec![];
    let mut deprecated = vec![];

    let mut communities_vec: Vec<MetaCommunity> = vec![];

    for attr in attributes {
        match attr {
            AttributeValue::Origin(v) => origin = Some(v),
            AttributeValue::AsPath {
                path,
                is_as4: false,
            } => as_path = Some(path),
            AttributeValue::AsPath { path, is_as4: true } => as4_path = Some(path),
            AttributeValue::NextHop(v) => next_hop = Some(v),
            AttributeValue::MultiExitDiscriminator(v) => med = Some(v),
            AttributeValue::LocalPreference(v) => local_pref = Some(v),
            AttributeValue::AtomicAggregate => atomic = true,
            AttributeValue::Communities(v) => communities_vec.extend(
                v.into_iter()
                    .map(MetaCommunity::Plain)
                    .collect::<Vec<MetaCommunity>>(),
            ),
            AttributeValue::ExtendedCommunities(v) => communities_vec.extend(
                v.into_iter()
                    .map(MetaCommunity::Extended)
                    .collect::<Vec<MetaCommunity>>(),
            ),
            AttributeValue::Ipv6AddressSpecificExtendedCommunities(v) => communities_vec.extend(
                v.into_iter()
                    .map(MetaCommunity::Ipv6Extended)
                    .collect::<Vec<MetaCommunity>>(),
            ),
            AttributeValue::LargeCommunities(v) => communities_vec.extend(
                v.into_iter()
                    .map(MetaCommunity::Large)
                    .collect::<Vec<MetaCommunity>>(),
            ),
            AttributeValue::Aggregator { asn, id, .. } => aggregator = Some((asn, id)),
            AttributeValue::MpReachNlri(nlri) => announced = Some(nlri),
            AttributeValue::MpUnreachNlri(nlri) => withdrawn = Some(nlri),
            AttributeValue::OnlyToCustomer(o) => otc = Some(o),

            AttributeValue::Unknown(t) => {
                unknown.push(t);
            }
            AttributeValue::Deprecated(t) => {
                deprecated.push(t);
            }

            AttributeValue::OriginatorId(_)
            | AttributeValue::Clusters(_)
            | AttributeValue::Development(_)
            | AttributeValue::LinkState(_)
            | AttributeValue::TunnelEncapsulation(_) => {}
        };
    }

    let communities = match !communities_vec.is_empty() {
        true => Some(communities_vec),
        false => None,
    };

    // If the next_hop is not set, we try to get it from the announced NLRI.
    let next_hop = next_hop.or_else(|| {
        announced.as_ref().and_then(|v| {
            v.next_hop.as_ref().map(|h| match h {
                NextHopAddress::Ipv4(v) => IpAddr::from(*v),
                NextHopAddress::Ipv6(v) => IpAddr::from(*v),
                NextHopAddress::Ipv6LinkLocal(v, _) => IpAddr::from(*v),
                // RFC 8950: VPN next hops - return the IPv6 address part
                NextHopAddress::VpnIpv6(_, v) => IpAddr::from(*v),
                NextHopAddress::VpnIpv6LinkLocal(_, v, _, _) => IpAddr::from(*v),
            })
        })
    });

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
        otc,
        if unknown.is_empty() {
            None
        } else {
            Some(unknown)
        },
        if deprecated.is_empty() {
            None
        } else {
            Some(deprecated)
        },
    )
}

fn rib_entry_to_elem(prefix: NetworkPrefix, peer: &Peer, entry: RibEntry) -> BgpElem {
    let (
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
        _withdrawn,
        only_to_customer,
        unknown,
        deprecated,
    ) = get_relevant_attributes(entry.attributes);

    let path = match (as_path, as4_path) {
        (None, None) => None,
        (Some(v), None) => Some(v),
        (None, Some(v)) => Some(v),
        (Some(v1), Some(v2)) => Some(AsPath::merge_aspath_as4path(&v1, &v2)),
    };

    let next_hop = match next_hop {
        Some(v) => Some(v),
        None => announced.and_then(|v| {
            v.next_hop.map(|h| match h {
                NextHopAddress::Ipv4(v) => IpAddr::from(v),
                NextHopAddress::Ipv6(v) => IpAddr::from(v),
                NextHopAddress::Ipv6LinkLocal(v, _) => IpAddr::from(v),
                NextHopAddress::VpnIpv6(_, v) => IpAddr::from(v),
                NextHopAddress::VpnIpv6LinkLocal(_, v, _, _) => IpAddr::from(v),
            })
        }),
    };

    let origin_asns = path
        .as_ref()
        .map(|as_path| as_path.iter_origins().collect());

    BgpElem {
        timestamp: entry.originated_time as f64,
        elem_type: ElemType::ANNOUNCE,
        peer_ip: peer.peer_ip,
        peer_asn: peer.peer_asn,
        prefix,
        next_hop,
        as_path: path,
        origin,
        origin_asns,
        local_pref,
        med,
        communities,
        atomic,
        aggr_asn: aggregator.map(|v| v.0),
        aggr_ip: aggregator.map(|v| v.1),
        only_to_customer,
        unknown,
        deprecated,
    }
}

/// Iterator over [`BgpElem`]s produced from a single [`MrtRecord`],
/// without requiring a mutable reference to the [`Elementor`].
///
/// This avoids allocating a `Vec` for the common RIB table dump case
/// by lazily converting each [`RibEntry`] into a [`BgpElem`] on demand.
pub enum RecordElemIter<'a> {
    #[doc(hidden)]
    Empty,
    #[doc(hidden)]
    TableDump(Option<BgpElem>),
    #[doc(hidden)]
    RibAfi {
        peer_table: &'a PeerIndexTable,
        prefix: NetworkPrefix,
        entries: std::vec::IntoIter<RibEntry>,
    },
    #[doc(hidden)]
    Bgp4Mp(BgpUpdateElemIter),
}

impl Iterator for RecordElemIter<'_> {
    type Item = BgpElem;

    fn next(&mut self) -> Option<BgpElem> {
        match self {
            RecordElemIter::Empty => None,
            RecordElemIter::TableDump(elem) => elem.take(),
            RecordElemIter::Bgp4Mp(iter) => iter.next(),
            RecordElemIter::RibAfi {
                peer_table,
                prefix,
                entries,
            } => {
                let entry = entries.next()?;
                let pid = entry.peer_index;
                match peer_table.get_peer_by_id(&pid) {
                    Some(peer) => Some(rib_entry_to_elem(*prefix, peer, entry)),
                    None => {
                        error!("peer ID {} not found in peer_index table", pid);
                        *self = RecordElemIter::Empty;
                        None
                    }
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            RecordElemIter::Empty => (0, Some(0)),
            RecordElemIter::TableDump(elem) => {
                let n = elem.is_some() as usize;
                (n, Some(n))
            }
            RecordElemIter::Bgp4Mp(iter) => iter.size_hint(),
            RecordElemIter::RibAfi { entries, .. } => (0, Some(entries.len())),
        }
    }
}

/// Iterator over [`BgpElem`]s produced from a [`BgpUpdateMessage`],
/// avoiding allocation by lazily yielding elements from announced and
/// withdrawn prefixes in two phases.
pub struct BgpUpdateElemIter {
    timestamp: f64,
    peer_ip: IpAddr,
    peer_asn: Asn,
    only_to_customer: Option<Asn>,
    // Announce-specific shared attributes
    path: Option<AsPath>,
    origin_asns: Option<Vec<Asn>>,
    origin: Option<Origin>,
    next_hop: Option<IpAddr>,
    local_pref: Option<u32>,
    med: Option<u32>,
    communities: Option<Vec<MetaCommunity>>,
    atomic: bool,
    aggr_asn: Option<Asn>,
    aggr_ip: Option<BgpIdentifier>,
    unknown: Option<Vec<AttrRaw>>,
    deprecated: Option<Vec<AttrRaw>>,
    // Prefix iterators (two chained sources each)
    announced: std::iter::Chain<std::vec::IntoIter<NetworkPrefix>, std::vec::IntoIter<NetworkPrefix>>,
    withdrawn: std::iter::Chain<std::vec::IntoIter<NetworkPrefix>, std::vec::IntoIter<NetworkPrefix>>,
    in_withdrawn_phase: bool,
}

impl Iterator for BgpUpdateElemIter {
    type Item = BgpElem;

    fn next(&mut self) -> Option<BgpElem> {
        if !self.in_withdrawn_phase {
            if let Some(prefix) = self.announced.next() {
                return Some(BgpElem {
                    timestamp: self.timestamp,
                    elem_type: ElemType::ANNOUNCE,
                    peer_ip: self.peer_ip,
                    peer_asn: self.peer_asn,
                    prefix,
                    next_hop: self.next_hop,
                    as_path: self.path.clone(),
                    origin: self.origin,
                    origin_asns: self.origin_asns.clone(),
                    local_pref: self.local_pref,
                    med: self.med,
                    communities: self.communities.clone(),
                    atomic: self.atomic,
                    aggr_asn: self.aggr_asn,
                    aggr_ip: self.aggr_ip,
                    only_to_customer: self.only_to_customer,
                    unknown: self.unknown.clone(),
                    deprecated: self.deprecated.clone(),
                });
            }
            self.in_withdrawn_phase = true;
        }

        self.withdrawn.next().map(|prefix| BgpElem {
            timestamp: self.timestamp,
            elem_type: ElemType::WITHDRAW,
            peer_ip: self.peer_ip,
            peer_asn: self.peer_asn,
            prefix,
            next_hop: None,
            as_path: None,
            origin: None,
            origin_asns: None,
            local_pref: None,
            med: None,
            communities: None,
            atomic: false,
            aggr_asn: None,
            aggr_ip: None,
            only_to_customer: self.only_to_customer,
            unknown: None,
            deprecated: None,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (ann_lo, ann_hi) = if self.in_withdrawn_phase {
            (0, Some(0))
        } else {
            self.announced.size_hint()
        };
        let (wd_lo, wd_hi) = self.withdrawn.size_hint();
        (
            ann_lo + wd_lo,
            ann_hi.and_then(|a| wd_hi.map(|w| a + w)),
        )
    }
}

impl Elementor {
    pub fn new() -> Elementor {
        Self::default()
    }

    /// Sets the peer index table for the elementor.
    ///
    /// This method takes an MRT record and extracts the peer index table from it if the record contains one.
    /// The peer index table is required for processing TableDumpV2 records, as it contains the mapping between
    /// peer indices and their corresponding IP addresses and ASNs.
    ///
    /// # Arguments
    ///
    /// * `record` - An MRT record that should contain a peer index table
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the peer table was successfully extracted and set
    /// * `Err(ParserError)` - If the record does not contain a peer index table
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bgpkit_parser::{BgpkitParser, Elementor};
    ///
    /// let mut parser = BgpkitParser::new("rib.dump.bz2").unwrap();
    /// let mut elementor = Elementor::new();
    ///
    /// // Get the first record which should be the peer index table
    /// if let Ok(record) = parser.next_record() {
    ///     elementor.set_peer_table(record).unwrap();
    /// }
    /// ```
    pub fn set_peer_table(&mut self, record: MrtRecord) -> Result<(), ParserError> {
        if let MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(p)) =
            record.message
        {
            self.peer_table = Some(p);
            Ok(())
        } else {
            Err(ParseError("peer_table is not a PeerIndexTable".to_string()))
        }
    }

    /// Creates an [`Elementor`] with the given [`PeerIndexTable`] already set.
    pub fn with_peer_table(peer_table: PeerIndexTable) -> Elementor {
        Elementor {
            peer_table: Some(peer_table),
        }
    }

    /// Convert a [`MrtRecord`] into an iterator of [`BgpElem`]s without
    /// requiring `&mut self`.
    ///
    /// Unlike [`record_to_elems`](Elementor::record_to_elems), this method:
    /// - Takes `&self` instead of `&mut self`, since the peer table must
    ///   already be set via [`set_peer_table`](Elementor::set_peer_table) or
    ///   [`with_peer_table`](Elementor::with_peer_table).
    /// - Returns an error if the record contains a [`PeerIndexTable`] (which
    ///   would require mutation).
    /// - Returns a lazy [`RecordElemIter`] instead of collecting into a `Vec`,
    ///   avoiding allocation for the common RIB table dump case.
    ///
    /// # Errors
    ///
    /// - [`ElemError::UnexpectedPeerIndexTable`] if the record is a PeerIndexTable message.
    /// - [`ElemError::MissingPeerTable`] if the record requires a peer table but none is set.
    pub fn record_to_elems_iter(
        &self,
        record: MrtRecord,
    ) -> Result<RecordElemIter<'_>, ElemError> {
        let timestamp = {
            let t = record.common_header.timestamp;
            if let Some(micro) = &record.common_header.microsecond_timestamp {
                let m = (*micro as f64) / 1000000.0;
                t as f64 + m
            } else {
                f64::from(t)
            }
        };

        match record.message {
            MrtMessage::TableDumpMessage(msg) => {
                let (
                    as_path,
                    _as4_path,
                    origin,
                    next_hop,
                    local_pref,
                    med,
                    communities,
                    atomic,
                    aggregator,
                    _announced,
                    _withdrawn,
                    only_to_customer,
                    unknown,
                    deprecated,
                ) = get_relevant_attributes(msg.attributes);

                let origin_asns = as_path
                    .as_ref()
                    .map(|as_path| as_path.iter_origins().collect());

                Ok(RecordElemIter::TableDump(Some(BgpElem {
                    timestamp: msg.originated_time as f64,
                    elem_type: ElemType::ANNOUNCE,
                    peer_ip: msg.peer_ip,
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
                    aggr_asn: aggregator.map(|v| v.0),
                    aggr_ip: aggregator.map(|v| v.1),
                    only_to_customer,
                    unknown,
                    deprecated,
                })))
            }

            MrtMessage::TableDumpV2Message(msg) => match msg {
                TableDumpV2Message::PeerIndexTable(p) => {
                    Err(ElemError::UnexpectedPeerIndexTable(p))
                }
                TableDumpV2Message::RibAfi(t) => {
                    let peer_table = self
                        .peer_table
                        .as_ref()
                        .ok_or(ElemError::MissingPeerTable)?;
                    Ok(RecordElemIter::RibAfi {
                        peer_table,
                        prefix: t.prefix,
                        entries: t.rib_entries.into_iter(),
                    })
                }
                TableDumpV2Message::RibGeneric(_) => Err(ElemError::UnsupportedRibGeneric),
                TableDumpV2Message::GeoPeerTable(_) => Ok(RecordElemIter::Empty),
            },

            MrtMessage::Bgp4Mp(msg) => match msg {
                Bgp4MpEnum::StateChange(_) => Ok(RecordElemIter::Empty),
                Bgp4MpEnum::Message(v) => {
                    match Elementor::bgp_to_elems_iter(
                        v.bgp_message,
                        timestamp,
                        &v.peer_ip,
                        &v.peer_asn,
                    ) {
                        Some(iter) => Ok(RecordElemIter::Bgp4Mp(iter)),
                        None => Ok(RecordElemIter::Empty),
                    }
                }
            },
        }
    }

    /// Convert a [BgpMessage] to a vector of [BgpElem]s.
    ///
    /// A [BgpMessage] may include `Update`, `Open`, `Notification` or `KeepAlive` messages,
    /// and only `Update` message contains [BgpElem]s.
    pub fn bgp_to_elems(
        msg: BgpMessage,
        timestamp: f64,
        peer_ip: &IpAddr,
        peer_asn: &Asn,
    ) -> Vec<BgpElem> {
        Elementor::bgp_to_elems_iter(msg, timestamp, peer_ip, peer_asn)
            .map(|iter| iter.collect())
            .unwrap_or_default()
    }

    /// Convert a [BgpMessage] into an iterator of [BgpElem]s.
    ///
    /// Returns `None` for non-Update messages (Open, Notification, KeepAlive).
    pub fn bgp_to_elems_iter(
        msg: BgpMessage,
        timestamp: f64,
        peer_ip: &IpAddr,
        peer_asn: &Asn,
    ) -> Option<BgpUpdateElemIter> {
        match msg {
            BgpMessage::Update(msg) => Some(Elementor::bgp_update_to_elems_iter(
                msg, timestamp, peer_ip, peer_asn,
            )),
            BgpMessage::Open(_) | BgpMessage::Notification(_) | BgpMessage::KeepAlive => None,
        }
    }

    /// Convert a [BgpUpdateMessage] to a vector of [BgpElem]s.
    pub fn bgp_update_to_elems(
        msg: BgpUpdateMessage,
        timestamp: f64,
        peer_ip: &IpAddr,
        peer_asn: &Asn,
    ) -> Vec<BgpElem> {
        Elementor::bgp_update_to_elems_iter(msg, timestamp, peer_ip, peer_asn).collect()
    }

    /// Convert a [BgpUpdateMessage] into a [`BgpUpdateElemIter`] that lazily
    /// yields [BgpElem]s without allocating a `Vec`.
    pub fn bgp_update_to_elems_iter(
        msg: BgpUpdateMessage,
        timestamp: f64,
        peer_ip: &IpAddr,
        peer_asn: &Asn,
    ) -> BgpUpdateElemIter {
        let (
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
            only_to_customer,
            unknown,
            deprecated,
        ) = get_relevant_attributes(msg.attributes);

        let path = match (as_path, as4_path) {
            (None, None) => None,
            (Some(v), None) => Some(v),
            (None, Some(v)) => Some(v),
            (Some(v1), Some(v2)) => Some(AsPath::merge_aspath_as4path(&v1, &v2)),
        };

        let origin_asns = path
            .as_ref()
            .map(|as_path| as_path.iter_origins().collect());

        let nlri_announced = announced.map(|n| n.prefixes).unwrap_or_default();
        let nlri_withdrawn = withdrawn.map(|n| n.prefixes).unwrap_or_default();

        BgpUpdateElemIter {
            timestamp,
            peer_ip: *peer_ip,
            peer_asn: *peer_asn,
            only_to_customer,
            path,
            origin_asns,
            origin,
            next_hop,
            local_pref,
            med,
            communities,
            atomic,
            aggr_asn: aggregator.as_ref().map(|v| v.0),
            aggr_ip: aggregator.as_ref().map(|v| v.1),
            unknown,
            deprecated,
            announced: msg
                .announced_prefixes
                .into_iter()
                .chain(nlri_announced),
            withdrawn: msg
                .withdrawn_prefixes
                .into_iter()
                .chain(nlri_withdrawn),
            in_withdrawn_phase: false,
        }
    }

    /// Convert a [MrtRecord] to a vector of [BgpElem]s.
    ///
    /// If the record is a [`PeerIndexTable`], it is consumed to set the internal
    /// peer table. Errors are logged.
    ///
    /// For a non-mutating, lazy alternative, see
    /// [`record_to_elems_iter`](Elementor::record_to_elems_iter).
    pub fn record_to_elems(&mut self, record: MrtRecord) -> Vec<BgpElem> {
        match record.message {
            MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(_)) => {
                self.set_peer_table(record);
                vec![]
            },
            _ => {
                match self.record_to_elems_iter(record) {
                    Ok(iter) => iter.collect(),
                    Err(e) => {
                        error!("{}", e);
                        vec![]
                    }

                }
            }
        }
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

impl From<&BgpElem> for Attributes {
    fn from(value: &BgpElem) -> Self {
        let mut values = Vec::<AttributeValue>::new();
        let mut attributes = Attributes::default();
        let prefix = value.prefix;

        if value.elem_type == ElemType::WITHDRAW {
            values.push(AttributeValue::MpUnreachNlri(Nlri::new_unreachable(prefix)));
            attributes.extend(values);
            return attributes;
        }

        values.push(AttributeValue::MpReachNlri(Nlri::new_reachable(
            prefix,
            value.next_hop,
        )));

        if let Some(v) = value.next_hop {
            values.push(AttributeValue::NextHop(v));
        }

        if let Some(v) = value.as_path.as_ref() {
            let is_as4 = match v.get_origin_opt() {
                None => true,
                Some(asn) => asn.is_four_byte(),
            };
            values.push(AttributeValue::AsPath {
                path: v.clone(),
                is_as4,
            });
        }

        if let Some(v) = value.origin {
            values.push(AttributeValue::Origin(v));
        }

        if let Some(v) = value.local_pref {
            values.push(AttributeValue::LocalPreference(v));
        }

        if let Some(v) = value.med {
            values.push(AttributeValue::MultiExitDiscriminator(v));
        }

        if let Some(v) = value.communities.as_ref() {
            let mut communites = vec![];
            let mut extended_communities = vec![];
            let mut ipv6_extended_communities = vec![];
            let mut large_communities = vec![];
            for c in v {
                match c {
                    MetaCommunity::Plain(v) => communites.push(*v),
                    MetaCommunity::Extended(v) => extended_communities.push(*v),
                    MetaCommunity::Large(v) => large_communities.push(*v),
                    MetaCommunity::Ipv6Extended(v) => ipv6_extended_communities.push(*v),
                }
            }
            if !communites.is_empty() {
                values.push(AttributeValue::Communities(communites));
            }
            if !extended_communities.is_empty() {
                values.push(AttributeValue::ExtendedCommunities(extended_communities));
            }
            if !large_communities.is_empty() {
                values.push(AttributeValue::LargeCommunities(large_communities));
            }
            if !ipv6_extended_communities.is_empty() {
                values.push(AttributeValue::Ipv6AddressSpecificExtendedCommunities(
                    ipv6_extended_communities,
                ));
            }
        }

        if let Some(v) = value.aggr_asn {
            let aggregator_id = match value.aggr_ip {
                Some(v) => v,
                None => Ipv4Addr::UNSPECIFIED,
            };
            values.push(AttributeValue::Aggregator {
                asn: v,
                id: aggregator_id,
                is_as4: v.is_four_byte(),
            });
        }

        if let Some(v) = value.only_to_customer {
            values.push(AttributeValue::OnlyToCustomer(v));
        }

        if let Some(v) = value.unknown.as_ref() {
            for t in v {
                values.push(AttributeValue::Unknown(t.clone()));
            }
        }

        if let Some(v) = value.deprecated.as_ref() {
            for t in v {
                values.push(AttributeValue::Deprecated(t.clone()));
            }
        }

        attributes.extend(values);
        attributes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BgpkitParser;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_option_to_string() {
        let o1 = Some(1);
        let o2: Option<u32> = None;
        assert_eq!(option_to_string(&o1), "1");
        assert_eq!(option_to_string(&o2), "");
    }

    #[test]
    fn test_record_to_elems() {
        let url_table_dump_v1 = "https://data.ris.ripe.net/rrc00/2003.01/bview.20030101.0000.gz";
        let url_table_dump_v2 = "https://data.ris.ripe.net/rrc00/2023.01/bview.20230101.0000.gz";
        let url_bgp4mp = "https://data.ris.ripe.net/rrc00/2021.10/updates.20211001.0000.gz";

        let mut elementor = Elementor::new();
        let parser = BgpkitParser::new(url_table_dump_v1).unwrap();
        let mut record_iter = parser.into_record_iter();
        let record = record_iter.next().unwrap();
        let elems = elementor.record_to_elems(record);
        assert_eq!(elems.len(), 1);

        let parser = BgpkitParser::new(url_table_dump_v2).unwrap();
        let mut record_iter = parser.into_record_iter();
        let peer_index_table = record_iter.next().unwrap();
        let _elems = elementor.record_to_elems(peer_index_table);
        let record = record_iter.next().unwrap();
        let elems = elementor.record_to_elems(record);
        assert!(!elems.is_empty());

        let parser = BgpkitParser::new(url_bgp4mp).unwrap();
        let mut record_iter = parser.into_record_iter();
        let record = record_iter.next().unwrap();
        let elems = elementor.record_to_elems(record);
        assert!(!elems.is_empty());
    }

    #[test]
    fn test_attributes_from_bgp_elem() {
        let mut elem = BgpElem {
            timestamp: 0.0,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from_str("10.0.0.1").unwrap(),
            peer_asn: Asn::new_32bit(65000),
            prefix: NetworkPrefix::from_str("10.0.1.0/24").unwrap(),
            next_hop: Some(IpAddr::from_str("10.0.0.2").unwrap()),
            as_path: Some(AsPath::from_sequence([65000, 65001, 65002])),
            origin: Some(Origin::EGP),
            origin_asns: Some(vec![Asn::new_32bit(65000)]),
            local_pref: Some(100),
            med: Some(200),
            communities: Some(vec![
                MetaCommunity::Plain(Community::NoAdvertise),
                MetaCommunity::Extended(ExtendedCommunity::Raw([0, 0, 0, 0, 0, 0, 0, 0])),
                MetaCommunity::Large(LargeCommunity {
                    global_admin: 0,
                    local_data: [0, 0],
                }),
                MetaCommunity::Ipv6Extended(Ipv6AddrExtCommunity {
                    community_type: ExtendedCommunityType::TransitiveTwoOctetAs,
                    subtype: 0,
                    global_admin: Ipv6Addr::from_str("2001:db8::").unwrap(),
                    local_admin: [0, 0],
                }),
            ]),
            atomic: false,
            aggr_asn: Some(Asn::new_32bit(65000)),
            aggr_ip: Some(Ipv4Addr::from_str("10.2.0.0").unwrap()),
            only_to_customer: Some(Asn::new_32bit(65000)),
            unknown: Some(vec![AttrRaw {
                attr_type: AttrType::RESERVED,
                bytes: vec![],
            }]),
            deprecated: Some(vec![AttrRaw {
                attr_type: AttrType::RESERVED,
                bytes: vec![],
            }]),
        };

        let _attributes = Attributes::from(&elem);
        elem.elem_type = ElemType::WITHDRAW;
        let _attributes = Attributes::from(&elem);
    }

    #[test]
    fn test_get_relevant_attributes() {
        let attributes = vec![
            AttributeValue::Origin(Origin::IGP),
            AttributeValue::AsPath {
                path: AsPath::from_sequence([65000, 65001, 65002]),
                is_as4: true,
            },
            AttributeValue::NextHop(IpAddr::from_str("10.0.0.1").unwrap()),
            AttributeValue::MultiExitDiscriminator(100),
            AttributeValue::LocalPreference(200),
            AttributeValue::AtomicAggregate,
            AttributeValue::Aggregator {
                asn: Asn::new_32bit(65000),
                id: Ipv4Addr::from_str("10.0.0.1").unwrap(),
                is_as4: false,
            },
            AttributeValue::Communities(vec![Community::NoExport]),
            AttributeValue::ExtendedCommunities(vec![ExtendedCommunity::Raw([
                0, 0, 0, 0, 0, 0, 0, 0,
            ])]),
            AttributeValue::LargeCommunities(vec![LargeCommunity {
                global_admin: 0,
                local_data: [0, 0],
            }]),
            AttributeValue::Ipv6AddressSpecificExtendedCommunities(vec![Ipv6AddrExtCommunity {
                community_type: ExtendedCommunityType::TransitiveTwoOctetAs,
                subtype: 0,
                global_admin: Ipv6Addr::from_str("2001:db8::").unwrap(),
                local_admin: [0, 0],
            }]),
            AttributeValue::MpReachNlri(Nlri::new_reachable(
                NetworkPrefix::from_str("10.0.0.0/24").unwrap(),
                Some(IpAddr::from_str("10.0.0.1").unwrap()),
            )),
            AttributeValue::MpUnreachNlri(Nlri::new_unreachable(
                NetworkPrefix::from_str("10.0.0.0/24").unwrap(),
            )),
            AttributeValue::OnlyToCustomer(Asn::new_32bit(65000)),
            AttributeValue::Unknown(AttrRaw {
                attr_type: AttrType::RESERVED,
                bytes: vec![],
            }),
            AttributeValue::Deprecated(AttrRaw {
                attr_type: AttrType::RESERVED,
                bytes: vec![],
            }),
        ]
        .into_iter()
        .map(Attribute::from)
        .collect::<Vec<Attribute>>();

        let attributes = Attributes::from(attributes);

        let (
            _as_path,
            _as4_path, // Table dump v1 does not have 4-byte AS number
            _origin,
            _next_hop,
            _local_pref,
            _med,
            _communities,
            _atomic,
            _aggregator,
            _announced,
            _withdrawn,
            _only_to_customer,
            _unknown,
            _deprecated,
        ) = get_relevant_attributes(attributes);
    }

    #[test]
    fn test_next_hop_from_nlri() {
        let attributes = vec![AttributeValue::NextHop(
            IpAddr::from_str("10.0.0.1").unwrap(),
        )]
        .into_iter()
        .map(Attribute::from)
        .collect::<Vec<Attribute>>();

        let attributes = Attributes::from(attributes);

        let (
            _as_path,
            _as4_path, // Table dump v1 does not have 4-byte AS number
            _origin,
            next_hop,
            _local_pref,
            _med,
            _communities,
            _atomic,
            _aggregator,
            _announced,
            _withdrawn,
            _only_to_customer,
            _unknown,
            _deprecated,
        ) = get_relevant_attributes(attributes);

        assert_eq!(next_hop, Some(IpAddr::from_str("10.0.0.1").unwrap()));

        let attributes = vec![AttributeValue::MpReachNlri(Nlri::new_reachable(
            NetworkPrefix::from_str("10.0.0.0/24").unwrap(),
            Some(IpAddr::from_str("10.0.0.2").unwrap()),
        ))]
        .into_iter()
        .map(Attribute::from)
        .collect::<Vec<Attribute>>();

        let attributes = Attributes::from(attributes);

        let (
            _as_path,
            _as4_path, // Table dump v1 does not have 4-byte AS number
            _origin,
            next_hop,
            _local_pref,
            _med,
            _communities,
            _atomic,
            _aggregator,
            _announced,
            _withdrawn,
            _only_to_customer,
            _unknown,
            _deprecated,
        ) = get_relevant_attributes(attributes);

        assert_eq!(next_hop, Some(IpAddr::from_str("10.0.0.2").unwrap()));
    }
}
