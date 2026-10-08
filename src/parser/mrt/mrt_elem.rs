//! This module handles converting MRT records into individual per-prefix BGP elements.
//!
//! Each MRT record may contain reachability information for multiple prefixes. This module breaks
//! down MRT records into corresponding BGP elements, and thus allowing users to more conveniently
//! process BGP information on a per-prefix basis.
use crate::models::*;
use crate::ParserError;
use crate::ParserError::ParseError;
use log::error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Default, Debug, Clone)]
pub struct Elementor {
    pub peer_table: Option<PeerIndexTable>,
    error_handling: ErrorHandlingMode,
}

/// Error returned by [`Elementor::record_to_elems_iter`].
#[derive(Debug)]
pub enum ElemError {
    /// The record contains a [`PeerIndexTable`]. The contained table can be
    /// passed to [`Elementor::with_peer_table`] to create an initialized elementor.
    UnexpectedPeerIndexTable(Box<PeerIndexTable>),
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

/// The attribute values an elem is built from, taken out of an [`Attributes`] set.
struct RelevantAttributes {
    as_path: Option<AsPath>,
    as4_path: Option<AsPath>,
    origin: Option<Origin>,
    next_hop: Option<IpAddr>,
    local_pref: Option<u32>,
    med: Option<u32>,
    communities: Option<Vec<MetaCommunity>>,
    atomic: bool,
    aggregator: Option<(Asn, BgpIdentifier)>,
    announced_prefixes: Vec<NetworkPrefix>,
    withdrawn_prefixes: Vec<NetworkPrefix>,
    only_to_customer: Option<Asn>,
    unknown: Option<Vec<AttrRaw>>,
    deprecated: Option<Vec<AttrRaw>>,
}

impl RelevantAttributes {
    /// The effective AS path: AS_PATH merged with AS4_PATH when both are present (RFC 6793).
    fn path(&mut self) -> Option<AsPath> {
        match (self.as_path.take(), self.as4_path.take()) {
            (None, None) => None,
            (Some(v), None) => Some(v),
            (None, Some(v)) => Some(v),
            (Some(v1), Some(v2)) => Some(AsPath::merge_aspath_as4path(&v1, &v2)),
        }
    }
}

/// Take the values an elem needs out of `attributes`.
///
/// The values are moved out of the attribute list in place rather than by consuming it, which
/// avoids copying every (large) [`AttributeValue`] once more on the way through.
fn get_relevant_attributes(mut attributes: Attributes) -> RelevantAttributes {
    let mut as_path = None;
    let mut as4_path = None;
    let mut origin = None;
    let mut next_hop = None;
    let mut local_pref = Some(0);
    let mut med = Some(0);
    let mut atomic = false;
    let mut aggregator = None;
    let mut announced_prefixes = Vec::new();
    let mut announced_next_hop = None;
    let mut withdrawn_prefixes = Vec::new();
    let mut otc = None;
    let mut unknown = vec![];
    let mut deprecated = vec![];

    let mut communities_vec: Vec<MetaCommunity> = vec![];

    let take_raw = |t: &mut AttrRaw| AttrRaw {
        code: t.code,
        bytes: std::mem::take(&mut t.bytes),
    };

    for attr in attributes.inner.iter_mut() {
        match &mut attr.value {
            AttributeValue::Origin(v) => origin = Some(*v),
            AttributeValue::AsPath(path) => as_path = Some(std::mem::take(path)),
            AttributeValue::As4Path(path) => as4_path = Some(std::mem::take(path)),
            AttributeValue::NextHop(v) => next_hop = Some(*v),
            AttributeValue::MultiExitDiscriminator(v) => med = Some(*v),
            AttributeValue::LocalPreference(v) => local_pref = Some(*v),
            AttributeValue::AtomicAggregate => atomic = true,
            AttributeValue::Communities(v) => {
                communities_vec.extend(v.drain(..).map(MetaCommunity::Plain))
            }
            AttributeValue::ExtendedCommunities(v) => {
                communities_vec.extend(v.drain(..).map(MetaCommunity::Extended))
            }
            AttributeValue::Ipv6AddressSpecificExtendedCommunities(v) => {
                communities_vec.extend(v.drain(..).map(MetaCommunity::Ipv6Extended))
            }
            AttributeValue::LargeCommunities(v) => {
                communities_vec.extend(v.drain(..).map(MetaCommunity::Large))
            }
            AttributeValue::Aggregator { asn, id } | AttributeValue::As4Aggregator { asn, id } => {
                aggregator = Some((*asn, *id))
            }
            AttributeValue::MpReachNlri(nlri) => {
                announced_prefixes = std::mem::take(&mut nlri.prefixes);
                announced_next_hop = nlri.next_hop.as_ref().map(NextHopAddress::global_addr);
            }
            AttributeValue::MpUnreachNlri(nlri) => {
                withdrawn_prefixes = std::mem::take(&mut nlri.prefixes)
            }
            AttributeValue::OnlyToCustomer(o) => otc = Some(*o),

            AttributeValue::Unknown(t) | AttributeValue::Raw(t) => {
                unknown.push(take_raw(t));
            }
            AttributeValue::Deprecated(t) => {
                deprecated.push(take_raw(t));
            }

            AttributeValue::OriginatorId(_)
            | AttributeValue::Clusters(_)
            | AttributeValue::Development(_)
            | AttributeValue::LinkState(_)
            | AttributeValue::TunnelEncapsulation(_)
            | AttributeValue::TrafficEngineering(_)
            | AttributeValue::Aigp(_)
            | AttributeValue::DomainPath(_)
            | AttributeValue::BfdDiscriminator(_)
            | AttributeValue::BgpPrefixSid(_)
            | AttributeValue::Bier(_)
            | AttributeValue::Sfp(_)
            | AttributeValue::AttrSet(_) => {}
        };
    }

    let communities = match !communities_vec.is_empty() {
        true => Some(communities_vec),
        false => None,
    };

    RelevantAttributes {
        as_path,
        as4_path,
        origin,
        // If the next_hop is not set, we try to get it from the announced NLRI.
        next_hop: next_hop.or(announced_next_hop),
        local_pref,
        med,
        communities,
        atomic,
        aggregator,
        announced_prefixes,
        withdrawn_prefixes,
        only_to_customer: otc,
        unknown: if unknown.is_empty() {
            None
        } else {
            Some(unknown)
        },
        deprecated: if deprecated.is_empty() {
            None
        } else {
            Some(deprecated)
        },
    }
}

fn rib_entry_to_elem(prefix: NetworkPrefix, peer: &Peer, entry: RibEntry) -> BgpElem {
    let mut attrs = get_relevant_attributes(entry.attributes);
    let path = attrs.path();

    let origin_asns = path
        .as_ref()
        .map(|as_path| as_path.iter_origins().collect());

    BgpElem {
        timestamp: entry.originated_time as f64,
        elem_type: ElemType::ANNOUNCE,
        peer_ip: peer.peer_ip,
        peer_asn: peer.peer_asn,
        peer_bgp_id: Some(peer.peer_bgp_id),
        prefix,
        next_hop: attrs.next_hop,
        as_path: path,
        origin: attrs.origin,
        origin_asns,
        local_pref: attrs.local_pref,
        med: attrs.med,
        communities: attrs.communities,
        atomic: attrs.atomic,
        aggr_asn: attrs.aggregator.map(|v| v.0),
        aggr_ip: attrs.aggregator.map(|v| v.1),
        only_to_customer: attrs.only_to_customer,
        unknown: attrs.unknown,
        deprecated: attrs.deprecated,
        error_handling: None,
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
    TableDumpBatch(std::vec::IntoIter<TableDumpMessage>),
    #[doc(hidden)]
    RibAfi {
        peer_table: &'a PeerIndexTable,
        prefix: NetworkPrefix,
        entries: std::vec::IntoIter<RibEntry>,
    },
    #[doc(hidden)]
    Bgp4Mp(BgpUpdateElemIter),
}

/// Convert the next RIB entry into an elem.
///
/// `Err` means the entry names a peer the table does not have; iteration over the record stops
/// there.
fn next_rib_elem(
    peer_table: &PeerIndexTable,
    prefix: NetworkPrefix,
    entries: &mut std::vec::IntoIter<RibEntry>,
) -> Result<Option<BgpElem>, ()> {
    let Some(entry) = entries.next() else {
        return Ok(None);
    };
    let pid = entry.peer_index;
    match peer_table.get_peer_by_id(&pid) {
        Some(peer) => Ok(Some(rib_entry_to_elem(prefix, peer, entry))),
        None => {
            error!("peer ID {} not found in peer_index table", pid);
            Err(())
        }
    }
}

/// The elems a record has yet to yield, without a borrow of the peer table.
///
/// This is [`RecordElemIter`] with the peer table passed to each
/// [`next_elem`](PendingElems::next_elem) call instead of held, so an iterator that owns an
/// [`Elementor`] can keep one next to it and stream elems instead of collecting them.
pub(crate) enum PendingElems {
    Empty,
    TableDump(Option<BgpElem>),
    TableDumpBatch(std::vec::IntoIter<TableDumpMessage>),
    RibAfi {
        prefix: NetworkPrefix,
        entries: std::vec::IntoIter<RibEntry>,
    },
    Bgp4Mp(BgpUpdateElemIter),
}

impl PendingElems {
    /// The next elem, given the peer table of the [`Elementor`] that produced these elems.
    pub(crate) fn next_elem(&mut self, peer_table: Option<&PeerIndexTable>) -> Option<BgpElem> {
        match self {
            PendingElems::Empty => None,
            PendingElems::TableDump(elem) => elem.take(),
            PendingElems::TableDumpBatch(entries) => entries.next().map(table_dump_to_elem),
            PendingElems::Bgp4Mp(iter) => iter.next(),
            PendingElems::RibAfi { prefix, entries } => {
                // a RIB record only becomes pending while a peer table is set
                let next = peer_table
                    .ok_or(())
                    .and_then(|t| next_rib_elem(t, *prefix, entries));
                next.unwrap_or_else(|()| {
                    *self = PendingElems::Empty;
                    None
                })
            }
        }
    }
}

impl Iterator for RecordElemIter<'_> {
    type Item = BgpElem;

    fn next(&mut self) -> Option<BgpElem> {
        match self {
            RecordElemIter::Empty => None,
            RecordElemIter::TableDump(elem) => elem.take(),
            RecordElemIter::TableDumpBatch(entries) => entries.next().map(table_dump_to_elem),
            RecordElemIter::Bgp4Mp(iter) => iter.next(),
            RecordElemIter::RibAfi {
                peer_table,
                prefix,
                entries,
            } => next_rib_elem(peer_table, *prefix, entries).unwrap_or_else(|()| {
                *self = RecordElemIter::Empty;
                None
            }),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            RecordElemIter::Empty => (0, Some(0)),
            RecordElemIter::TableDump(elem) => {
                let n = elem.is_some() as usize;
                (n, Some(n))
            }
            RecordElemIter::TableDumpBatch(entries) => {
                let len = entries.len();
                (len, Some(len))
            }
            RecordElemIter::Bgp4Mp(iter) => iter.size_hint(),
            RecordElemIter::RibAfi { entries, .. } => {
                let len = entries.len();
                (len, Some(len))
            }
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
    peer_bgp_id: Option<BgpIdentifier>,
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
    announced:
        std::iter::Chain<std::vec::IntoIter<NetworkPrefix>, std::vec::IntoIter<NetworkPrefix>>,
    withdrawn:
        std::iter::Chain<std::vec::IntoIter<NetworkPrefix>, std::vec::IntoIter<NetworkPrefix>>,
    in_withdrawn_phase: bool,
    /// Element type of the announced prefixes: `ANNOUNCE`, or `WITHDRAW` / `RESET` when RFC 7606
    /// error handling withdrew them, in which case the shared attributes above are all empty.
    announced_as: ElemType,
    /// RFC 7606 approach stamped on every element, when one was applied.
    error_handling: Option<ErrorHandlingApproach>,
}

impl Iterator for BgpUpdateElemIter {
    type Item = BgpElem;

    fn next(&mut self) -> Option<BgpElem> {
        if !self.in_withdrawn_phase {
            if let Some(prefix) = self.announced.next() {
                // The shared attributes are only used for announcements, so the last one can
                // take them instead of cloning, which saves every clone for a single-prefix UPDATE.
                let last = self.announced.size_hint().1 == Some(0);
                let (as_path, origin_asns, communities, unknown, deprecated) = if last {
                    (
                        self.path.take(),
                        self.origin_asns.take(),
                        self.communities.take(),
                        self.unknown.take(),
                        self.deprecated.take(),
                    )
                } else {
                    (
                        self.path.clone(),
                        self.origin_asns.clone(),
                        self.communities.clone(),
                        self.unknown.clone(),
                        self.deprecated.clone(),
                    )
                };
                return Some(BgpElem {
                    timestamp: self.timestamp,
                    elem_type: self.announced_as,
                    peer_ip: self.peer_ip,
                    peer_asn: self.peer_asn,
                    peer_bgp_id: self.peer_bgp_id,
                    prefix,
                    next_hop: self.next_hop,
                    as_path,
                    origin: self.origin,
                    origin_asns,
                    local_pref: self.local_pref,
                    med: self.med,
                    communities,
                    atomic: self.atomic,
                    aggr_asn: self.aggr_asn,
                    aggr_ip: self.aggr_ip,
                    only_to_customer: self.only_to_customer,
                    unknown,
                    deprecated,
                    error_handling: self.error_handling,
                });
            }
            self.in_withdrawn_phase = true;
        }

        self.withdrawn.next().map(|prefix| BgpElem {
            timestamp: self.timestamp,
            elem_type: ElemType::WITHDRAW,
            peer_ip: self.peer_ip,
            peer_asn: self.peer_asn,
            peer_bgp_id: self.peer_bgp_id,
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
            only_to_customer: None,
            unknown: None,
            deprecated: None,
            error_handling: self.error_handling,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (ann_lo, ann_hi) = if self.in_withdrawn_phase {
            (0, Some(0))
        } else {
            self.announced.size_hint()
        };
        let (wd_lo, wd_hi) = self.withdrawn.size_hint();
        (ann_lo + wd_lo, ann_hi.and_then(|a| wd_hi.map(|w| a + w)))
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
            ..Default::default()
        }
    }

    /// Sets how UPDATE messages with validation findings become elements.
    ///
    /// With [`ErrorHandlingMode::Rfc7606`], each UPDATE is converted according to its
    /// [`BgpUpdateMessage::error_handling_approach`], assuming an eBGP session:
    ///
    /// - attribute discard: the announcements are kept and the malformed attributes, plus
    ///   repeats of an attribute after its first occurrence, are left out;
    /// - treat-as-withdraw: every announced prefix becomes a [`ElemType::WITHDRAW`] element;
    /// - AFI/SAFI disable or session reset: every announced prefix becomes a
    ///   [`ElemType::RESET`] element.
    ///
    /// Elements of an UPDATE that had an approach applied carry it in
    /// [`BgpElem::error_handling`]. RIB entries are converted as before.
    ///
    /// ```
    /// use bgpkit_parser::Elementor;
    /// use bgpkit_parser::models::ErrorHandlingMode;
    ///
    /// let elementor = Elementor::new().with_error_handling(ErrorHandlingMode::Rfc7606);
    /// assert_eq!(elementor.error_handling(), ErrorHandlingMode::Rfc7606);
    /// ```
    pub fn with_error_handling(mut self, mode: ErrorHandlingMode) -> Elementor {
        self.error_handling = mode;
        self
    }

    /// Shorthand for [`with_error_handling(ErrorHandlingMode::Rfc7606)`](Self::with_error_handling).
    pub fn enable_rfc7606_error_handling(self) -> Elementor {
        self.with_error_handling(ErrorHandlingMode::Rfc7606)
    }

    /// How this elementor converts UPDATE messages with validation findings.
    pub fn error_handling(&self) -> ErrorHandlingMode {
        self.error_handling
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
    pub fn record_to_elems_iter(&self, record: MrtRecord) -> Result<RecordElemIter<'_>, ElemError> {
        Ok(match self.pending_elems(record)? {
            PendingElems::Empty => RecordElemIter::Empty,
            PendingElems::TableDump(elem) => RecordElemIter::TableDump(elem),
            PendingElems::TableDumpBatch(entries) => RecordElemIter::TableDumpBatch(entries),
            PendingElems::RibAfi { prefix, entries } => RecordElemIter::RibAfi {
                peer_table: self
                    .peer_table
                    .as_ref()
                    .ok_or(ElemError::MissingPeerTable)?,
                prefix,
                entries,
            },
            PendingElems::Bgp4Mp(iter) => RecordElemIter::Bgp4Mp(iter),
        })
    }

    /// The elems of `record`, for [`record_to_elems_iter`](Elementor::record_to_elems_iter) and
    /// [`ingest`](Elementor::ingest).
    fn pending_elems(&self, record: MrtRecord) -> Result<PendingElems, ElemError> {
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
                Ok(PendingElems::TableDump(Some(table_dump_to_elem(msg))))
            }
            MrtMessage::TableDumpMessageBatch(messages) => {
                Ok(PendingElems::TableDumpBatch(messages.into_iter()))
            }

            MrtMessage::TableDumpV2Message(msg) => match msg {
                TableDumpV2Message::PeerIndexTable(p) => {
                    Err(ElemError::UnexpectedPeerIndexTable(Box::new(p)))
                }
                TableDumpV2Message::RibAfi(t) => {
                    if self.peer_table.is_none() {
                        return Err(ElemError::MissingPeerTable);
                    }
                    Ok(PendingElems::RibAfi {
                        prefix: t.prefix,
                        entries: t.rib_entries.into_iter(),
                    })
                }
                TableDumpV2Message::RibGeneric(_) => Err(ElemError::UnsupportedRibGeneric),
                TableDumpV2Message::GeoPeerTable(_) => Ok(PendingElems::Empty),
            },

            MrtMessage::Bgp4Mp(msg) => match msg {
                Bgp4MpEnum::StateChange(_) => Ok(PendingElems::Empty),
                Bgp4MpEnum::Message(v) => {
                    match Elementor::bgp_to_elems_iter_with(
                        v.bgp_message,
                        timestamp,
                        &v.peer_ip,
                        &v.peer_asn,
                        self.error_handling,
                    ) {
                        Some(iter) => Ok(PendingElems::Bgp4Mp(iter)),
                        None => Ok(PendingElems::Empty),
                    }
                }
            },
            MrtMessage::LegacyBgp(msg) => match msg {
                LegacyBgp::StateChange(_) => Ok(PendingElems::Empty),
                LegacyBgp::Message(message) => match Elementor::bgp_to_elems_iter_with(
                    message.bgp_message,
                    timestamp,
                    &message.peer_ip,
                    &message.peer_asn,
                    self.error_handling,
                ) {
                    Some(iter) => Ok(PendingElems::Bgp4Mp(iter)),
                    None => Ok(PendingElems::Empty),
                },
            },
        }
    }

    /// Take in a record the way [`record_to_elems`](Elementor::record_to_elems) does, returning
    /// its elems for lazy draining with [`PendingElems::next_elem`] instead of a `Vec`.
    ///
    /// A [`PeerIndexTable`] record sets the peer table; errors are logged.
    pub(crate) fn ingest(&mut self, record: MrtRecord) -> PendingElems {
        match record.message {
            MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(_)) => {
                if let Err(e) = self.set_peer_table(record) {
                    error!("{}", e);
                }
                PendingElems::Empty
            }
            _ => self.pending_elems(record).unwrap_or_else(|e| {
                error!("{}", e);
                PendingElems::Empty
            }),
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
    /// Returns `None` for non-Update messages (Open, Notification, KeepAlive, RouteRefresh).
    pub fn bgp_to_elems_iter(
        msg: BgpMessage,
        timestamp: f64,
        peer_ip: &IpAddr,
        peer_asn: &Asn,
    ) -> Option<BgpUpdateElemIter> {
        Elementor::bgp_to_elems_iter_with(
            msg,
            timestamp,
            peer_ip,
            peer_asn,
            ErrorHandlingMode::Preserve,
        )
    }

    /// Like [`bgp_to_elems_iter`](Self::bgp_to_elems_iter), converting UPDATE messages according
    /// to `mode`; see [`with_error_handling`](Self::with_error_handling).
    pub fn bgp_to_elems_iter_with(
        msg: BgpMessage,
        timestamp: f64,
        peer_ip: &IpAddr,
        peer_asn: &Asn,
        mode: ErrorHandlingMode,
    ) -> Option<BgpUpdateElemIter> {
        match msg {
            BgpMessage::Update(msg) => Some(Elementor::bgp_update_to_elems_iter_with(
                msg, timestamp, peer_ip, peer_asn, mode,
            )),
            BgpMessage::Open(_)
            | BgpMessage::Notification(_)
            | BgpMessage::KeepAlive
            | BgpMessage::RouteRefresh(_) => None,
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

    /// Like [`bgp_update_to_elems`](Self::bgp_update_to_elems), converting the UPDATE according
    /// to `mode`; see [`with_error_handling`](Self::with_error_handling).
    pub fn bgp_update_to_elems_with(
        msg: BgpUpdateMessage,
        timestamp: f64,
        peer_ip: &IpAddr,
        peer_asn: &Asn,
        mode: ErrorHandlingMode,
    ) -> Vec<BgpElem> {
        Elementor::bgp_update_to_elems_iter_with(msg, timestamp, peer_ip, peer_asn, mode).collect()
    }

    /// Convert a [BgpUpdateMessage] into a [`BgpUpdateElemIter`] that lazily
    /// yields [BgpElem]s without allocating a `Vec`.
    pub fn bgp_update_to_elems_iter(
        msg: BgpUpdateMessage,
        timestamp: f64,
        peer_ip: &IpAddr,
        peer_asn: &Asn,
    ) -> BgpUpdateElemIter {
        Elementor::bgp_update_to_elems_iter_with(
            msg,
            timestamp,
            peer_ip,
            peer_asn,
            ErrorHandlingMode::Preserve,
        )
    }

    /// Like [`bgp_update_to_elems_iter`](Self::bgp_update_to_elems_iter), converting the UPDATE
    /// according to `mode`; see [`with_error_handling`](Self::with_error_handling).
    pub fn bgp_update_to_elems_iter_with(
        mut msg: BgpUpdateMessage,
        timestamp: f64,
        peer_ip: &IpAddr,
        peer_asn: &Asn,
        mode: ErrorHandlingMode,
    ) -> BgpUpdateElemIter {
        let approach = match mode {
            ErrorHandlingMode::Rfc7606 => msg.error_handling_approach(),
            ErrorHandlingMode::Preserve => None,
        };
        match approach {
            Some(approach) if approach.withdraws_routes() => {
                return withdrawn_update_elems_iter(msg, timestamp, peer_ip, peer_asn, approach);
            }
            Some(_) => DiscardPlan::from_warnings(&msg.attributes.validation_warnings)
                .apply(&mut msg.attributes),
            None => {}
        }

        let mut attrs = get_relevant_attributes(msg.attributes);
        let path = attrs.path();

        let origin_asns = path
            .as_ref()
            .map(|as_path| as_path.iter_origins().collect());

        BgpUpdateElemIter {
            timestamp,
            peer_ip: *peer_ip,
            peer_asn: *peer_asn,
            peer_bgp_id: None,
            only_to_customer: attrs.only_to_customer,
            path,
            origin_asns,
            origin: attrs.origin,
            next_hop: attrs.next_hop,
            local_pref: attrs.local_pref,
            med: attrs.med,
            communities: attrs.communities,
            atomic: attrs.atomic,
            aggr_asn: attrs.aggregator.map(|v| v.0),
            aggr_ip: attrs.aggregator.map(|v| v.1),
            unknown: attrs.unknown,
            deprecated: attrs.deprecated,
            announced: msg
                .announced_prefixes
                .into_iter()
                .chain(attrs.announced_prefixes),
            withdrawn: msg
                .withdrawn_prefixes
                .into_iter()
                .chain(attrs.withdrawn_prefixes),
            in_withdrawn_phase: false,
            announced_as: ElemType::ANNOUNCE,
            error_handling: approach,
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
                if let Err(e) = self.set_peer_table(record) {
                    error!("{}", e);
                }
                vec![]
            }
            _ => match self.record_to_elems_iter(record) {
                Ok(iter) => iter.collect(),
                Err(e) => {
                    error!("{}", e);
                    vec![]
                }
            },
        }
    }
}

/// RFC 7606 treat-as-withdraw and stronger: no announced route is installed, so every announced
/// prefix becomes a `WITHDRAW` element, or a `RESET` element when the approach is AFI/SAFI disable
/// or session reset. The path attributes describe routes that are not installed, so no element
/// carries them. As in the route iterator, only the first MP_REACH_NLRI and MP_UNREACH_NLRI
/// count (RFC 7606 §3(g)).
fn withdrawn_update_elems_iter(
    msg: BgpUpdateMessage,
    timestamp: f64,
    peer_ip: &IpAddr,
    peer_asn: &Asn,
    approach: ErrorHandlingApproach,
) -> BgpUpdateElemIter {
    let mut nlri_announced = Vec::new();
    let mut nlri_withdrawn = Vec::new();
    let mut seen = AttrCodeSet::default();
    for attribute in msg.attributes.inner {
        if !seen.insert(attribute.value.attr_code()) {
            continue;
        }
        match attribute.value {
            AttributeValue::MpReachNlri(nlri) => nlri_announced.extend(nlri.prefixes),
            AttributeValue::MpUnreachNlri(nlri) => nlri_withdrawn.extend(nlri.prefixes),
            _ => {}
        }
    }

    BgpUpdateElemIter {
        timestamp,
        peer_ip: *peer_ip,
        peer_asn: *peer_asn,
        peer_bgp_id: None,
        only_to_customer: None,
        path: None,
        origin_asns: None,
        origin: None,
        next_hop: None,
        local_pref: None,
        med: None,
        communities: None,
        atomic: false,
        aggr_asn: None,
        aggr_ip: None,
        unknown: None,
        deprecated: None,
        announced: msg.announced_prefixes.into_iter().chain(nlri_announced),
        withdrawn: msg.withdrawn_prefixes.into_iter().chain(nlri_withdrawn),
        in_withdrawn_phase: false,
        announced_as: approach.announced_elem_type(),
        error_handling: Some(approach),
    }
}

fn table_dump_to_elem(msg: TableDumpMessage) -> BgpElem {
    let attrs = get_relevant_attributes(msg.attributes);

    let origin_asns = attrs
        .as_path
        .as_ref()
        .map(|as_path| as_path.iter_origins().collect());

    BgpElem {
        timestamp: msg.originated_time as f64,
        elem_type: ElemType::ANNOUNCE,
        peer_ip: msg.peer_ip,
        peer_asn: msg.peer_asn,
        peer_bgp_id: None,
        prefix: msg.prefix,
        next_hop: attrs.next_hop,
        as_path: attrs.as_path,
        origin: attrs.origin,
        origin_asns,
        local_pref: attrs.local_pref,
        med: attrs.med,
        communities: attrs.communities,
        atomic: attrs.atomic,
        aggr_asn: attrs.aggregator.map(|v| v.0),
        aggr_ip: attrs.aggregator.map(|v| v.1),
        only_to_customer: attrs.only_to_customer,
        unknown: attrs.unknown,
        deprecated: attrs.deprecated,
        error_handling: None,
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

        // RESET elems are routes RFC 7606 forbids installing, so they encode as withdrawals too
        if !value.elem_type.is_announce() {
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
            // The elem path is the RFC 6793 merged (effective) path, so it
            // always maps to the plain AS_PATH attribute; the segment width is
            // decided by the session's `asn_len` at encode time.
            values.push(AttributeValue::AsPath(v.clone()));
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
    use bytes::Bytes;
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
            peer_bgp_id: None,
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
                code: AttrType::RESERVED.into(),
                bytes: Bytes::new(),
            }]),
            deprecated: Some(vec![AttrRaw {
                code: AttrType::RESERVED.into(),
                bytes: Bytes::new(),
            }]),
            error_handling: None,
        };

        let _attributes = Attributes::from(&elem);
        elem.elem_type = ElemType::WITHDRAW;
        let _attributes = Attributes::from(&elem);
    }

    #[test]
    fn test_reset_elem_converts_to_withdrawal() {
        let elem = BgpElem {
            elem_type: ElemType::RESET,
            prefix: NetworkPrefix::from_str("10.0.0.0/24").unwrap(),
            ..Default::default()
        };
        let attributes = Attributes::from(&elem);
        assert!(attributes.has_attr(AttrType::MP_UNREACHABLE_NLRI));
        assert!(!attributes.has_attr(AttrType::MP_REACHABLE_NLRI));
    }

    #[test]
    fn test_get_relevant_attributes() {
        let attributes = vec![
            AttributeValue::Origin(Origin::IGP),
            AttributeValue::As4Path(AsPath::from_sequence([65000, 65001, 65002])),
            AttributeValue::NextHop(IpAddr::from_str("10.0.0.1").unwrap()),
            AttributeValue::MultiExitDiscriminator(100),
            AttributeValue::LocalPreference(200),
            AttributeValue::AtomicAggregate,
            AttributeValue::Aggregator {
                asn: Asn::new_32bit(65000),
                id: Ipv4Addr::from_str("10.0.0.1").unwrap(),
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
                code: AttrType::RESERVED.into(),
                bytes: Bytes::new(),
            }),
            AttributeValue::Deprecated(AttrRaw {
                code: AttrType::RESERVED.into(),
                bytes: Bytes::new(),
            }),
        ]
        .into_iter()
        .map(Attribute::from)
        .collect::<Vec<Attribute>>();

        let attributes = Attributes::from(attributes);

        let attrs = get_relevant_attributes(attributes);

        assert_eq!(attrs.origin, Some(Origin::IGP));
        assert_eq!(
            attrs.as4_path,
            Some(AsPath::from_sequence([65000, 65001, 65002]))
        );
        assert_eq!(attrs.next_hop, Some(IpAddr::from_str("10.0.0.1").unwrap()));
        assert_eq!((attrs.med, attrs.local_pref), (Some(100), Some(200)));
        assert!(attrs.atomic);
        // one community of each of the four kinds, in attribute order
        let communities = attrs.communities.unwrap();
        assert_eq!(communities.len(), 4);
        assert_eq!(communities[0], MetaCommunity::Plain(Community::NoExport));
        let prefix = NetworkPrefix::from_str("10.0.0.0/24").unwrap();
        assert_eq!(attrs.announced_prefixes, vec![prefix]);
        assert_eq!(attrs.withdrawn_prefixes, vec![prefix]);
        assert_eq!(attrs.only_to_customer, Some(Asn::new_32bit(65000)));
        assert_eq!(attrs.unknown.map(|v| v.len()), Some(1));
        assert_eq!(attrs.deprecated.map(|v| v.len()), Some(1));
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

        let next_hop = get_relevant_attributes(attributes).next_hop;

        assert_eq!(next_hop, Some(IpAddr::from_str("10.0.0.1").unwrap()));

        let attributes = vec![AttributeValue::MpReachNlri(Nlri::new_reachable(
            NetworkPrefix::from_str("10.0.0.0/24").unwrap(),
            Some(IpAddr::from_str("10.0.0.2").unwrap()),
        ))]
        .into_iter()
        .map(Attribute::from)
        .collect::<Vec<Attribute>>();

        let attributes = Attributes::from(attributes);

        let next_hop = get_relevant_attributes(attributes).next_hop;

        assert_eq!(next_hop, Some(IpAddr::from_str("10.0.0.2").unwrap()));
    }

    #[test]
    fn test_record_to_elems_iter_equivalence_tabledumpv2_small() {
        // rib-example-small.bz2 is a TableDumpV2 file (starts with PeerIndexTable)
        let url = "https://spaces.bgpkit.org/parser/rib-example-small.bz2";

        let mut elementor = Elementor::new();
        let parser = BgpkitParser::new(url).unwrap();
        let mut record_iter = parser.into_record_iter();

        // Skip the PeerIndexTable
        let peer_index_table = record_iter.next().unwrap();
        let _ = elementor.record_to_elems(peer_index_table);

        // Process the first RIB entry
        let record = record_iter.next().unwrap();
        let elems_vec = elementor.record_to_elems(record.clone());
        let elems_iter: Vec<BgpElem> = elementor.record_to_elems_iter(record).unwrap().collect();
        assert_eq!(elems_vec, elems_iter);
        assert!(!elems_vec.is_empty());
    }

    #[test]
    fn test_record_to_elems_iter_equivalence_bgp4mp() {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";

        let mut elementor = Elementor::new();
        let parser = BgpkitParser::new(url).unwrap();
        let mut record_iter = parser.into_record_iter();
        let record = record_iter.next().unwrap();

        let elems_vec = elementor.record_to_elems(record.clone());
        let elems_iter: Vec<BgpElem> = elementor.record_to_elems_iter(record).unwrap().collect();
        assert_eq!(elems_vec, elems_iter);
        assert!(!elems_vec.is_empty());
    }

    #[test]
    #[ignore = "requires large RIB file download"]
    fn test_record_to_elems_iter_equivalence_tabledumpv2() {
        let url = "https://data.ris.ripe.net/rrc00/2023.01/bview.20230101.0000.gz";

        let mut elementor = Elementor::new();
        let parser = BgpkitParser::new(url).unwrap();
        let mut record_iter = parser.into_record_iter();

        let peer_index_table = record_iter.next().unwrap();
        let _ = elementor.record_to_elems(peer_index_table);

        let record = record_iter.next().unwrap();
        let elems_vec = elementor.record_to_elems(record.clone());
        let elems_iter: Vec<BgpElem> = elementor.record_to_elems_iter(record).unwrap().collect();
        assert_eq!(elems_vec, elems_iter);
        assert!(!elems_vec.is_empty());
    }

    #[test]
    fn test_record_to_elems_iter_tabledumpv2_with_peer_table() {
        let url = "https://spaces.bgpkit.org/parser/rib-example-small.bz2";

        let parser = BgpkitParser::new(url).unwrap();
        let mut record_iter = parser.into_record_iter();

        let peer_index_table = record_iter.next().unwrap();
        let mut elementor = Elementor::with_peer_table(
            if let MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(pit)) =
                peer_index_table.message
            {
                pit
            } else {
                panic!("Expected PeerIndexTable");
            },
        );

        let record = record_iter.next().unwrap();
        let elems_vec = elementor.record_to_elems(record.clone());
        let elems_iter: Vec<BgpElem> = elementor.record_to_elems_iter(record).unwrap().collect();
        assert_eq!(elems_vec, elems_iter);
        assert!(!elems_vec.is_empty());
    }

    #[test]
    fn test_record_to_elems_iter_error_unexpected_peer_index_table() {
        let url = "https://spaces.bgpkit.org/parser/rib-example-small.bz2";

        let elementor = Elementor::new();
        let parser = BgpkitParser::new(url).unwrap();
        let mut record_iter = parser.into_record_iter();
        let record = record_iter.next().unwrap();

        let result = elementor.record_to_elems_iter(record);
        assert!(matches!(
            result,
            Err(ElemError::UnexpectedPeerIndexTable(_))
        ));
    }

    #[test]
    fn test_record_to_elems_iter_error_missing_peer_table() {
        // rib-example-small.bz2 is a TableDumpV2 file (starts with PeerIndexTable)
        let url = "https://spaces.bgpkit.org/parser/rib-example-small.bz2";

        let elementor = Elementor::new();
        let parser = BgpkitParser::new(url).unwrap();
        let mut record_iter = parser.into_record_iter();

        // Skip the PeerIndexTable without consuming it via record_to_elems
        // which would set the peer table in the elementor
        let _peer_index_table = record_iter.next().unwrap();

        // Now try to process a RIB entry without having set the peer table
        let record = record_iter.next().unwrap();
        let result = elementor.record_to_elems_iter(record);
        assert!(matches!(result, Err(ElemError::MissingPeerTable)));
    }

    #[test]
    fn test_bgp_to_elems_iter_equivalence() {
        let timestamp = 0.0;
        let peer_ip = IpAddr::from_str("10.0.0.1").unwrap();
        let peer_asn = Asn::new_32bit(65000);

        let attributes = vec![
            AttributeValue::Origin(Origin::IGP),
            AttributeValue::AsPath(AsPath::from_sequence([65000, 65001, 65002])),
            AttributeValue::NextHop(peer_ip),
        ]
        .into_iter()
        .map(Attribute::from)
        .collect::<Vec<Attribute>>();
        let attributes = Attributes::from(attributes);

        let announced_prefixes = vec![NetworkPrefix::from_str("10.0.0.0/24").unwrap()];

        let bgp_message = BgpMessage::Update(BgpUpdateMessage {
            attributes,
            announced_prefixes,
            withdrawn_prefixes: vec![],
        });

        let elems_vec =
            Elementor::bgp_to_elems(bgp_message.clone(), timestamp, &peer_ip, &peer_asn);
        let elems_iter: Vec<BgpElem> =
            Elementor::bgp_to_elems_iter(bgp_message, timestamp, &peer_ip, &peer_asn)
                .unwrap()
                .collect();
        assert_eq!(elems_vec, elems_iter);
        assert_eq!(elems_vec.len(), 1);
    }

    #[test]
    fn test_bgp_to_elems_iter_non_update_messages() {
        use std::net::Ipv4Addr;

        let timestamp = 0.0;
        let peer_ip = IpAddr::from_str("10.0.0.1").unwrap();
        let peer_asn = Asn::new_32bit(65000);

        let open_msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_32bit(1),
            hold_time: 180,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![],
        };
        assert!(Elementor::bgp_to_elems_iter(
            BgpMessage::Open(open_msg),
            timestamp,
            &peer_ip,
            &peer_asn
        )
        .is_none());

        let notification_msg = BgpNotificationMessage {
            error: BgpError::Unknown(0, 0),
            data: vec![],
        };
        assert!(Elementor::bgp_to_elems_iter(
            BgpMessage::Notification(notification_msg),
            timestamp,
            &peer_ip,
            &peer_asn
        )
        .is_none());

        assert!(Elementor::bgp_to_elems_iter(
            BgpMessage::KeepAlive,
            timestamp,
            &peer_ip,
            &peer_asn
        )
        .is_none());
    }

    #[test]
    fn test_bgp_update_to_elems_iter_equivalence() {
        let timestamp = 0.0;
        let peer_ip = IpAddr::from_str("10.0.0.1").unwrap();
        let peer_asn = Asn::new_32bit(65000);

        let attributes = vec![
            AttributeValue::Origin(Origin::IGP),
            AttributeValue::AsPath(AsPath::from_sequence([65000, 65001, 65002])),
            AttributeValue::NextHop(peer_ip),
        ]
        .into_iter()
        .map(Attribute::from)
        .collect::<Vec<Attribute>>();
        let attributes = Attributes::from(attributes);

        let announced_prefixes = vec![NetworkPrefix::from_str("10.0.0.0/24").unwrap()];
        let withdrawn_prefixes = vec![NetworkPrefix::from_str("10.0.1.0/24").unwrap()];

        let update = BgpUpdateMessage {
            attributes,
            announced_prefixes,
            withdrawn_prefixes,
        };

        let elems_vec =
            Elementor::bgp_update_to_elems(update.clone(), timestamp, &peer_ip, &peer_asn);
        let elems_iter: Vec<BgpElem> =
            Elementor::bgp_update_to_elems_iter(update, timestamp, &peer_ip, &peer_asn).collect();
        assert_eq!(elems_vec, elems_iter);
        assert_eq!(elems_vec.len(), 2);
    }

    #[test]
    fn test_bgp_update_to_elems_iter_shares_attributes_across_prefixes() {
        let peer_ip = IpAddr::from_str("10.0.0.1").unwrap();
        let peer_asn = Asn::new_32bit(65000);
        let as_path = AsPath::from_sequence([65000, 65001, 65002]);
        let unknown = AttrRaw {
            code: 254,
            bytes: Bytes::from_static(&[1, 2]),
        };

        let attributes = vec![
            AttributeValue::AsPath(as_path.clone()),
            AttributeValue::Communities(vec![Community::NoExport]),
            AttributeValue::Unknown(unknown.clone()),
            AttributeValue::MpReachNlri(Nlri::new_reachable(
                NetworkPrefix::from_str("2001:db8::/32").unwrap(),
                Some(IpAddr::from_str("2001:db8::1").unwrap()),
            )),
        ]
        .into_iter()
        .map(Attribute::from)
        .collect::<Vec<Attribute>>();

        let update = BgpUpdateMessage {
            attributes: Attributes::from(attributes),
            announced_prefixes: vec![
                NetworkPrefix::from_str("10.0.0.0/24").unwrap(),
                NetworkPrefix::from_str("10.0.2.0/24").unwrap(),
            ],
            withdrawn_prefixes: vec![NetworkPrefix::from_str("10.0.1.0/24").unwrap()],
        };

        let mut iter = Elementor::bgp_update_to_elems_iter(update, 0.0, &peer_ip, &peer_asn);
        assert_eq!(iter.size_hint(), (4, Some(4)));
        let elems: Vec<BgpElem> = iter.by_ref().collect();
        assert_eq!(iter.size_hint(), (0, Some(0)));

        // the classic NLRI first, then the MP_REACH_NLRI prefix; the last announcement takes
        // the shared attributes rather than cloning them, so it must match the others
        let announced: Vec<&BgpElem> = elems.iter().filter(|e| e.elem_type.is_announce()).collect();
        assert_eq!(announced.len(), 3);
        assert_eq!(
            announced[2].prefix,
            NetworkPrefix::from_str("2001:db8::/32").unwrap()
        );
        for elem in &announced {
            assert_eq!(elem.as_path.as_ref(), Some(&as_path));
            assert_eq!(elem.origin_asns, Some(vec![Asn::new_32bit(65002)]));
            assert_eq!(
                elem.communities,
                Some(vec![MetaCommunity::Plain(Community::NoExport)])
            );
            assert_eq!(elem.unknown, Some(vec![unknown.clone()]));
        }

        let withdrawn = elems.last().unwrap();
        assert_eq!(withdrawn.elem_type, ElemType::WITHDRAW);
        assert_eq!(withdrawn.as_path, None);
        assert_eq!(withdrawn.communities, None);
    }

    #[test]
    fn test_record_elem_iter_size_hint() {
        use std::collections::HashMap;

        let peer_table = PeerIndexTable {
            collector_bgp_id: BgpIdentifier::from_str("10.0.0.1").unwrap(),
            view_name: "".to_string(),
            id_peer_map: HashMap::new(),
            peer_ip_id_map: HashMap::new(),
        };

        let entries: Vec<RibEntry> = vec![];
        let iter = RecordElemIter::RibAfi {
            peer_table: &peer_table,
            prefix: NetworkPrefix::from_str("10.0.0.0/24").unwrap(),
            entries: entries.into_iter(),
        };
        assert_eq!(iter.size_hint(), (0, Some(0)));

        let entries: Vec<RibEntry> = (0..5)
            .map(|i| RibEntry {
                peer_index: i as u16,
                originated_time: 0,
                path_id: None,
                attributes: Attributes::default(),
            })
            .collect();
        let iter = RecordElemIter::RibAfi {
            peer_table: &peer_table,
            prefix: NetworkPrefix::from_str("10.0.0.0/24").unwrap(),
            entries: entries.into_iter(),
        };
        assert_eq!(iter.size_hint(), (5, Some(5)));
    }

    #[test]
    fn test_pending_elems_rib_entries() {
        use std::collections::HashMap;

        let peer = Peer::new(
            BgpIdentifier::from_str("10.0.0.2").unwrap(),
            IpAddr::from_str("10.0.0.2").unwrap(),
            Asn::new_32bit(65002),
        );
        let peer_table = PeerIndexTable {
            collector_bgp_id: BgpIdentifier::from_str("10.0.0.1").unwrap(),
            view_name: "".to_string(),
            id_peer_map: HashMap::from([(0, peer)]),
            peer_ip_id_map: HashMap::new(),
        };
        let prefix = NetworkPrefix::from_str("10.0.0.0/24").unwrap();
        // peer 0 is in the table, peer 7 is not
        let pending = || PendingElems::RibAfi {
            prefix,
            entries: [0, 0, 7, 0]
                .map(|peer_index| RibEntry {
                    peer_index,
                    originated_time: 0,
                    path_id: None,
                    attributes: Attributes::default(),
                })
                .to_vec()
                .into_iter(),
        };

        // an unknown peer ends the record, like RecordElemIter does
        let mut elems = pending();
        let first = elems.next_elem(Some(&peer_table)).unwrap();
        assert_eq!(first.prefix, prefix);
        assert_eq!(first.peer_asn, Asn::new_32bit(65002));
        assert!(elems.next_elem(Some(&peer_table)).is_some());
        assert!(elems.next_elem(Some(&peer_table)).is_none());
        assert!(matches!(elems, PendingElems::Empty));

        // without a peer table nothing is produced
        let mut elems = pending();
        assert!(elems.next_elem(None).is_none());
        assert!(matches!(elems, PendingElems::Empty));
    }
}
