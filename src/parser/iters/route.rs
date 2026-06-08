use crate::error::{ParserError, ParserErrorWithBytes};
use crate::models::*;
use crate::parser::bgp::attributes::{parse_as_path, AttributeValidationState};
use crate::parser::bgp::messages::read_and_validate_bgp_marker;
use crate::parser::iters::write_mrt_core_dump;
use crate::parser::mrt::messages::bgp4mp::bgp4mp_message_payload_len;
use crate::parser::mrt::messages::table_dump_v2::rib_entry_min_len;
use crate::parser::{
    chunk_mrt_record, looks_like_zero_path_id_add_path, try_parse_prefix, BgpkitParser, Filter,
    Filterable, ReadUtils,
};
use bytes::{Buf, Bytes};
use ipnet::IpNet;
use log::{debug, error, warn};
use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Default)]
struct RouteAttributes {
    as_path: Option<AsPath>,
    announced: Vec<RouteNlriBytes>,
    withdrawn: Vec<RouteNlriBytes>,
}

struct RouteAttributeContext<'a> {
    afi: Option<Afi>,
    safi: Option<Safi>,
    prefixes: Option<&'a [NetworkPrefix]>,
    is_announcement: Option<bool>,
    has_standard_nlri: bool,
}

#[derive(Clone)]
struct RouteNlriBytes {
    data: Bytes,
    afi: Afi,
    add_path: bool,
}

fn merge_as_path(as_path: Option<AsPath>, as4_path: Option<AsPath>) -> Option<AsPath> {
    match (as_path, as4_path) {
        (None, None) => None,
        (Some(path), None) | (None, Some(path)) => Some(path),
        (Some(path), Some(as4_path)) => Some(AsPath::merge_aspath_as4path(&path, &as4_path)),
    }
}

fn parse_route_nlri_bytes(
    mut input: Bytes,
    afi: &Option<Afi>,
    safi: &Option<Safi>,
    prefixes: &Option<&[NetworkPrefix]>,
    reachable: bool,
    add_path: bool,
) -> Result<Option<RouteNlriBytes>, ParserError> {
    let first_byte_zero = input.first().map(|b| *b == 0).unwrap_or(false);

    let afi = match afi {
        Some(afi) => {
            if first_byte_zero {
                input.read_afi()?
            } else {
                *afi
            }
        }
        None => input.read_afi()?,
    };
    let safi = match safi {
        Some(safi) => {
            if first_byte_zero {
                input.read_safi()?
            } else {
                *safi
            }
        }
        None => input.read_safi()?,
    };

    if afi == Afi::LinkState || safi == Safi::LinkState || safi == Safi::LinkStateVpn {
        return Ok(None);
    }

    if safi == Safi::MplsLabel {
        if reachable {
            return Ok(None);
        }

        let config = LabeledNlriConfig {
            add_path,
            mode: LabeledNlriMode::MultiLabel,
            max_labels: 16,
            peer_max_labels: None,
        };
        let prefixes = parse_labeled_withdrawal_nlri(&mut input, afi, &config)?;
        return Ok(Some(RouteNlriBytes {
            data: encode_nlri_prefixes_without_alloc_api(&prefixes),
            afi,
            add_path,
        }));
    }

    if reachable {
        let next_hop_length = input.read_u8()? as usize;
        input.has_n_remaining(next_hop_length)?;
        input.advance(next_hop_length);
    }

    if let Some(prefixes) = prefixes {
        if !first_byte_zero {
            return Ok(Some(RouteNlriBytes {
                data: encode_nlri_prefixes_without_alloc_api(prefixes),
                afi,
                add_path,
            }));
        }
    }

    if reachable && input.read_u8()? != 0 {
        warn!("NLRI reserved byte not 0 (parsing route-level NLRI prefixes)");
    }

    Ok(Some(RouteNlriBytes {
        data: input,
        afi,
        add_path,
    }))
}

fn encode_nlri_prefixes_without_alloc_api(prefixes: &[NetworkPrefix]) -> Bytes {
    crate::parser::encode_nlri_prefixes(prefixes)
}

fn parse_route_attributes(
    mut data: Bytes,
    asn_len: &AsnLength,
    add_path: bool,
    ctx: RouteAttributeContext<'_>,
) -> Result<RouteAttributes, ParserError> {
    let mut validation = AttributeValidationState::new();
    let mut as_path = None;
    let mut as4_path = None;
    let mut announced = Vec::new();
    let mut withdrawn = Vec::new();

    while data.remaining() >= 3 {
        let flags = AttrFlags::from_bits_retain(data.read_u8()?);
        let raw_attr_type = data.read_u8()?;
        let attr_length = if flags.contains(AttrFlags::EXTENDED) {
            data.read_u16()? as usize
        } else {
            data.read_u8()? as usize
        };
        let attr_type = AttrType::from(raw_attr_type);
        let partial = validation.observe_header(raw_attr_type, attr_type, flags, attr_length);

        if data.remaining() < attr_length {
            warn!(
                "{:?} attribute encodes a length ({}) that is longer than the remaining attribute data ({}). Skipping remaining attribute data for BGP message",
                attr_type,
                attr_length,
                data.remaining()
            );
            break;
        }

        let attr_data = data.split_to(attr_length);
        let result = match attr_type {
            AttrType::AS_PATH => parse_as_path(attr_data, asn_len).map(|path| {
                as_path = Some(path);
            }),
            AttrType::AS4_PATH => parse_as_path(attr_data, &AsnLength::Bits32).map(|path| {
                as4_path = Some(path);
            }),
            AttrType::MP_REACHABLE_NLRI => parse_route_nlri_bytes(
                attr_data,
                &ctx.afi,
                &ctx.safi,
                &ctx.prefixes,
                true,
                add_path,
            )
            .map(|nlri| {
                if let Some(nlri) = nlri {
                    announced.push(nlri);
                }
            }),
            AttrType::MP_UNREACHABLE_NLRI => parse_route_nlri_bytes(
                attr_data,
                &ctx.afi,
                &ctx.safi,
                &ctx.prefixes,
                false,
                add_path,
            )
            .map(|nlri| {
                if let Some(nlri) = nlri {
                    withdrawn.push(nlri);
                }
            }),
            _ => Ok(()),
        };

        if let Err(err) = result {
            validation.observe_parse_error(attr_type, partial, &err);
        }
    }

    let is_announcement = ctx
        .is_announcement
        .unwrap_or(ctx.has_standard_nlri || validation.has_attr(AttrType::MP_REACHABLE_NLRI));
    validation.check_mandatory_attributes(is_announcement, ctx.has_standard_nlri);
    let _warnings = validation.finish();
    Ok(RouteAttributes {
        as_path: merge_as_path(as_path, as4_path),
        announced,
        withdrawn,
    })
}

fn record_timestamp(common_header: &CommonHeader) -> f64 {
    match common_header.microsecond_timestamp {
        Some(microseconds) => common_header.timestamp as f64 + microseconds as f64 / 1_000_000.0,
        None => common_header.timestamp as f64,
    }
}

struct NlriPrefixIter {
    input: Bytes,
    afi: Afi,
    add_path: bool,
    is_add_path: bool,
    use_heuristic: bool,
}

impl NlriPrefixIter {
    fn new(input: Bytes, afi: Afi, add_path: bool) -> Self {
        Self {
            input,
            afi,
            add_path,
            is_add_path: add_path,
            use_heuristic: false,
        }
    }
}

impl Iterator for NlriPrefixIter {
    type Item = Result<NetworkPrefix, ParserError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.input.remaining() == 0 {
            return None;
        }

        let data = self.input.as_ref();
        if !self.is_add_path && looks_like_zero_path_id_add_path(data) {
            debug!("NLRI: first 4 bytes are 0, treating as Add-Path format");
            self.is_add_path = true;
            self.use_heuristic = true;
        }

        let (prefix, consumed) = match try_parse_prefix(data, &self.afi, self.is_add_path) {
            Ok(result) => result,
            Err(_) if self.use_heuristic => {
                debug!(
                    "NLRI: Add-Path heuristic failed, retrying with add_path={}",
                    self.add_path
                );
                self.is_add_path = self.add_path;
                self.use_heuristic = false;
                match try_parse_prefix(data, &self.afi, self.add_path) {
                    Ok(result) => result,
                    Err(err) => return Some(Err(err)),
                }
            }
            Err(err) => return Some(Err(err)),
        };

        self.input.advance(consumed);
        Some(Ok(prefix))
    }
}

#[derive(Clone)]
enum RoutePrefixSource {
    One(Option<NetworkPrefix>),
    Nlri(RouteNlriBytes),
}

impl RoutePrefixSource {
    fn iter(&self) -> RoutePrefixSourceIter {
        match self {
            RoutePrefixSource::One(prefix) => RoutePrefixSourceIter::One(*prefix),
            RoutePrefixSource::Nlri(nlri) => RoutePrefixSourceIter::Nlri(NlriPrefixIter::new(
                nlri.data.clone(),
                nlri.afi,
                nlri.add_path,
            )),
        }
    }
}

enum RoutePrefixSourceIter {
    One(Option<NetworkPrefix>),
    Nlri(NlriPrefixIter),
}

impl Iterator for RoutePrefixSourceIter {
    type Item = Result<NetworkPrefix, ParserError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            RoutePrefixSourceIter::One(prefix) => prefix.take().map(Ok),
            RoutePrefixSourceIter::Nlri(iter) => iter.next(),
        }
    }
}

struct RouteBatchPart {
    elem_type: ElemType,
    source: RoutePrefixSource,
    has_as_path: bool,
}

/// A route-level MRT/BGP batch with shared parsed state.
///
/// A batch corresponds to one MRT route-bearing record or BGP UPDATE message.
/// Prefixes are parsed lazily from shared `Bytes` slices when iterating routes.
#[derive(Clone)]
pub struct RouteBatch {
    timestamp: f64,
    peer_ip: IpAddr,
    peer_asn: Asn,
    as_path: Option<AsPath>,
    parts: Arc<[RouteBatchPart]>,
    filters: Arc<[Filter]>,
}

impl RouteBatch {
    fn new(
        timestamp: f64,
        peer_ip: IpAddr,
        peer_asn: Asn,
        as_path: Option<AsPath>,
        parts: Vec<RouteBatchPart>,
        filters: Arc<[Filter]>,
    ) -> Self {
        Self {
            timestamp,
            peer_ip,
            peer_asn,
            as_path,
            parts: Arc::from(parts),
            filters,
        }
    }

    pub fn routes(&self) -> RouteBatchIter<'_> {
        RouteBatchIter::new(self, true)
    }

    pub fn all_routes(&self) -> RouteBatchIter<'_> {
        RouteBatchIter::new(self, false)
    }
}

pub struct RouteBatchIter<'a> {
    batch: &'a RouteBatch,
    part_index: usize,
    current: Option<RoutePrefixSourceIter>,
    filtered: bool,
}

impl<'a> RouteBatchIter<'a> {
    fn new(batch: &'a RouteBatch, filtered: bool) -> Self {
        Self {
            batch,
            part_index: 0,
            current: None,
            filtered,
        }
    }
}

impl<'a> Iterator for RouteBatchIter<'a> {
    type Item = Result<BgpRouteElem<'a>, ParserError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current.is_none() {
                let part = self.batch.parts.get(self.part_index)?;
                self.part_index += 1;
                self.current = Some(part.source.iter());
            }

            let part = &self.batch.parts[self.part_index - 1];
            let prefix = match self.current.as_mut().and_then(Iterator::next) {
                Some(Ok(prefix)) => prefix,
                Some(Err(err)) => return Some(Err(err)),
                None => {
                    self.current = None;
                    continue;
                }
            };

            let route = BgpRouteElem {
                timestamp: self.batch.timestamp,
                elem_type: part.elem_type,
                peer_ip: self.batch.peer_ip,
                peer_asn: self.batch.peer_asn,
                prefix,
                as_path: part
                    .has_as_path
                    .then_some(())
                    .and(self.batch.as_path.as_ref()),
            };

            if !self.filtered || route.match_filters(&self.batch.filters) {
                return Some(Ok(route));
            }
        }
    }
}

#[derive(Clone, Default)]
struct RoutePeerTable {
    peers: Arc<[Peer]>,
}

impl RoutePeerTable {
    fn get_peer_by_id(&self, peer_index: u16) -> Option<Peer> {
        self.peers.get(peer_index as usize).copied()
    }
}

fn parse_route_peer_table(mut data: Bytes) -> Result<RoutePeerTable, ParserError> {
    let _collector_bgp_id = data.read_u32()?;
    let view_name_length = data.read_u16()? as usize;
    data.has_n_remaining(view_name_length)?;
    data.advance(view_name_length);

    let peer_count = data.read_u16()? as usize;
    let mut peers = Vec::with_capacity(peer_count);
    for _ in 0..peer_count {
        let peer_type = PeerType::from_bits_retain(data.read_u8()?);
        let afi = if peer_type.contains(PeerType::ADDRESS_FAMILY_IPV6) {
            Afi::Ipv6
        } else {
            Afi::Ipv4
        };
        let asn_len = if peer_type.contains(PeerType::AS_SIZE_32BIT) {
            AsnLength::Bits32
        } else {
            AsnLength::Bits16
        };

        let peer_bgp_id = data.read_ipv4_address()?;
        let peer_ip = data.read_address(&afi)?;
        let peer_asn = data.read_asn(asn_len)?;
        peers.push(Peer {
            peer_type,
            peer_bgp_id,
            peer_ip,
            peer_asn,
        });
    }

    Ok(RoutePeerTable {
        peers: Arc::from(peers),
    })
}

#[derive(Default)]
enum RouteRecordIter {
    #[default]
    Empty,
    One(RouteBatch),
    RibAfi(RouteRibAfiIter),
}

impl RouteRecordIter {
    fn next_batch(&mut self, filters: Arc<[Filter]>) -> Result<Option<RouteBatch>, ParserError> {
        match std::mem::take(self) {
            RouteRecordIter::Empty => Ok(None),
            RouteRecordIter::One(batch) => Ok(Some(batch)),
            RouteRecordIter::RibAfi(mut iter) => {
                let batch = iter.next_batch(filters)?;
                if iter.remaining_entries > 0 {
                    *self = RouteRecordIter::RibAfi(iter);
                }
                Ok(batch)
            }
        }
    }
}

struct RouteRibAfiIter {
    data: Bytes,
    peer_table: RoutePeerTable,
    afi: Afi,
    safi: Safi,
    is_add_path: bool,
    prefix: NetworkPrefix,
    remaining_entries: u16,
}

impl RouteRibAfiIter {
    fn next_batch(&mut self, filters: Arc<[Filter]>) -> Result<Option<RouteBatch>, ParserError> {
        while self.remaining_entries > 0 {
            if self.data.remaining() < rib_entry_min_len(self.is_add_path) {
                warn!("early break due to truncated msg while parsing RIB AFI entries");
                self.remaining_entries = 0;
                return Ok(None);
            }

            self.remaining_entries -= 1;
            let peer_index = self.data.read_u16()?;
            let originated_time = self.data.read_u32()? as f64;
            let _path_id = if self.is_add_path {
                Some(self.data.read_u32()?)
            } else {
                None
            };
            let attribute_length = self.data.read_u16()? as usize;
            if self.data.remaining() < attribute_length {
                warn!(
                    "early break due to truncated attribute payload while parsing RIB AFI entries: expected {} bytes, have {} bytes available",
                    attribute_length,
                    self.data.remaining()
                );
                self.remaining_entries = 0;
                return Ok(None);
            }

            let prefixes = [self.prefix];
            let attrs = parse_route_attributes(
                self.data.split_to(attribute_length),
                &AsnLength::Bits32,
                self.is_add_path,
                RouteAttributeContext {
                    afi: Some(self.afi),
                    safi: Some(self.safi),
                    prefixes: Some(&prefixes),
                    is_announcement: Some(true),
                    has_standard_nlri: self.afi == Afi::Ipv4,
                },
            )?;
            let Some(peer) = self.peer_table.get_peer_by_id(peer_index) else {
                error!("peer ID {} not found in peer_index table", peer_index);
                continue;
            };

            return Ok(Some(RouteBatch::new(
                originated_time,
                peer.peer_ip,
                peer.peer_asn,
                attrs.as_path,
                vec![RouteBatchPart {
                    elem_type: ElemType::ANNOUNCE,
                    source: RoutePrefixSource::One(Some(self.prefix)),
                    has_as_path: true,
                }],
                filters,
            )));
        }

        Ok(None)
    }
}

fn parse_bgp_update_routes(
    mut input: Bytes,
    add_path: bool,
    asn_len: &AsnLength,
    timestamp: f64,
    peer_ip: IpAddr,
    peer_asn: Asn,
    filters: Arc<[Filter]>,
) -> Result<RouteBatch, ParserError> {
    let withdrawn_len = input.read_u16()? as usize;
    input.has_n_remaining(withdrawn_len)?;
    let withdrawn_prefixes = input.split_to(withdrawn_len);

    let attribute_length = input.read_u16()? as usize;
    input.has_n_remaining(attribute_length)?;
    let attribute_bytes = input.split_to(attribute_length);
    let announced_prefixes = input;
    let has_standard_nlri = !announced_prefixes.is_empty();
    let attributes = parse_route_attributes(
        attribute_bytes,
        asn_len,
        add_path,
        RouteAttributeContext {
            afi: None,
            safi: None,
            prefixes: None,
            is_announcement: None,
            has_standard_nlri,
        },
    )?;

    let mut parts = Vec::new();
    if !announced_prefixes.is_empty() {
        parts.push(RouteBatchPart {
            elem_type: ElemType::ANNOUNCE,
            source: RoutePrefixSource::Nlri(RouteNlriBytes {
                data: announced_prefixes,
                afi: Afi::Ipv4,
                add_path,
            }),
            has_as_path: true,
        });
    }
    parts.extend(attributes.announced.into_iter().map(|nlri| RouteBatchPart {
        elem_type: ElemType::ANNOUNCE,
        source: RoutePrefixSource::Nlri(nlri),
        has_as_path: true,
    }));
    if !withdrawn_prefixes.is_empty() {
        parts.push(RouteBatchPart {
            elem_type: ElemType::WITHDRAW,
            source: RoutePrefixSource::Nlri(RouteNlriBytes {
                data: withdrawn_prefixes,
                afi: Afi::Ipv4,
                add_path,
            }),
            has_as_path: false,
        });
    }
    parts.extend(attributes.withdrawn.into_iter().map(|nlri| RouteBatchPart {
        elem_type: ElemType::WITHDRAW,
        source: RoutePrefixSource::Nlri(nlri),
        has_as_path: false,
    }));

    Ok(RouteBatch::new(
        timestamp,
        peer_ip,
        peer_asn,
        attributes.as_path,
        parts,
        filters,
    ))
}

fn parse_bgp_message_routes(
    mut data: Bytes,
    add_path: bool,
    asn_len: &AsnLength,
    timestamp: f64,
    peer_ip: IpAddr,
    peer_asn: Asn,
    filters: Arc<[Filter]>,
) -> Result<RouteRecordIter, ParserError> {
    let total_size = data.len();
    data.has_n_remaining(19)?;
    read_and_validate_bgp_marker(&mut data)?;
    let length = data.read_u16()?;
    if !(19..=65_535).contains(&length) {
        return Err(ParserError::ParseError(format!(
            "invalid BGP message length {length}"
        )));
    }

    let bgp_msg_length = if length as usize > total_size {
        total_size - 19
    } else {
        length as usize - 19
    };
    let msg_type = BgpMessageType::try_from(data.read_u8()?)
        .map_err(|_| ParserError::ParseError("Unknown BGP Message Type".to_string()))?;

    if matches!(msg_type, BgpMessageType::OPEN | BgpMessageType::KEEPALIVE) && length > 4096 {
        return Err(ParserError::ParseError(format!(
            "BGP {msg_type:?} message length {length} exceeds maximum allowed 4096 bytes (RFC 8654)"
        )));
    }

    if data.remaining() != bgp_msg_length {
        warn!(
            "BGP message length {} does not match the actual length {} (parsing BGP message)",
            bgp_msg_length,
            data.remaining()
        );
    }
    data.has_n_remaining(bgp_msg_length)?;
    let msg_data = data.split_to(bgp_msg_length);

    match msg_type {
        BgpMessageType::UPDATE => Ok(RouteRecordIter::One(parse_bgp_update_routes(
            msg_data, add_path, asn_len, timestamp, peer_ip, peer_asn, filters,
        )?)),
        BgpMessageType::OPEN | BgpMessageType::NOTIFICATION | BgpMessageType::KEEPALIVE => {
            Ok(RouteRecordIter::Empty)
        }
    }
}

fn bgp4mp_asn_len_and_add_path(msg_type: Bgp4MpType) -> Option<(AsnLength, bool)> {
    match msg_type {
        Bgp4MpType::Message | Bgp4MpType::MessageLocal => Some((AsnLength::Bits16, false)),
        Bgp4MpType::MessageAs4 | Bgp4MpType::MessageAs4Local => Some((AsnLength::Bits32, false)),
        Bgp4MpType::MessageAddpath | Bgp4MpType::MessageLocalAddpath => {
            Some((AsnLength::Bits16, true))
        }
        Bgp4MpType::MessageAs4Addpath | Bgp4MpType::MessageLocalAs4Addpath => {
            Some((AsnLength::Bits32, true))
        }
        Bgp4MpType::StateChange | Bgp4MpType::StateChangeAs4 => None,
    }
}

fn parse_bgp4mp_routes(
    sub_type: u16,
    mut data: Bytes,
    timestamp: f64,
    filters: Arc<[Filter]>,
) -> Result<RouteRecordIter, ParserError> {
    let msg_type = Bgp4MpType::try_from(sub_type)?;
    let Some((asn_len, add_path)) = bgp4mp_asn_len_and_add_path(msg_type) else {
        return Ok(RouteRecordIter::Empty);
    };

    let total_size = data.len();
    let peer_asn = data.read_asn(asn_len)?;
    let _local_asn = data.read_asn(asn_len)?;
    let _interface_index = data.read_u16()?;
    let afi = data.read_afi()?;
    let peer_ip = data.read_address(&afi)?;
    let _local_ip = data.read_address(&afi)?;

    let should_read = bgp4mp_message_payload_len(&afi, &asn_len, total_size);
    if should_read != data.remaining() {
        return Err(ParserError::TruncatedMsg(format!(
            "truncated bgp4mp message: should read {} bytes, have {} bytes available",
            should_read,
            data.remaining()
        )));
    }

    parse_bgp_message_routes(
        data, add_path, &asn_len, timestamp, peer_ip, peer_asn, filters,
    )
}

fn table_dump_v2_afi_safi(rib_type: TableDumpV2Type) -> Result<(Afi, Safi), ParserError> {
    match rib_type {
        TableDumpV2Type::RibIpv4Unicast | TableDumpV2Type::RibIpv4UnicastAddPath => {
            Ok((Afi::Ipv4, Safi::Unicast))
        }
        TableDumpV2Type::RibIpv4Multicast | TableDumpV2Type::RibIpv4MulticastAddPath => {
            Ok((Afi::Ipv4, Safi::Multicast))
        }
        TableDumpV2Type::RibIpv6Unicast | TableDumpV2Type::RibIpv6UnicastAddPath => {
            Ok((Afi::Ipv6, Safi::Unicast))
        }
        TableDumpV2Type::RibIpv6Multicast | TableDumpV2Type::RibIpv6MulticastAddPath => {
            Ok((Afi::Ipv6, Safi::Multicast))
        }
        _ => Err(ParserError::ParseError(format!(
            "wrong RIB type for parsing: {rib_type:?}"
        ))),
    }
}

fn is_add_path_rib_type(rib_type: TableDumpV2Type) -> bool {
    matches!(
        rib_type,
        TableDumpV2Type::RibIpv4UnicastAddPath
            | TableDumpV2Type::RibIpv4MulticastAddPath
            | TableDumpV2Type::RibIpv6UnicastAddPath
            | TableDumpV2Type::RibIpv6MulticastAddPath
    )
}

fn parse_table_dump_routes(
    sub_type: u16,
    mut data: Bytes,
    filters: Arc<[Filter]>,
) -> Result<RouteRecordIter, ParserError> {
    let afi = match sub_type {
        1 => Afi::Ipv4,
        2 => Afi::Ipv6,
        _ => {
            return Err(ParserError::ParseError(format!(
                "Invalid subtype found for TABLE_DUMP (V1) message: {sub_type}"
            )))
        }
    };

    let _view_number = data.read_u16()?;
    let _sequence_number = data.read_u16()?;
    let prefix = match &afi {
        Afi::Ipv4 => data.read_ipv4_prefix().map(IpNet::V4),
        Afi::Ipv6 => data.read_ipv6_prefix().map(IpNet::V6),
        Afi::LinkState => unreachable!(),
    }?;
    let _status = data.read_u8()?;
    let originated_time = data.read_u32()? as f64;
    let peer_ip = data.read_address(&afi)?;
    let peer_asn = Asn::new_16bit(data.read_u16()?);
    let attribute_length = data.read_u16()? as usize;
    data.has_n_remaining(attribute_length)?;
    let attrs = parse_route_attributes(
        data.split_to(attribute_length),
        &AsnLength::Bits16,
        false,
        RouteAttributeContext {
            afi: None,
            safi: None,
            prefixes: None,
            is_announcement: Some(true),
            has_standard_nlri: afi == Afi::Ipv4,
        },
    )?;

    Ok(RouteRecordIter::One(RouteBatch::new(
        originated_time,
        peer_ip,
        peer_asn,
        attrs.as_path,
        vec![RouteBatchPart {
            elem_type: ElemType::ANNOUNCE,
            source: RoutePrefixSource::One(Some(NetworkPrefix::new(prefix, None))),
            has_as_path: true,
        }],
        filters,
    )))
}

fn parse_table_dump_v2_routes(
    sub_type: u16,
    mut data: Bytes,
    peer_table: &mut Option<RoutePeerTable>,
    _filters: Arc<[Filter]>,
) -> Result<RouteRecordIter, ParserError> {
    let v2_type = TableDumpV2Type::try_from(sub_type)?;
    match v2_type {
        TableDumpV2Type::PeerIndexTable => {
            *peer_table = Some(parse_route_peer_table(data)?);
            Ok(RouteRecordIter::Empty)
        }
        TableDumpV2Type::GeoPeerTable => Ok(RouteRecordIter::Empty),
        TableDumpV2Type::RibGeneric | TableDumpV2Type::RibGenericAddPath => Err(
            ParserError::Unsupported("TableDumpV2 RibGeneric is not currently supported".into()),
        ),
        rib_type => {
            let (afi, safi) = table_dump_v2_afi_safi(rib_type)?;
            let is_add_path = is_add_path_rib_type(rib_type);
            let _sequence_number = data.read_u32()?;
            let prefix = data.read_nlri_prefix(&afi, false)?;
            let entry_count = data.read_u16()?;
            let Some(peer_table) = peer_table.clone() else {
                return Err(ParserError::ParseError(
                    "peer table not set for TableDumpV2 RIB entries".to_string(),
                ));
            };

            Ok(RouteRecordIter::RibAfi(RouteRibAfiIter {
                data,
                peer_table,
                afi,
                safi,
                is_add_path,
                prefix,
                remaining_entries: entry_count,
            }))
        }
    }
}

fn parse_raw_record_route_iter(
    raw_record: crate::RawMrtRecord,
    peer_table: &mut Option<RoutePeerTable>,
    filters: Arc<[Filter]>,
) -> Result<RouteRecordIter, ParserError> {
    let timestamp = record_timestamp(&raw_record.common_header);
    match raw_record.common_header.entry_type {
        EntryType::TABLE_DUMP => parse_table_dump_routes(
            raw_record.common_header.entry_subtype,
            raw_record.message_bytes,
            filters,
        ),
        EntryType::TABLE_DUMP_V2 => parse_table_dump_v2_routes(
            raw_record.common_header.entry_subtype,
            raw_record.message_bytes,
            peer_table,
            filters,
        ),
        EntryType::BGP4MP | EntryType::BGP4MP_ET => parse_bgp4mp_routes(
            raw_record.common_header.entry_subtype,
            raw_record.message_bytes,
            timestamp,
            filters,
        ),
        v => Err(ParserError::Unsupported(format!(
            "unsupported MRT type: {v:?}"
        ))),
    }
}

pub struct RouteIterator<R> {
    parser: BgpkitParser<R>,
    pending_routes: RouteRecordIter,
    peer_table: Option<RoutePeerTable>,
    filters: Arc<[Filter]>,
}

impl<R> RouteIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        let filters = Arc::from(parser.filters.clone());
        Self {
            parser,
            pending_routes: RouteRecordIter::Empty,
            peer_table: None,
            filters,
        }
    }
}

impl<R: Read> Iterator for RouteIterator<R> {
    type Item = RouteBatch;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.pending_routes.next_batch(Arc::clone(&self.filters)) {
                Ok(Some(batch)) => return Some(batch),
                Ok(None) => {}
                Err(err) => {
                    error!("parser error: {}", err);
                    self.pending_routes = RouteRecordIter::Empty;
                    if self.parser.core_dump {
                        return None;
                    }
                    continue;
                }
            }

            let raw_record = match chunk_mrt_record(&mut self.parser.reader) {
                Ok(raw_record) => raw_record,
                Err(e) => match e.error {
                    ParserError::TruncatedMsg(err_str) | ParserError::Unsupported(err_str) => {
                        if self.parser.options.show_warnings {
                            warn!("parser warn: {}", err_str);
                        }
                        write_mrt_core_dump(self.parser.core_dump, e.bytes);
                        continue;
                    }
                    ParserError::ParseError(err_str) => {
                        error!("parser error: {}", err_str);
                        if self.parser.core_dump {
                            write_mrt_core_dump(true, e.bytes);
                            return None;
                        }
                        continue;
                    }
                    ParserError::EofExpected => return None,
                    ParserError::IoError(err) | ParserError::EofError(err) => {
                        error!("{:?}", err);
                        write_mrt_core_dump(self.parser.core_dump, e.bytes);
                        return None;
                    }
                    #[cfg(feature = "oneio")]
                    ParserError::OneIoError(_) => return None,
                    ParserError::FilterError(_) => return None,
                    ParserError::InvalidLabeledNlriLength
                    | ParserError::TruncatedLabeledNlri
                    | ParserError::TruncatedPrefix
                    | ParserError::MaxLabelStackDepthExceeded
                    | ParserError::PeerMaxLabelsExceeded
                    | ParserError::InvalidPrefix => {
                        if self.parser.options.show_warnings {
                            warn!("parser warn: labeled NLRI parsing error: {:?}", e.error);
                        }
                        continue;
                    }
                },
            };

            match parse_raw_record_route_iter(
                raw_record,
                &mut self.peer_table,
                Arc::clone(&self.filters),
            ) {
                Ok(routes) => {
                    self.pending_routes = routes;
                }
                Err(err) => {
                    error!("parser error: {}", err);
                    if self.parser.core_dump {
                        return None;
                    }
                    continue;
                }
            }
        }
    }
}

pub struct FallibleRouteIterator<R> {
    parser: BgpkitParser<R>,
    pending_routes: RouteRecordIter,
    peer_table: Option<RoutePeerTable>,
    filters: Arc<[Filter]>,
}

impl<R> FallibleRouteIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        let filters = Arc::from(parser.filters.clone());
        Self {
            parser,
            pending_routes: RouteRecordIter::Empty,
            peer_table: None,
            filters,
        }
    }
}

impl<R: Read> Iterator for FallibleRouteIterator<R> {
    type Item = Result<RouteBatch, ParserErrorWithBytes>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.pending_routes.next_batch(Arc::clone(&self.filters)) {
                Ok(Some(batch)) => return Some(Ok(batch)),
                Ok(None) => {}
                Err(error) => {
                    self.pending_routes = RouteRecordIter::Empty;
                    return Some(Err(ParserErrorWithBytes { error, bytes: None }));
                }
            }

            let raw_record = match chunk_mrt_record(&mut self.parser.reader) {
                Ok(raw_record) => raw_record,
                Err(e) if matches!(e.error, ParserError::EofExpected) => return None,
                Err(e) => return Some(Err(e)),
            };

            match parse_raw_record_route_iter(
                raw_record,
                &mut self.peer_table,
                Arc::clone(&self.filters),
            ) {
                Ok(routes) => {
                    self.pending_routes = routes;
                }
                Err(error) => return Some(Err(ParserErrorWithBytes { error, bytes: None })),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::iters::write_mrt_core_dump_to_path;
    use bytes::{BufMut, BytesMut};
    use std::io::Cursor;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn route_projection(elem: BgpElem) -> BgpRouteElemOwned {
        BgpRouteElemOwned {
            timestamp: elem.timestamp,
            elem_type: elem.elem_type,
            peer_ip: elem.peer_ip,
            peer_asn: elem.peer_asn,
            prefix: elem.prefix,
            as_path: elem.as_path.map(Arc::new),
        }
    }

    fn collect_route_record_iter(
        mut iter: RouteRecordIter,
    ) -> Result<Vec<BgpRouteElemOwned>, ParserError> {
        let mut routes = Vec::new();
        let filters: Arc<[Filter]> = Arc::from([]);
        while let Some(batch) = iter.next_batch(Arc::clone(&filters))? {
            for route in batch.all_routes() {
                routes.push(route?.into_owned());
            }
        }
        Ok(routes)
    }

    fn collect_route_batches<R: Read>(parser: BgpkitParser<R>) -> Vec<BgpRouteElemOwned> {
        parser
            .into_route_iter()
            .flat_map(|batch| {
                batch
                    .routes()
                    .map(|route| route.map(BgpRouteElem::into_owned))
                    .collect::<Vec<_>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn route_peer_table_from_peer_index(peer_table: PeerIndexTable) -> RoutePeerTable {
        let mut peer_ids = peer_table.id_peer_map.keys().copied().collect::<Vec<_>>();
        peer_ids.sort_unstable();
        let peers = peer_ids
            .into_iter()
            .map(|peer_id| peer_table.id_peer_map[&peer_id])
            .collect::<Vec<_>>();

        RoutePeerTable {
            peers: Arc::from(peers),
        }
    }

    fn update_record() -> MrtRecord {
        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        attributes.add_attr(
            AttributeValue::AsPath {
                path: AsPath::from_sequence([64500, 64501]),
                is_as4: false,
            }
            .into(),
        );
        attributes
            .add_attr(AttributeValue::NextHop(IpAddr::from_str("192.0.2.254").unwrap()).into());

        MrtRecord {
            common_header: CommonHeader {
                timestamp: 1_700_000_000,
                microsecond_timestamp: None,
                entry_type: EntryType::BGP4MP,
                entry_subtype: Bgp4MpType::MessageAs4 as u16,
                length: 0,
            },
            message: MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(Bgp4MpMessage {
                msg_type: Bgp4MpType::MessageAs4,
                peer_asn: Asn::new_32bit(64496),
                local_asn: Asn::new_32bit(64497),
                interface_index: 0,
                peer_ip: IpAddr::from_str("192.0.2.1").unwrap(),
                local_ip: IpAddr::from_str("192.0.2.2").unwrap(),
                bgp_message: BgpMessage::Update(BgpUpdateMessage {
                    withdrawn_prefixes: vec![NetworkPrefix::from_str("198.51.100.0/24").unwrap()],
                    attributes,
                    announced_prefixes: vec![NetworkPrefix::from_str("203.0.113.0/24").unwrap()],
                }),
            })),
        }
    }

    fn route_attributes(as_path: impl AsRef<[u32]>) -> Attributes {
        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        attributes.add_attr(
            AttributeValue::AsPath {
                path: AsPath::from_sequence(as_path),
                is_as4: false,
            }
            .into(),
        );
        attributes
            .add_attr(AttributeValue::NextHop(IpAddr::from_str("192.0.2.254").unwrap()).into());
        attributes
    }

    fn bgp4mp_record(msg_type: Bgp4MpType, bgp_message: BgpMessage) -> MrtRecord {
        let asn = if matches!(
            msg_type,
            Bgp4MpType::Message
                | Bgp4MpType::MessageLocal
                | Bgp4MpType::MessageAddpath
                | Bgp4MpType::MessageLocalAddpath
        ) {
            Asn::new_16bit(64496)
        } else {
            Asn::new_32bit(64496)
        };

        MrtRecord {
            common_header: CommonHeader {
                timestamp: 1_700_000_000,
                microsecond_timestamp: None,
                entry_type: EntryType::BGP4MP,
                entry_subtype: msg_type as u16,
                length: 0,
            },
            message: MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(Bgp4MpMessage {
                msg_type,
                peer_asn: asn,
                local_asn: Asn::new_32bit(64497),
                interface_index: 0,
                peer_ip: IpAddr::from_str("192.0.2.1").unwrap(),
                local_ip: IpAddr::from_str("192.0.2.2").unwrap(),
                bgp_message,
            })),
        }
    }

    fn open_message() -> BgpMessage {
        BgpMessage::Open(BgpOpenMessage {
            version: 4,
            asn: Asn::new_16bit(64496),
            hold_time: 180,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![],
        })
    }

    fn raw_bgp_message(length: u16, msg_type: BgpMessageType, payload: &[u8]) -> Bytes {
        raw_bgp_message_with_marker([0xff; 16], length, msg_type, payload)
    }

    fn raw_bgp_message_with_marker(
        marker: [u8; 16],
        length: u16,
        msg_type: BgpMessageType,
        payload: &[u8],
    ) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&marker);
        bytes.put_u16(length);
        bytes.put_u8(msg_type as u8);
        bytes.put_slice(payload);
        bytes.freeze()
    }

    fn table_dump_record() -> MrtRecord {
        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        attributes.add_attr(
            AttributeValue::AsPath {
                path: AsPath::from_sequence([64500, 64501]),
                is_as4: false,
            }
            .into(),
        );
        attributes
            .add_attr(AttributeValue::NextHop(IpAddr::from_str("192.0.2.254").unwrap()).into());

        MrtRecord {
            common_header: CommonHeader {
                timestamp: 1_700_000_000,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP,
                entry_subtype: 1,
                length: 0,
            },
            message: MrtMessage::TableDumpMessage(TableDumpMessage {
                view_number: 0,
                sequence_number: 1,
                prefix: NetworkPrefix::from_str("203.0.113.0/24").unwrap(),
                status: 1,
                originated_time: 1_699_999_998,
                peer_ip: IpAddr::from_str("192.0.2.20").unwrap(),
                peer_asn: Asn::new_16bit(64496),
                attributes,
            }),
        }
    }

    fn table_dump_ipv6_record() -> MrtRecord {
        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        attributes.add_attr(
            AttributeValue::AsPath {
                path: AsPath::from_sequence([64500, 64501]),
                is_as4: false,
            }
            .into(),
        );

        MrtRecord {
            common_header: CommonHeader {
                timestamp: 1_700_000_000,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP,
                entry_subtype: 2,
                length: 0,
            },
            message: MrtMessage::TableDumpMessage(TableDumpMessage {
                view_number: 0,
                sequence_number: 1,
                prefix: NetworkPrefix::from_str("2001:db8::/32").unwrap(),
                status: 1,
                originated_time: 1_699_999_998,
                peer_ip: IpAddr::from_str("2001:db8::20").unwrap(),
                peer_asn: Asn::new_16bit(64496),
                attributes,
            }),
        }
    }

    fn table_dump_v2_records_bytes() -> Vec<u8> {
        let peer = Peer::new(
            "192.0.2.10".parse().unwrap(),
            "192.0.2.11".parse().unwrap(),
            Asn::new_32bit(64496),
        );
        let mut peer_table = PeerIndexTable::default();
        let peer_index = peer_table.add_peer(peer);

        let mut attributes = Attributes::default();
        attributes.add_attr(AttributeValue::Origin(Origin::IGP).into());
        attributes.add_attr(
            AttributeValue::AsPath {
                path: AsPath::from_sequence([64500, 64501]),
                is_as4: false,
            }
            .into(),
        );
        attributes
            .add_attr(AttributeValue::NextHop(IpAddr::from_str("192.0.2.254").unwrap()).into());

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
                prefix: NetworkPrefix::from_str("203.0.113.0/24").unwrap(),
                rib_entries: vec![RibEntry {
                    peer_index,
                    originated_time: 1_699_999_999,
                    path_id: None,
                    attributes,
                }],
            })),
        };

        let mut bytes = pit_record.encode().to_vec();
        bytes.extend_from_slice(&rib_record.encode());
        bytes
    }

    fn table_dump_v2_truncated_attribute_payload() -> (Vec<u8>, Bytes, PeerIndexTable) {
        let peer = Peer::new(
            "192.0.2.10".parse().unwrap(),
            "192.0.2.11".parse().unwrap(),
            Asn::new_32bit(64496),
        );
        let mut peer_table = PeerIndexTable::default();
        let peer_index = peer_table.add_peer(peer);

        let pit_record = MrtRecord {
            common_header: CommonHeader {
                timestamp: 1_700_000_000,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP_V2,
                entry_subtype: TableDumpV2Type::PeerIndexTable as u16,
                length: 0,
            },
            message: MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(
                peer_table.clone(),
            )),
        };

        let first_entry = RibEntry {
            peer_index,
            originated_time: 1_699_999_999,
            path_id: None,
            attributes: route_attributes([64500, 64501]),
        };

        let mut rib_body = BytesMut::new();
        rib_body.put_u32(1);
        rib_body.extend(NetworkPrefix::from_str("203.0.113.0/24").unwrap().encode());
        rib_body.put_u16(2);
        rib_body.extend(first_entry.encode());
        rib_body.put_u16(peer_index);
        rib_body.put_u32(1_699_999_998);
        rib_body.put_u16(32);
        rib_body.put_u8(0);

        let rib_body = rib_body.freeze();
        let rib_header = CommonHeader {
            timestamp: 1_700_000_001,
            microsecond_timestamp: None,
            entry_type: EntryType::TABLE_DUMP_V2,
            entry_subtype: TableDumpV2Type::RibIpv4Unicast as u16,
            length: rib_body.len() as u32,
        };

        let mut bytes = pit_record.encode().to_vec();
        bytes.extend_from_slice(&rib_header.encode());
        bytes.extend_from_slice(&rib_body);

        (bytes, rib_body, peer_table)
    }

    fn assert_filtered_route_projection(bytes: Vec<u8>, filters: &[(&str, &str)]) {
        let elem_parser = filters.iter().fold(
            BgpkitParser::from_reader(Cursor::new(bytes.clone())),
            |parser, (filter_type, filter_value)| {
                parser.add_filter(filter_type, filter_value).unwrap()
            },
        );
        let route_parser = filters.iter().fold(
            BgpkitParser::from_reader(Cursor::new(bytes)),
            |parser, (filter_type, filter_value)| {
                parser.add_filter(filter_type, filter_value).unwrap()
            },
        );

        let elem_projection = elem_parser
            .into_elem_iter()
            .map(route_projection)
            .collect::<Vec<_>>();
        let routes = collect_route_batches(route_parser);

        assert_eq!(routes, elem_projection, "filters: {filters:?}");
    }

    fn assert_route_projection(bytes: Vec<u8>) -> Vec<BgpRouteElemOwned> {
        let elem_projection = BgpkitParser::from_reader(Cursor::new(bytes.clone()))
            .into_elem_iter()
            .map(route_projection)
            .collect::<Vec<_>>();
        let routes = collect_route_batches(BgpkitParser::from_reader(Cursor::new(bytes)));

        assert_eq!(routes, elem_projection);
        routes
    }

    #[test]
    fn route_iterator_matches_elem_projection_for_update() {
        let bytes = update_record().encode().to_vec();
        let routes = assert_route_projection(bytes);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].elem_type, ElemType::ANNOUNCE);
        assert_eq!(routes[1].elem_type, ElemType::WITHDRAW);
        assert!(routes[1].as_path.is_none());
    }

    #[test]
    fn route_iterator_does_not_treat_default_route_as_add_path() {
        let mut update = BytesMut::new();
        update.put_u16(0);
        update.put_u16(0);
        update.put_u8(0);
        update.put_u8(32);
        update.extend_from_slice(&[1, 2, 3, 4]);

        let batch = parse_bgp_update_routes(
            update.freeze(),
            false,
            &AsnLength::Bits32,
            1_700_000_000.0,
            "192.0.2.1".parse().unwrap(),
            Asn::new_32bit(64496),
            Arc::from([]),
        )
        .unwrap();
        let routes = batch
            .all_routes()
            .map(|route| route.map(BgpRouteElem::into_owned))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(routes.len(), 2);
        assert_eq!(
            routes[0].prefix,
            NetworkPrefix::from_str("0.0.0.0/0").unwrap()
        );
        assert_eq!(
            routes[1].prefix,
            NetworkPrefix::from_str("1.2.3.4/32").unwrap()
        );
        assert!(routes.iter().all(|route| route.prefix.path_id.is_none()));
    }

    #[test]
    fn route_iterator_emits_mpls_labeled_mp_unreach_withdrawals() {
        let mut mp_unreach = BytesMut::new();
        mp_unreach.put_u16(Afi::Ipv4 as u16);
        mp_unreach.put_u8(Safi::MplsLabel as u8);
        mp_unreach.put_u8(48);
        mp_unreach.extend_from_slice(&[0, 0, 0]);
        mp_unreach.extend_from_slice(&[203, 0, 113]);

        let mut attr = BytesMut::new();
        attr.put_u8(AttrFlags::OPTIONAL.bits());
        attr.put_u8(u8::from(AttrType::MP_UNREACHABLE_NLRI));
        attr.put_u8(mp_unreach.len() as u8);
        attr.extend_from_slice(&mp_unreach);

        let mut update = BytesMut::new();
        update.put_u16(0);
        update.put_u16(attr.len() as u16);
        update.extend_from_slice(&attr);

        let batch = parse_bgp_update_routes(
            update.freeze(),
            false,
            &AsnLength::Bits32,
            1_700_000_000.0,
            "192.0.2.1".parse().unwrap(),
            Asn::new_32bit(64496),
            Arc::from([]),
        )
        .unwrap();
        let routes = batch
            .all_routes()
            .map(|route| route.map(BgpRouteElem::into_owned))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].elem_type, ElemType::WITHDRAW);
        assert_eq!(
            routes[0].prefix,
            NetworkPrefix::from_str("203.0.113.0/24").unwrap()
        );
        assert!(routes[0].as_path.is_none());
    }

    #[test]
    fn route_iterator_shares_as_path_for_update_announcements() {
        let bytes = bgp4mp_record(
            Bgp4MpType::MessageAs4,
            BgpMessage::Update(BgpUpdateMessage {
                withdrawn_prefixes: vec![],
                attributes: route_attributes([64500, 64501]),
                announced_prefixes: vec![
                    NetworkPrefix::from_str("203.0.113.0/24").unwrap(),
                    NetworkPrefix::from_str("198.51.100.0/24").unwrap(),
                ],
            }),
        )
        .encode()
        .to_vec();

        let batch = BgpkitParser::from_reader(Cursor::new(bytes))
            .into_route_iter()
            .next()
            .unwrap();
        let routes = batch.all_routes().collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(routes.len(), 2);
        assert!(std::ptr::eq(
            routes[0].as_path.unwrap(),
            routes[1].as_path.unwrap()
        ));
    }

    #[test]
    fn route_iterator_uses_microsecond_timestamps() {
        let timestamp = record_timestamp(&CommonHeader {
            timestamp: 1_700_000_000,
            microsecond_timestamp: Some(123_456),
            entry_type: EntryType::BGP4MP_ET,
            entry_subtype: Bgp4MpType::MessageAs4 as u16,
            length: 0,
        });

        assert_eq!(timestamp, 1_700_000_000.123_456);
    }

    #[test]
    fn route_iterator_matches_elem_projection_for_mp_update() {
        let mut attributes = route_attributes([64500, 64501]);
        attributes.add_attr(
            AttributeValue::MpReachNlri(Nlri::new_reachable(
                NetworkPrefix::from_str("2001:db8::/32").unwrap(),
                Some(IpAddr::from_str("2001:db8::1").unwrap()),
            ))
            .into(),
        );
        attributes.add_attr(
            AttributeValue::MpUnreachNlri(Nlri::new_unreachable(
                NetworkPrefix::from_str("2001:db8:1::/48").unwrap(),
            ))
            .into(),
        );

        let bytes = bgp4mp_record(
            Bgp4MpType::MessageAs4,
            BgpMessage::Update(BgpUpdateMessage {
                withdrawn_prefixes: vec![],
                attributes,
                announced_prefixes: vec![],
            }),
        )
        .encode()
        .to_vec();

        let routes = assert_route_projection(bytes);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].elem_type, ElemType::ANNOUNCE);
        assert_eq!(
            routes[0].prefix,
            NetworkPrefix::from_str("2001:db8::/32").unwrap()
        );
        assert_eq!(routes[1].elem_type, ElemType::WITHDRAW);
        assert_eq!(
            routes[1].prefix,
            NetworkPrefix::from_str("2001:db8:1::/48").unwrap()
        );
    }

    #[test]
    fn route_iterator_matches_elem_projection_for_non_update_bgp4mp_messages() {
        let records = [
            bgp4mp_record(Bgp4MpType::Message, open_message()),
            bgp4mp_record(
                Bgp4MpType::MessageAs4,
                BgpMessage::Notification(BgpNotificationMessage {
                    error: BgpError::Unknown(1, 0),
                    data: vec![],
                }),
            ),
            bgp4mp_record(Bgp4MpType::MessageAddpath, BgpMessage::KeepAlive),
            bgp4mp_record(Bgp4MpType::MessageAs4Addpath, BgpMessage::KeepAlive),
        ];
        let mut bytes = Vec::new();
        for record in records {
            bytes.extend_from_slice(&record.encode());
        }

        assert!(assert_route_projection(bytes).is_empty());
    }

    #[test]
    fn route_iterator_matches_elem_projection_for_bgp4mp_16bit_update() {
        let bytes = bgp4mp_record(
            Bgp4MpType::Message,
            BgpMessage::Update(BgpUpdateMessage {
                withdrawn_prefixes: vec![],
                attributes: route_attributes([64500, 64501]),
                announced_prefixes: vec![NetworkPrefix::from_str("203.0.113.0/24").unwrap()],
            }),
        )
        .encode()
        .to_vec();

        let routes = assert_route_projection(bytes);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].peer_asn, Asn::new_16bit(64496));
    }

    #[test]
    fn route_iterator_filters_match_elem_projection_for_update() {
        let bytes = update_record().encode().to_vec();
        let cases: &[&[(&str, &str)]] = &[
            &[("peer_ip", "192.0.2.1")],
            &[("peer_ip", "192.0.2.99")],
            &[("peer_asn", "64496")],
            &[("type", "a")],
            &[("type", "w")],
            &[("type", "!w")],
            &[("prefix", "203.0.113.0/24")],
            &[("prefix", "198.51.100.0/24")],
            &[("prefix_super", "203.0.113.128/25")],
            &[("origin_asn", "64501")],
            &[("origin_asns", "64496,64501")],
            &[("as_path", "64500 64501$")],
            &[("ip_version", "4")],
            &[("ts_start", "1700000000"), ("ts_end", "1700000000")],
            &[("peer_ip", "192.0.2.1"), ("type", "a")],
        ];

        for filters in cases {
            assert_filtered_route_projection(bytes.clone(), filters);
        }
    }

    #[test]
    fn selective_attribute_parser_merges_as4_path() {
        let mut attributes = Attributes::default();
        attributes.add_attr(
            AttributeValue::AsPath {
                path: AsPath::from_sequence([23456, 64497]),
                is_as4: false,
            }
            .into(),
        );
        attributes.add_attr(
            AttributeValue::AsPath {
                path: AsPath::from_sequence([65536, 64497]),
                is_as4: true,
            }
            .into(),
        );

        let attrs = parse_route_attributes(
            attributes.encode(AsnLength::Bits16),
            &AsnLength::Bits16,
            false,
            RouteAttributeContext {
                afi: None,
                safi: None,
                prefixes: None,
                is_announcement: Some(true),
                has_standard_nlri: true,
            },
        )
        .unwrap();

        assert_eq!(
            attrs.as_path.unwrap().to_u32_vec_opt(false).unwrap(),
            vec![65536, 64497]
        );
    }

    #[test]
    fn selective_attribute_parser_handles_as_path_without_as4_path() {
        let attrs = parse_route_attributes(
            route_attributes([64500, 64501]).encode(AsnLength::Bits16),
            &AsnLength::Bits16,
            false,
            RouteAttributeContext {
                afi: None,
                safi: None,
                prefixes: None,
                is_announcement: Some(true),
                has_standard_nlri: true,
            },
        )
        .unwrap();

        assert_eq!(
            attrs.as_path.unwrap().to_u32_vec_opt(false).unwrap(),
            vec![64500, 64501]
        );
    }

    #[test]
    fn selective_attribute_parser_handles_as4_path_without_as_path() {
        let mut attributes = Attributes::default();
        attributes.add_attr(
            AttributeValue::AsPath {
                path: AsPath::from_sequence([65536, 64497]),
                is_as4: true,
            }
            .into(),
        );

        let attrs = parse_route_attributes(
            attributes.encode(AsnLength::Bits16),
            &AsnLength::Bits16,
            false,
            RouteAttributeContext {
                afi: None,
                safi: None,
                prefixes: None,
                is_announcement: Some(false),
                has_standard_nlri: false,
            },
        )
        .unwrap();

        assert_eq!(
            attrs.as_path.unwrap().to_u32_vec_opt(false).unwrap(),
            vec![65536, 64497]
        );
    }

    #[test]
    fn selective_attribute_parser_handles_no_as_path() {
        let attrs = parse_route_attributes(
            Bytes::new(),
            &AsnLength::Bits16,
            false,
            RouteAttributeContext {
                afi: None,
                safi: None,
                prefixes: None,
                is_announcement: Some(false),
                has_standard_nlri: false,
            },
        )
        .unwrap();

        assert!(attrs.as_path.is_none());
    }

    #[test]
    fn selective_attribute_parser_handles_extended_and_truncated_attributes() {
        let mut extended_as_path = BytesMut::new();
        extended_as_path.put_u8((AttrFlags::TRANSITIVE | AttrFlags::EXTENDED).bits());
        extended_as_path.put_u8(u8::from(AttrType::AS_PATH));
        extended_as_path.put_u16(4);
        extended_as_path.put_u8(2);
        extended_as_path.put_u8(1);
        extended_as_path.put_u16(64500);

        let attrs = parse_route_attributes(
            extended_as_path.freeze(),
            &AsnLength::Bits16,
            false,
            RouteAttributeContext {
                afi: None,
                safi: None,
                prefixes: None,
                is_announcement: Some(false),
                has_standard_nlri: false,
            },
        )
        .unwrap();
        assert_eq!(
            attrs.as_path.unwrap().to_u32_vec_opt(false).unwrap(),
            vec![64500]
        );

        let attrs = parse_route_attributes(
            Bytes::from_static(&[0x40, 2, 5, 0]),
            &AsnLength::Bits16,
            false,
            RouteAttributeContext {
                afi: None,
                safi: None,
                prefixes: None,
                is_announcement: Some(false),
                has_standard_nlri: false,
            },
        )
        .unwrap();
        assert!(attrs.as_path.is_none());
    }

    #[test]
    fn selective_attribute_parser_discards_malformed_as_path() {
        let attrs = parse_route_attributes(
            Bytes::from_static(&[0x40, 2, 1, 0]),
            &AsnLength::Bits16,
            false,
            RouteAttributeContext {
                afi: None,
                safi: None,
                prefixes: None,
                is_announcement: Some(false),
                has_standard_nlri: false,
            },
        )
        .unwrap();

        assert!(attrs.as_path.is_none());
    }

    #[test]
    fn route_iterator_matches_elem_projection_for_table_dump() {
        let bytes = table_dump_record().encode().to_vec();
        let routes = assert_route_projection(bytes);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].timestamp, 1_699_999_998.0);
        assert_eq!(routes[0].peer_asn, Asn::new_16bit(64496));
    }

    #[test]
    fn route_iterator_matches_elem_projection_for_table_dump_ipv6() {
        let bytes = table_dump_ipv6_record().encode().to_vec();
        let routes = assert_route_projection(bytes);
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].prefix,
            NetworkPrefix::from_str("2001:db8::/32").unwrap()
        );
        assert_eq!(
            routes[0].peer_ip,
            IpAddr::from(Ipv6Addr::from_str("2001:db8::20").unwrap())
        );
    }

    #[test]
    fn route_iterator_matches_elem_projection_for_table_dump_v2() {
        let bytes = table_dump_v2_records_bytes();
        let routes = assert_route_projection(bytes);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].elem_type, ElemType::ANNOUNCE);
        assert_eq!(
            routes[0].as_path.as_ref().unwrap().to_u32_vec_opt(false),
            Some(vec![64500, 64501])
        );
    }

    #[test]
    fn route_iterator_matches_elem_projection_for_table_dump_v2_ipv6_addpath() {
        let peer = Peer::new(
            "192.0.2.11".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
            Asn::new_32bit(64496),
        );
        let mut peer_table = PeerIndexTable::default();
        let peer_index = peer_table.add_peer(peer);

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
        let rib_record = MrtRecord {
            common_header: CommonHeader {
                timestamp: 1_700_000_001,
                microsecond_timestamp: None,
                entry_type: EntryType::TABLE_DUMP_V2,
                entry_subtype: TableDumpV2Type::RibIpv6UnicastAddPath as u16,
                length: 0,
            },
            message: MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(RibAfiEntries {
                rib_type: TableDumpV2Type::RibIpv6UnicastAddPath,
                sequence_number: 1,
                prefix: NetworkPrefix::from_str("2001:db8::/32").unwrap(),
                rib_entries: vec![RibEntry {
                    peer_index,
                    originated_time: 1_699_999_999,
                    path_id: Some(1234),
                    attributes: route_attributes([64500, 64501]),
                }],
            })),
        };

        let mut bytes = pit_record.encode().to_vec();
        bytes.extend_from_slice(&rib_record.encode());
        let routes = assert_route_projection(bytes);
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].prefix,
            NetworkPrefix::from_str("2001:db8::/32").unwrap()
        );
    }

    #[test]
    fn route_iterator_matches_elem_projection_for_bgp4mp_ipv6_peer_update() {
        let record = MrtRecord {
            common_header: CommonHeader {
                timestamp: 1_700_000_000,
                microsecond_timestamp: None,
                entry_type: EntryType::BGP4MP,
                entry_subtype: Bgp4MpType::MessageAs4 as u16,
                length: 0,
            },
            message: MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(Bgp4MpMessage {
                msg_type: Bgp4MpType::MessageAs4,
                peer_asn: Asn::new_32bit(64496),
                local_asn: Asn::new_32bit(64497),
                interface_index: 0,
                peer_ip: IpAddr::from_str("2001:db8::1").unwrap(),
                local_ip: IpAddr::from_str("2001:db8::2").unwrap(),
                bgp_message: BgpMessage::Update(BgpUpdateMessage {
                    withdrawn_prefixes: vec![],
                    attributes: route_attributes([64500, 64501]),
                    announced_prefixes: vec![NetworkPrefix::from_str("203.0.113.0/24").unwrap()],
                }),
            })),
        };

        let routes = assert_route_projection(record.encode().to_vec());
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].peer_ip,
            IpAddr::from(Ipv6Addr::from_str("2001:db8::1").unwrap())
        );
    }

    #[test]
    fn route_iterator_filters_match_elem_projection_for_table_dump_v2() {
        let bytes = table_dump_v2_records_bytes();
        let cases: &[&[(&str, &str)]] = &[
            &[("peer_ip", "192.0.2.10")],
            &[("peer_asn", "64496")],
            &[("type", "a")],
            &[("type", "w")],
            &[("prefix", "203.0.113.0/24")],
            &[("prefix_sub", "203.0.112.0/23")],
            &[("origin_asn", "64501")],
            &[("as_path", "64500 64501$")],
            &[("ts_start", "1699999999"), ("ts_end", "1699999999")],
            &[("peer_asn", "64496"), ("origin_asn", "64501")],
        ];

        for filters in cases {
            assert_filtered_route_projection(bytes.clone(), filters);
        }
    }

    #[test]
    fn route_parser_reports_bgp_message_shape_errors() {
        assert!(parse_bgp_message_routes(
            raw_bgp_message(18, BgpMessageType::KEEPALIVE, &[]),
            false,
            &AsnLength::Bits16,
            1_700_000_000.0,
            "192.0.2.1".parse().unwrap(),
            Asn::new_16bit(64496),
            Arc::from([]),
        )
        .is_err());
        assert!(parse_bgp_message_routes(
            raw_bgp_message(4097, BgpMessageType::OPEN, &[]),
            false,
            &AsnLength::Bits16,
            1_700_000_000.0,
            "192.0.2.1".parse().unwrap(),
            Asn::new_16bit(64496),
            Arc::from([]),
        )
        .is_err());

        let routes = collect_route_record_iter(
            parse_bgp_message_routes(
                raw_bgp_message(30, BgpMessageType::KEEPALIVE, &[]),
                false,
                &AsnLength::Bits16,
                1_700_000_000.0,
                "192.0.2.1".parse().unwrap(),
                Asn::new_16bit(64496),
                Arc::from([]),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(routes.is_empty());

        let routes = collect_route_record_iter(
            parse_bgp_message_routes(
                raw_bgp_message(19, BgpMessageType::KEEPALIVE, &[0]),
                false,
                &AsnLength::Bits16,
                1_700_000_000.0,
                "192.0.2.1".parse().unwrap(),
                Asn::new_16bit(64496),
                Arc::from([]),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(routes.is_empty());

        let routes = collect_route_record_iter(
            parse_bgp_message_routes(
                raw_bgp_message_with_marker([0x00; 16], 19, BgpMessageType::KEEPALIVE, &[]),
                false,
                &AsnLength::Bits16,
                1_700_000_000.0,
                "192.0.2.1".parse().unwrap(),
                Asn::new_16bit(64496),
                Arc::from([]),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(routes.is_empty());
    }

    #[test]
    fn route_core_dump_write_respects_enabled_flag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mrt_core_dump");

        write_mrt_core_dump_to_path(false, Some(vec![1, 2, 3]), &path);
        assert!(!path.exists());

        write_mrt_core_dump_to_path(true, Some(vec![1, 2, 3]), &path);
        assert_eq!(std::fs::read(&path).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn route_parser_handles_table_dump_v2_error_edges() {
        let rib = RibAfiEntries {
            rib_type: TableDumpV2Type::RibIpv4Unicast,
            sequence_number: 1,
            prefix: NetworkPrefix::from_str("203.0.113.0/24").unwrap(),
            rib_entries: vec![RibEntry {
                peer_index: 99,
                originated_time: 1_699_999_999,
                path_id: None,
                attributes: route_attributes([64500, 64501]),
            }],
        };
        let mut no_peer_table = None;
        assert!(parse_table_dump_v2_routes(
            TableDumpV2Type::RibIpv4Unicast as u16,
            rib.encode(),
            &mut no_peer_table,
            Arc::from([]),
        )
        .is_err());

        let mut empty_peer_table = Some(RoutePeerTable::default());
        let routes = collect_route_record_iter(
            parse_table_dump_v2_routes(
                TableDumpV2Type::RibIpv4Unicast as u16,
                rib.encode(),
                &mut empty_peer_table,
                Arc::from([]),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(routes.is_empty());

        let mut truncated = BytesMut::new();
        truncated.put_u32(1);
        truncated.extend(NetworkPrefix::from_str("203.0.113.0/24").unwrap().encode());
        truncated.put_u16(1);
        let mut empty_peer_table = Some(RoutePeerTable::default());
        let routes = collect_route_record_iter(
            parse_table_dump_v2_routes(
                TableDumpV2Type::RibIpv4Unicast as u16,
                truncated.freeze(),
                &mut empty_peer_table,
                Arc::from([]),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(routes.is_empty());

        let peer = Peer::new(
            "192.0.2.10".parse().unwrap(),
            "192.0.2.11".parse().unwrap(),
            Asn::new_32bit(64496),
        );
        let mut peer_table = PeerIndexTable::default();
        let peer_index = peer_table.add_peer(peer);

        let first_entry = RibEntry {
            peer_index,
            originated_time: 1_699_999_999,
            path_id: Some(1234),
            attributes: route_attributes([64500, 64501]),
        };
        let mut add_path_truncated = BytesMut::new();
        add_path_truncated.put_u32(1);
        add_path_truncated.extend(NetworkPrefix::from_str("203.0.113.0/24").unwrap().encode());
        add_path_truncated.put_u16(2);
        add_path_truncated.extend(first_entry.encode());
        add_path_truncated.put_u16(peer_index);
        add_path_truncated.put_u32(1_699_999_998);
        add_path_truncated.put_u32(5678);

        let mut peer_table = Some(route_peer_table_from_peer_index(peer_table));
        let routes = collect_route_record_iter(
            parse_table_dump_v2_routes(
                TableDumpV2Type::RibIpv4UnicastAddPath as u16,
                add_path_truncated.freeze(),
                &mut peer_table,
                Arc::from([]),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].prefix,
            NetworkPrefix::from_str("203.0.113.0/24").unwrap()
        );
    }

    #[test]
    fn route_parser_preserves_table_dump_v2_routes_before_truncated_attribute_payload() {
        let (_bytes, rib_body, peer_table) = table_dump_v2_truncated_attribute_payload();
        let mut peer_table = Some(route_peer_table_from_peer_index(peer_table));

        let routes = collect_route_record_iter(
            parse_table_dump_v2_routes(
                TableDumpV2Type::RibIpv4Unicast as u16,
                rib_body,
                &mut peer_table,
                Arc::from([]),
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].prefix,
            NetworkPrefix::from_str("203.0.113.0/24").unwrap()
        );
        assert_eq!(
            routes[0].as_path.as_ref().unwrap().to_u32_vec_opt(false),
            Some(vec![64500, 64501])
        );
    }

    #[test]
    fn route_iterators_preserve_table_dump_v2_routes_before_truncated_attribute_payload() {
        let (bytes, _rib_body, _peer_table) = table_dump_v2_truncated_attribute_payload();

        let routes = collect_route_batches(BgpkitParser::from_reader(Cursor::new(bytes.clone())));
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].prefix,
            NetworkPrefix::from_str("203.0.113.0/24").unwrap()
        );

        let fallible_routes = BgpkitParser::from_reader(Cursor::new(bytes))
            .into_fallible_route_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .flat_map(|batch| {
                batch
                    .routes()
                    .map(|route| route.map(BgpRouteElem::into_owned))
                    .collect::<Vec<_>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(fallible_routes, routes);
    }

    fn table_dump_v2_rib_without_peer_table_record() -> MrtRecord {
        MrtRecord {
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
                prefix: NetworkPrefix::from_str("203.0.113.0/24").unwrap(),
                rib_entries: vec![RibEntry {
                    peer_index: 0,
                    originated_time: 1_699_999_999,
                    path_id: None,
                    attributes: route_attributes([64500, 64501]),
                }],
            })),
        }
    }

    #[test]
    fn route_iterator_skips_route_parse_errors() {
        let routes = collect_route_batches(BgpkitParser::from_reader(Cursor::new(
            table_dump_v2_rib_without_peer_table_record()
                .encode()
                .to_vec(),
        )));

        assert!(routes.is_empty());
    }

    #[test]
    fn fallible_route_iterator_applies_filters_to_cached_routes() {
        let routes = BgpkitParser::from_reader(Cursor::new(update_record().encode().to_vec()))
            .add_filter("type", "w")
            .unwrap()
            .into_fallible_route_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .flat_map(|batch| {
                batch
                    .routes()
                    .map(|route| route.map(BgpRouteElem::into_owned))
                    .collect::<Vec<_>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].elem_type, ElemType::WITHDRAW);
    }

    #[test]
    fn fallible_route_iterator_returns_route_parse_errors() {
        let mut iter = BgpkitParser::from_reader(Cursor::new(
            table_dump_v2_rib_without_peer_table_record()
                .encode()
                .to_vec(),
        ))
        .into_fallible_route_iter();

        assert!(iter.next().unwrap().is_err());
    }

    #[test]
    fn fallible_route_iterator_yields_routes() {
        let bytes = update_record().encode().to_vec();
        let routes = BgpkitParser::from_reader(Cursor::new(bytes))
            .into_fallible_route_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .flat_map(|batch| {
                batch
                    .routes()
                    .map(|route| route.map(BgpRouteElem::into_owned))
                    .collect::<Vec<_>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].elem_type, ElemType::ANNOUNCE);
        assert_eq!(routes[1].elem_type, ElemType::WITHDRAW);
    }

    #[test]
    fn fallible_route_iterator_returns_parse_errors() {
        let invalid_data = vec![
            0x00, 0x00, 0x00, 0x00, // timestamp
            0xFF, 0xFF, // invalid type
            0x00, 0x00, // subtype
            0x00, 0x00, 0x00, 0x04, // length
            0x00, 0x00, 0x00, 0x00, // dummy data
        ];

        let mut iter =
            BgpkitParser::from_reader(Cursor::new(invalid_data)).into_fallible_route_iter();

        assert!(iter.next().unwrap().is_err());
    }
}
