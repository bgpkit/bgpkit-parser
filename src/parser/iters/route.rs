use crate::error::{ParserError, ParserErrorWithBytes};
use crate::models::*;
use crate::parser::bgp::attributes::{parse_as_path, parse_nlri, AttributeValidationState};
use crate::parser::bgp::messages::read_and_validate_bgp_marker;
use crate::parser::mrt::messages::bgp4mp::bgp4mp_message_payload_len;
use crate::parser::mrt::messages::table_dump_v2::rib_entry_min_len;
use crate::parser::mrt::parse_table_dump_v2_message;
use crate::parser::{chunk_mrt_record, parse_nlri_list, BgpkitParser, Filterable, ReadUtils};
use bytes::{Buf, Bytes};
use ipnet::IpNet;
use log::{error, warn};
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

#[derive(Default)]
struct RouteAttributes {
    as_path: Option<AsPath>,
    announced: Vec<NetworkPrefix>,
    withdrawn: Vec<NetworkPrefix>,
}

struct RouteAttributeContext<'a> {
    afi: Option<Afi>,
    safi: Option<Safi>,
    prefixes: Option<&'a [NetworkPrefix]>,
    is_announcement: Option<bool>,
    has_standard_nlri: bool,
}

fn write_mrt_core_dump(enabled: bool, bytes: Option<Vec<u8>>) {
    write_mrt_core_dump_to_path(enabled, bytes, "mrt_core_dump");
}

fn write_mrt_core_dump_to_path<P: AsRef<Path>>(enabled: bool, bytes: Option<Vec<u8>>, path: P) {
    if enabled {
        if let Some(bytes) = bytes {
            std::fs::write(path, bytes).expect("Unable to write to mrt_core_dump");
        }
    }
}

fn merge_as_path(as_path: Option<AsPath>, as4_path: Option<AsPath>) -> Option<AsPath> {
    match (as_path, as4_path) {
        (None, None) => None,
        (Some(path), None) | (None, Some(path)) => Some(path),
        (Some(path), Some(as4_path)) => Some(AsPath::merge_aspath_as4path(&path, &as4_path)),
    }
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

        data.has_n_remaining(attr_length)?;
        let attr_data = data.split_to(attr_length);
        let result = match attr_type {
            AttrType::AS_PATH => parse_as_path(attr_data, asn_len).map(|path| {
                as_path = Some(path);
            }),
            AttrType::AS4_PATH => parse_as_path(attr_data, &AsnLength::Bits32).map(|path| {
                as4_path = Some(path);
            }),
            AttrType::MP_REACHABLE_NLRI => parse_nlri(
                attr_data,
                &ctx.afi,
                &ctx.safi,
                &ctx.prefixes,
                true,
                add_path,
            )
            .map(|attr| {
                if let AttributeValue::MpReachNlri(nlri) = attr {
                    announced = nlri.prefixes;
                }
            }),
            AttrType::MP_UNREACHABLE_NLRI => parse_nlri(
                attr_data,
                &ctx.afi,
                &ctx.safi,
                &ctx.prefixes,
                false,
                add_path,
            )
            .map(|attr| {
                if let AttributeValue::MpUnreachNlri(nlri) = attr {
                    withdrawn = nlri.prefixes;
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

fn append_update_routes(
    routes: &mut Vec<BgpRouteElem>,
    timestamp: f64,
    peer_ip: IpAddr,
    peer_asn: Asn,
    top_announced: Vec<NetworkPrefix>,
    top_withdrawn: Vec<NetworkPrefix>,
    attrs: RouteAttributes,
) {
    let as_path = attrs.as_path;
    routes.extend(
        top_announced
            .into_iter()
            .chain(attrs.announced)
            .map(|prefix| BgpRouteElem {
                timestamp,
                elem_type: ElemType::ANNOUNCE,
                peer_ip,
                peer_asn,
                prefix,
                as_path: as_path.clone(),
            }),
    );
    routes.extend(
        top_withdrawn
            .into_iter()
            .chain(attrs.withdrawn)
            .map(|prefix| BgpRouteElem {
                timestamp,
                elem_type: ElemType::WITHDRAW,
                peer_ip,
                peer_asn,
                prefix,
                as_path: None,
            }),
    );
}

fn parse_bgp_update_routes(
    mut input: Bytes,
    add_path: bool,
    asn_len: &AsnLength,
    timestamp: f64,
    peer_ip: IpAddr,
    peer_asn: Asn,
) -> Result<Vec<BgpRouteElem>, ParserError> {
    let withdrawn_len = input.read_u16()? as usize;
    input.has_n_remaining(withdrawn_len)?;
    let withdrawn_prefixes = parse_nlri_list(input.split_to(withdrawn_len), add_path, &Afi::Ipv4)?;

    let attribute_length = input.read_u16()? as usize;
    input.has_n_remaining(attribute_length)?;
    let attribute_bytes = input.split_to(attribute_length);
    let announced_prefixes = parse_nlri_list(input, add_path, &Afi::Ipv4)?;
    let attributes = parse_route_attributes(
        attribute_bytes,
        asn_len,
        add_path,
        RouteAttributeContext {
            afi: None,
            safi: None,
            prefixes: None,
            is_announcement: None,
            has_standard_nlri: !announced_prefixes.is_empty(),
        },
    )?;

    let mut routes = Vec::with_capacity(
        announced_prefixes.len()
            + withdrawn_prefixes.len()
            + attributes.announced.len()
            + attributes.withdrawn.len(),
    );
    append_update_routes(
        &mut routes,
        timestamp,
        peer_ip,
        peer_asn,
        announced_prefixes,
        withdrawn_prefixes,
        attributes,
    );
    Ok(routes)
}

fn parse_bgp_message_routes(
    mut data: Bytes,
    add_path: bool,
    asn_len: &AsnLength,
    timestamp: f64,
    peer_ip: IpAddr,
    peer_asn: Asn,
) -> Result<Vec<BgpRouteElem>, ParserError> {
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
        BgpMessageType::UPDATE => {
            parse_bgp_update_routes(msg_data, add_path, asn_len, timestamp, peer_ip, peer_asn)
        }
        BgpMessageType::OPEN | BgpMessageType::NOTIFICATION | BgpMessageType::KEEPALIVE => {
            Ok(Vec::new())
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
) -> Result<Vec<BgpRouteElem>, ParserError> {
    let msg_type = Bgp4MpType::try_from(sub_type)?;
    let Some((asn_len, add_path)) = bgp4mp_asn_len_and_add_path(msg_type) else {
        return Ok(Vec::new());
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

    parse_bgp_message_routes(data, add_path, &asn_len, timestamp, peer_ip, peer_asn)
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
) -> Result<Vec<BgpRouteElem>, ParserError> {
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

    Ok(vec![BgpRouteElem {
        timestamp: originated_time,
        elem_type: ElemType::ANNOUNCE,
        peer_ip,
        peer_asn,
        prefix: NetworkPrefix::new(prefix, None),
        as_path: attrs.as_path,
    }])
}

fn parse_table_dump_v2_routes(
    sub_type: u16,
    mut data: Bytes,
    peer_table: &mut Option<PeerIndexTable>,
) -> Result<Vec<BgpRouteElem>, ParserError> {
    let v2_type = TableDumpV2Type::try_from(sub_type)?;
    match v2_type {
        TableDumpV2Type::PeerIndexTable => {
            if let TableDumpV2Message::PeerIndexTable(table) =
                parse_table_dump_v2_message(sub_type, data)?
            {
                *peer_table = Some(table);
            }
            Ok(Vec::new())
        }
        TableDumpV2Type::GeoPeerTable => Ok(Vec::new()),
        TableDumpV2Type::RibGeneric | TableDumpV2Type::RibGenericAddPath => Err(
            ParserError::Unsupported("TableDumpV2 RibGeneric is not currently supported".into()),
        ),
        rib_type => {
            let (afi, safi) = table_dump_v2_afi_safi(rib_type)?;
            let is_add_path = is_add_path_rib_type(rib_type);
            let _sequence_number = data.read_u32()?;
            let prefix = data.read_nlri_prefix(&afi, false)?;
            let entry_count = data.read_u16()?;
            let mut routes = Vec::with_capacity(entry_count as usize);
            let Some(peer_table) = peer_table.as_ref() else {
                return Err(ParserError::ParseError(
                    "peer table not set for TableDumpV2 RIB entries".to_string(),
                ));
            };

            for _ in 0..entry_count {
                if data.remaining() < rib_entry_min_len(is_add_path) {
                    warn!("early break due to truncated msg while parsing RIB AFI entries");
                    break;
                }
                let peer_index = data.read_u16()?;
                let originated_time = data.read_u32()? as f64;
                let _path_id = if is_add_path {
                    Some(data.read_u32()?)
                } else {
                    None
                };
                let attribute_length = data.read_u16()? as usize;
                if data.remaining() < attribute_length {
                    // Preserve routes parsed from earlier entries in this RIB record.
                    // Once a variable-length attribute payload is truncated, the next
                    // entry boundary is not recoverable, so stop this record instead of
                    // treating the whole record as failed. This mirrors
                    // parse_rib_afi_entries() in the full TableDumpV2 parser.
                    //
                    // TODO: expose partial-success diagnostics through a structured
                    // warning channel or partial-result API. Current iterators can only
                    // return parsed routes or an error, not both for the same record.
                    warn!(
                        "early break due to truncated attribute payload while parsing RIB AFI entries: expected {} bytes, have {} bytes available",
                        attribute_length,
                        data.remaining()
                    );
                    break;
                }
                let attrs = parse_route_attributes(
                    data.split_to(attribute_length),
                    &AsnLength::Bits32,
                    is_add_path,
                    RouteAttributeContext {
                        afi: Some(afi),
                        safi: Some(safi),
                        prefixes: Some(&[prefix]),
                        is_announcement: Some(true),
                        has_standard_nlri: afi == Afi::Ipv4,
                    },
                )?;
                let Some(peer) = peer_table.get_peer_by_id(&peer_index) else {
                    error!("peer ID {} not found in peer_index table", peer_index);
                    continue;
                };
                routes.push(BgpRouteElem {
                    timestamp: originated_time,
                    elem_type: ElemType::ANNOUNCE,
                    peer_ip: peer.peer_ip,
                    peer_asn: peer.peer_asn,
                    prefix,
                    as_path: attrs.as_path,
                });
            }
            Ok(routes)
        }
    }
}

fn parse_raw_record_routes(
    raw_record: crate::RawMrtRecord,
    peer_table: &mut Option<PeerIndexTable>,
) -> Result<Vec<BgpRouteElem>, ParserError> {
    let timestamp = record_timestamp(&raw_record.common_header);
    match raw_record.common_header.entry_type {
        EntryType::TABLE_DUMP => parse_table_dump_routes(
            raw_record.common_header.entry_subtype,
            raw_record.message_bytes,
        ),
        EntryType::TABLE_DUMP_V2 => parse_table_dump_v2_routes(
            raw_record.common_header.entry_subtype,
            raw_record.message_bytes,
            peer_table,
        ),
        EntryType::BGP4MP | EntryType::BGP4MP_ET => parse_bgp4mp_routes(
            raw_record.common_header.entry_subtype,
            raw_record.message_bytes,
            timestamp,
        ),
        v => Err(ParserError::Unsupported(format!(
            "unsupported MRT type: {v:?}"
        ))),
    }
}

pub struct RouteIterator<R> {
    parser: BgpkitParser<R>,
    cache_routes: Vec<BgpRouteElem>,
    peer_table: Option<PeerIndexTable>,
}

impl<R> RouteIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        Self {
            parser,
            cache_routes: Vec::new(),
            peer_table: None,
        }
    }
}

impl<R: Read> Iterator for RouteIterator<R> {
    type Item = BgpRouteElem;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(route) = self.cache_routes.pop() {
                if route.match_filters(&self.parser.filters) {
                    return Some(route);
                }
                continue;
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

            match parse_raw_record_routes(raw_record, &mut self.peer_table) {
                Ok(mut routes) => {
                    if routes.is_empty() {
                        continue;
                    }
                    routes.reverse();
                    self.cache_routes = routes;
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
    cache_routes: Vec<BgpRouteElem>,
    peer_table: Option<PeerIndexTable>,
}

impl<R> FallibleRouteIterator<R> {
    pub(crate) fn new(parser: BgpkitParser<R>) -> Self {
        Self {
            parser,
            cache_routes: Vec::new(),
            peer_table: None,
        }
    }
}

impl<R: Read> Iterator for FallibleRouteIterator<R> {
    type Item = Result<BgpRouteElem, ParserErrorWithBytes>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(route) = self.cache_routes.pop() {
                if route.match_filters(&self.parser.filters) {
                    return Some(Ok(route));
                }
                continue;
            }

            let raw_record = match chunk_mrt_record(&mut self.parser.reader) {
                Ok(raw_record) => raw_record,
                Err(e) if matches!(e.error, ParserError::EofExpected) => return None,
                Err(e) => return Some(Err(e)),
            };

            match parse_raw_record_routes(raw_record, &mut self.peer_table) {
                Ok(mut routes) => {
                    if routes.is_empty() {
                        continue;
                    }
                    routes.reverse();
                    self.cache_routes = routes;
                }
                Err(error) => return Some(Err(ParserErrorWithBytes { error, bytes: None })),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};
    use std::io::Cursor;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn route_projection(elem: BgpElem) -> BgpRouteElem {
        BgpRouteElem {
            timestamp: elem.timestamp,
            elem_type: elem.elem_type,
            peer_ip: elem.peer_ip,
            peer_asn: elem.peer_asn,
            prefix: elem.prefix,
            as_path: elem.as_path,
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
        let routes = route_parser.into_route_iter().collect::<Vec<_>>();

        assert_eq!(routes, elem_projection, "filters: {filters:?}");
    }

    fn assert_route_projection(bytes: Vec<u8>) -> Vec<BgpRouteElem> {
        let elem_projection = BgpkitParser::from_reader(Cursor::new(bytes.clone()))
            .into_elem_iter()
            .map(route_projection)
            .collect::<Vec<_>>();
        let routes = BgpkitParser::from_reader(Cursor::new(bytes))
            .into_route_iter()
            .collect::<Vec<_>>();

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
            Asn::new_16bit(64496)
        )
        .is_err());
        assert!(parse_bgp_message_routes(
            raw_bgp_message(4097, BgpMessageType::OPEN, &[]),
            false,
            &AsnLength::Bits16,
            1_700_000_000.0,
            "192.0.2.1".parse().unwrap(),
            Asn::new_16bit(64496)
        )
        .is_err());

        let routes = parse_bgp_message_routes(
            raw_bgp_message(30, BgpMessageType::KEEPALIVE, &[]),
            false,
            &AsnLength::Bits16,
            1_700_000_000.0,
            "192.0.2.1".parse().unwrap(),
            Asn::new_16bit(64496),
        )
        .unwrap();
        assert!(routes.is_empty());

        let routes = parse_bgp_message_routes(
            raw_bgp_message(19, BgpMessageType::KEEPALIVE, &[0]),
            false,
            &AsnLength::Bits16,
            1_700_000_000.0,
            "192.0.2.1".parse().unwrap(),
            Asn::new_16bit(64496),
        )
        .unwrap();
        assert!(routes.is_empty());

        let routes = parse_bgp_message_routes(
            raw_bgp_message_with_marker([0x00; 16], 19, BgpMessageType::KEEPALIVE, &[]),
            false,
            &AsnLength::Bits16,
            1_700_000_000.0,
            "192.0.2.1".parse().unwrap(),
            Asn::new_16bit(64496),
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
        )
        .is_err());

        let mut empty_peer_table = Some(PeerIndexTable::default());
        let routes = parse_table_dump_v2_routes(
            TableDumpV2Type::RibIpv4Unicast as u16,
            rib.encode(),
            &mut empty_peer_table,
        )
        .unwrap();
        assert!(routes.is_empty());

        let mut truncated = BytesMut::new();
        truncated.put_u32(1);
        truncated.extend(NetworkPrefix::from_str("203.0.113.0/24").unwrap().encode());
        truncated.put_u16(1);
        let mut empty_peer_table = Some(PeerIndexTable::default());
        let routes = parse_table_dump_v2_routes(
            TableDumpV2Type::RibIpv4Unicast as u16,
            truncated.freeze(),
            &mut empty_peer_table,
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

        let mut peer_table = Some(peer_table);
        let routes = parse_table_dump_v2_routes(
            TableDumpV2Type::RibIpv4UnicastAddPath as u16,
            add_path_truncated.freeze(),
            &mut peer_table,
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
        let mut peer_table = Some(peer_table);

        let routes = parse_table_dump_v2_routes(
            TableDumpV2Type::RibIpv4Unicast as u16,
            rib_body,
            &mut peer_table,
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

        let routes = BgpkitParser::from_reader(Cursor::new(bytes.clone()))
            .into_route_iter()
            .collect::<Vec<_>>();
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].prefix,
            NetworkPrefix::from_str("203.0.113.0/24").unwrap()
        );

        let fallible_routes = BgpkitParser::from_reader(Cursor::new(bytes))
            .into_fallible_route_iter()
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
        let routes = BgpkitParser::from_reader(Cursor::new(
            table_dump_v2_rib_without_peer_table_record()
                .encode()
                .to_vec(),
        ))
        .into_route_iter()
        .collect::<Vec<_>>();

        assert!(routes.is_empty());
    }

    #[test]
    fn fallible_route_iterator_applies_filters_to_cached_routes() {
        let routes = BgpkitParser::from_reader(Cursor::new(update_record().encode().to_vec()))
            .add_filter("type", "w")
            .unwrap()
            .into_fallible_route_iter()
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
