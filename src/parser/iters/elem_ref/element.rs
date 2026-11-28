//! One borrowed element inside a [`RecordElems`](super::RecordElems) batch.
//!
//! Every accessor reads the record's own bytes; the type itself owns nothing.

use super::*;

/// Borrowed view over a single BGP element inside a [`RecordElems`] batch.
///
/// Attributes are decoded lazily from `attr_bytes` when their accessors are called, without heap
/// allocation.
#[derive(Clone)]
pub struct ElemRef<'a> {
    attr_bytes: &'a [u8],
    peer_ip: IpAddr,
    peer_asn: Asn,
    peer_bgp_id: Option<BgpIdentifier>,
    as_path_slot: Cell<u64>,
    timestamp: f64,
    prefix: IpNet,
    /// The ADD-PATH identifier the announcement carried, if any. A dump's entry has none.
    path_id: Option<u32>,
    flags: u8,
    elem_type: ElemType,
    warned_truncation: Cell<bool>,
}

impl std::fmt::Debug for ElemRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The derived form printed the raw attribute bytes and the lazily filled cache slot, which
        // changed between two calls on the same element.
        f.debug_struct("ElemRef")
            .field("elem_type", &self.elem_type)
            .field("timestamp", &self.timestamp)
            .field("peer_ip", &self.peer_ip)
            .field("peer_asn", &self.peer_asn)
            .field("prefix", &self.prefix())
            .finish_non_exhaustive()
    }
}

// Structural invariant: none of the borrowed view types own heap allocations or require Drop.
const _: () = assert!(!std::mem::needs_drop::<ElemRef<'static>>());
const _: () = assert!(!std::mem::needs_drop::<AsPathView<'static>>());
const _: () = assert!(!std::mem::needs_drop::<AsnsView<'static>>());
const _: () = assert!(!std::mem::needs_drop::<CommunitiesView<'static>>());
// A borrowed element carries its peer inline so one type serves both dumps and updates.
const _: () = assert!(std::mem::size_of::<ElemRef<'static>>() <= 104);

impl<'a> ElemRef<'a> {
    #[inline]
    pub(super) fn new(
        prefix: IpNet,
        peer: &'a Peer,
        originated_time: u32,
        flags: u8,
        attr_bytes: &'a [u8],
    ) -> Self {
        Self {
            attr_bytes,
            peer_ip: peer.peer_ip,
            peer_asn: peer.peer_asn,
            peer_bgp_id: Some(peer.peer_bgp_id),
            as_path_slot: Cell::new(SLOT_UNSCANNED),
            timestamp: originated_time as f64,
            prefix,
            path_id: None,
            flags,
            elem_type: ElemType::ANNOUNCE,
            warned_truncation: Cell::new(false),
        }
    }

    /// An element of a `BGP4MP` update: the peer and the time come from the record header.
    #[inline]
    pub(super) fn new_update(
        entry: &UpdateEntry,
        peer_ip: IpAddr,
        peer_asn: Asn,
        timestamp: f64,
        attr_bytes: &'a [u8],
    ) -> Self {
        Self {
            attr_bytes,
            peer_ip,
            peer_asn,
            peer_bgp_id: None,
            as_path_slot: Cell::new(SLOT_UNSCANNED),
            timestamp,
            prefix: entry.prefix.prefix,
            path_id: entry.prefix.path_id,
            flags: entry.flags | FLAG_UPDATE,
            elem_type: entry.elem_type,
            warned_truncation: Cell::new(false),
        }
    }

    #[inline]
    fn afi(&self) -> Afi {
        if (self.flags & FLAG_AFI_IPV6) != 0 {
            Afi::Ipv6
        } else {
            Afi::Ipv4
        }
    }

    #[inline]
    fn safi(&self) -> Safi {
        if (self.flags & FLAG_SAFI_MULTICAST) != 0 {
            Safi::Multicast
        } else {
            Safi::Unicast
        }
    }

    /// The family `NEXT_HOP` is encoded with: the record's for a dump, IPv4 for an update.
    #[inline]
    fn next_hop_afi(&self) -> Afi {
        if (self.flags & FLAG_UPDATE) != 0 {
            Afi::Ipv4
        } else {
            self.afi()
        }
    }

    #[inline]
    fn is_add_path(&self) -> bool {
        (self.flags & FLAG_ADD_PATH) != 0
    }

    #[cold]
    #[inline(never)]
    fn warn_truncated_attr_once(&self, raw_code: u8, attr_length: usize, bytes_left: usize) {
        if !self.warned_truncation.replace(true) {
            let attr_type = AttrType::from(raw_code);
            warn!(
                "{:?} attribute encodes a length ({}) that is longer than the remaining attribute data ({}). Skipping remaining attribute data for BGP message",
                attr_type, attr_length, bytes_left
            );
        }
    }

    #[cold]
    #[inline(never)]
    fn scan_merged_as_paths(&self) -> (&'a [u8], &'a [u8]) {
        let bytes = self.attr_bytes;
        let len = bytes.len();
        let mut pos = 0usize;
        let mut p2: &'a [u8] = &[];
        let mut p4: &'a [u8] = &[];

        while pos + 3 <= len {
            let flags = bytes[pos];
            let code = bytes[pos + 1];
            let (hdr_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
                (3usize, bytes[pos + 2] as usize)
            } else {
                if pos + 4 > len {
                    break;
                }
                (
                    4usize,
                    u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize,
                )
            };
            let val_start = pos + hdr_len;
            let val_end = val_start + attr_len;
            if val_end > len {
                self.warn_truncated_attr_once(code, attr_len, len - val_start);
                break;
            }
            if code == u8::from(AttrType::AS_PATH) {
                let slice = &bytes[val_start..val_end];
                if validate_as_path_wire(slice) {
                    p2 = slice;
                }
            } else if code == u8::from(AttrType::AS4_PATH) {
                let slice = &bytes[val_start..val_end];
                if validate_as_path_wire(slice) {
                    p4 = slice;
                }
            }
            pos = val_end;
        }
        (p2, p4)
    }

    #[inline]
    fn resolve_as_path_source(&self) -> AsPathSource<'a> {
        let cached = self.as_path_slot.get();
        if cached != SLOT_UNSCANNED {
            return match cached {
                SLOT_ABSENT => AsPathSource::Absent,
                SLOT_MERGED => {
                    let (as_path, as4_path) = self.scan_merged_as_paths();
                    AsPathSource::Merged { as_path, as4_path }
                }
                packed => {
                    let start = (packed & 0xFFFF) as usize;
                    let len = ((packed >> 16) & 0xFFFF) as usize;
                    AsPathSource::Single(&self.attr_bytes[start..start + len])
                }
            };
        }

        let bytes = self.attr_bytes;
        let len = bytes.len();
        let mut pos = 0usize;
        let mut as_path_span: Option<(u16, u16)> = None;
        let mut as4_path_span: Option<(u16, u16)> = None;

        while pos + 3 <= len {
            let flags = bytes[pos];
            let code = bytes[pos + 1];
            let (hdr_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
                (3usize, bytes[pos + 2] as usize)
            } else {
                if pos + 4 > len {
                    break;
                }
                (
                    4usize,
                    u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize,
                )
            };
            let val_start = pos + hdr_len;
            let val_end = val_start + attr_len;
            if val_end > len {
                self.warn_truncated_attr_once(code, attr_len, len - val_start);
                break;
            }
            if code == u8::from(AttrType::AS_PATH) {
                if validate_as_path_wire(&bytes[val_start..val_end]) {
                    as_path_span = Some((val_start as u16, attr_len as u16));
                }
            } else if code == u8::from(AttrType::AS4_PATH)
                && validate_as_path_wire(&bytes[val_start..val_end])
            {
                as4_path_span = Some((val_start as u16, attr_len as u16));
            }
            pos = val_end;
        }

        match (as_path_span, as4_path_span) {
            (None, None) => {
                self.as_path_slot.set(SLOT_ABSENT);
                AsPathSource::Absent
            }
            (Some((s, l)), None) | (None, Some((s, l))) => {
                let packed = (s as u64) | ((l as u64) << 16);
                self.as_path_slot.set(packed);
                AsPathSource::Single(&bytes[s as usize..s as usize + l as usize])
            }
            (Some((s1, l1)), Some((s2, l2))) => {
                let p1 = &bytes[s1 as usize..s1 as usize + l1 as usize];
                let p2 = &bytes[s2 as usize..s2 as usize + l2 as usize];
                // Per RFC 6793 §4.2.3, when AS_PATH is shorter than AS4_PATH, AS4_PATH is ignored.
                if wire_route_len(p1) < wire_route_len(p2) {
                    let packed = (s1 as u64) | ((l1 as u64) << 16);
                    self.as_path_slot.set(packed);
                    AsPathSource::Single(p1)
                } else {
                    self.as_path_slot.set(SLOT_MERGED);
                    AsPathSource::Merged {
                        as_path: p1,
                        as4_path: p2,
                    }
                }
            }
        }
    }

    /// Returns the prefix this element announces, with the ADD-PATH identifier it carried.
    #[inline]
    pub fn prefix(&self) -> NetworkPrefix {
        NetworkPrefix::new(self.prefix, self.path_id)
    }

    /// Returns the IP address of the peer that exported this RIB entry.
    #[inline]
    pub fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }

    /// Returns the AS number of the peer that exported this RIB entry.
    #[inline]
    pub fn peer_asn(&self) -> Asn {
        self.peer_asn
    }

    /// Returns a zero-allocation borrowed view over the entry's effective `AS_PATH`.
    #[inline]
    pub fn as_path(&self) -> AsPathView<'a> {
        AsPathView {
            source: self.resolve_as_path_source(),
        }
    }

    /// Returns a zero-allocation view over the originating ASNs of the effective `AS_PATH`.
    #[inline]
    pub fn origin_asns(&self) -> AsnsView<'a> {
        match self.resolve_as_path_source() {
            AsPathSource::Absent => AsnsView {
                repr: OriginsRepr::Absent,
            },
            AsPathSource::Single(wire) => single_wire_origins(wire),
            AsPathSource::Merged { as_path, as4_path } => merged_wire_origins(as_path, as4_path),
        }
    }

    /// Returns a zero-allocation view over the entry's standard, extended, and large communities.
    #[inline]
    pub fn communities(&self) -> CommunitiesView<'a> {
        CommunitiesView {
            attr_bytes: self.usable_attr_prefix(),
        }
    }

    /// Returns the effective next-hop address (`NEXT_HOP`, or `MP_REACH_NLRI`'s global next hop).
    pub fn next_hop(&self) -> Option<IpAddr> {
        let bytes = self.attr_bytes;
        let len = bytes.len();
        let afi = self.afi();
        let safi = self.safi();
        let is_add_path = self.is_add_path();
        let mut pos = 0usize;
        let mut next_hop: Option<IpAddr> = None;
        let mut mp_next_hop: Option<IpAddr> = None;

        while pos + 3 <= len {
            let flags = bytes[pos];
            let code = bytes[pos + 1];
            let (hdr_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
                (3usize, bytes[pos + 2] as usize)
            } else {
                if pos + 4 > len {
                    break;
                }
                (
                    4usize,
                    u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize,
                )
            };
            let val_start = pos + hdr_len;
            let val_end = val_start + attr_len;
            if val_end > len {
                self.warn_truncated_attr_once(code, attr_len, len - val_start);
                break;
            }
            if code == u8::from(AttrType::NEXT_HOP) {
                let mut val = &bytes[val_start..val_end];
                if let Ok(addr) = val.read_address(&self.next_hop_afi()) {
                    next_hop = Some(addr);
                }
            } else if code == u8::from(AttrType::MP_REACHABLE_NLRI) {
                match mp_reach_next_hop(
                    &bytes[val_start..val_end],
                    self.prefix(),
                    afi,
                    safi,
                    is_add_path,
                    (self.flags & FLAG_UPDATE) != 0,
                ) {
                    Ok(address) => mp_next_hop = address,
                    // A body the owned parser rejects carries no usable next hop.
                    Err(()) => mp_next_hop = None,
                }
            }
            pos = val_end;
        }

        next_hop.or(mp_next_hop)
    }

    /// Returns the Multi-Exit Discriminator (`MULTI_EXIT_DISCRIMINATOR`), matching
    /// [`BgpElem::med`](crate::BgpElem::med) (`Some(0)` on RIB announcements without MED).
    pub fn med(&self) -> Option<u32> {
        if self.elem_type == ElemType::WITHDRAW {
            return None;
        }
        Some(
            self.scan_u32_attr(u8::from(AttrType::MULTI_EXIT_DISCRIMINATOR))
                .unwrap_or(0),
        )
    }

    /// Returns the Local Preference (`LOCAL_PREFERENCE`), matching
    /// [`BgpElem::local_pref`](crate::BgpElem::local_pref) (`Some(0)` on RIB announcements without
    /// `LOCAL_PREFERENCE`).
    pub fn local_pref(&self) -> Option<u32> {
        if self.elem_type == ElemType::WITHDRAW {
            return None;
        }
        Some(
            self.scan_u32_attr(u8::from(AttrType::LOCAL_PREFERENCE))
                .unwrap_or(0),
        )
    }

    /// Materialise this entry as an owned [`BgpElem`].
    ///
    /// Walks the attribute TLVs once for the scalar attributes, then reuses the borrowed views for
    /// the AS path, the communities, the next hop and the two u32 attributes. Values match an elem
    /// built from a parsed `MrtRecord`, including the `Some(0)` defaults for MED and LOCAL_PREF,
    /// with one documented difference: a known attribute that fails to parse is dropped here,
    /// while the owned path keeps it in `BgpElem::unknown`.
    /// This entry's attribute block, for the predicates that can decide an entry from bytes.
    pub(crate) fn attrs_bytes(&self) -> &'a [u8] {
        self.attr_bytes
    }

    /// Materialise this entry as an owned [`BgpElem`], for the fields the borrowed accessors do
    /// not expose.
    pub fn to_bgp_elem(&self) -> BgpElem {
        let bytes = self.usable_attr_prefix();
        let afi = self.afi();
        let safi = self.safi();
        let is_add_path = self.is_add_path();

        let mut origin: Option<Origin> = None;
        let mut atomic = false;
        let mut aggregator: Option<(Asn, BgpIdentifier)> = None;
        let mut only_to_customer: Option<Asn> = None;
        let mut med: Option<u32> = None;
        let mut local_pref: Option<u32> = None;
        let mut next_hop: Option<IpAddr> = None;
        let mut mp_next_hop: Option<IpAddr> = None;
        let mut as_path_wire: Option<&[u8]> = None;
        let mut as4_path_wire: Option<&[u8]> = None;
        let mut communities: Vec<MetaCommunity> = Vec::new();
        let mut unknown: Vec<AttrRaw> = Vec::new();
        let mut deprecated: Vec<AttrRaw> = Vec::new();

        let len = bytes.len();
        let mut pos = 0usize;
        while pos + 3 <= len {
            let flags = bytes[pos];
            let code = bytes[pos + 1];
            let (header_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
                (3usize, bytes[pos + 2] as usize)
            } else {
                if pos + 4 > len {
                    break;
                }
                (
                    4usize,
                    u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize,
                )
            };
            let val_start = pos + header_len;
            let val_end = val_start + attr_len;
            if val_end > len {
                self.warn_truncated_attr_once(code, attr_len, len - val_start);
                break;
            }
            let val = &bytes[val_start..val_end];
            pos = val_end;

            if get_deprecated_attr_type(code).is_some() {
                deprecated.push(AttrRaw {
                    code,
                    bytes: Bytes::copy_from_slice(val),
                });
                continue;
            }

            // A known attribute this cannot decode keeps its bytes in `unknown`, which is what the
            // owned path does with an attribute it falls back to `AttributeValue::Raw`.
            let mut undecoded = false;
            match AttrType::from(code) {
                // A value the owned path cannot parse becomes raw bytes and leaves the earlier
                // attribute of the same type in place, so keep what is already known here too.
                AttrType::ORIGIN => {
                    match val.first().and_then(|value| Origin::try_from(*value).ok()) {
                        Some(decoded) => origin = Some(decoded),
                        None => undecoded = true,
                    }
                }
                AttrType::AS_PATH => {
                    if validate_as_path_wire(val) {
                        as_path_wire = Some(val);
                    } else {
                        undecoded = true;
                    }
                }
                AttrType::AS4_PATH => {
                    if validate_as_path_wire(val) {
                        as4_path_wire = Some(val);
                    } else {
                        undecoded = true;
                    }
                }
                AttrType::NEXT_HOP => {
                    let mut value = val;
                    match value.read_address(&self.next_hop_afi()) {
                        Ok(address) => next_hop = Some(address),
                        Err(_) => undecoded = true,
                    }
                }
                AttrType::MULTI_EXIT_DISCRIMINATOR => {
                    let mut value = val;
                    match value.read_u32() {
                        Ok(number) => med = Some(number),
                        Err(_) => undecoded = true,
                    }
                }
                AttrType::LOCAL_PREFERENCE => {
                    let mut value = val;
                    match value.read_u32() {
                        Ok(number) => local_pref = Some(number),
                        Err(_) => undecoded = true,
                    }
                }
                AttrType::ATOMIC_AGGREGATE => atomic = true,
                // The owned parsers reject these two unless their length is exact.
                AttrType::ORIGINATOR_ID | AttrType::CLUSTER_LIST => {
                    if val.len() < 4 || !val.len().is_multiple_of(4) {
                        undecoded = true;
                    }
                }
                AttrType::AGGREGATOR | AttrType::AS4_AGGREGATOR => {
                    match crate::parser::bgp::attributes::parse_aggregator_slice(
                        bytes::Bytes::copy_from_slice(val),
                        &AsnLength::Bits32,
                    )
                    .ok()
                    {
                        Some(decoded) => aggregator = Some(decoded),
                        None => undecoded = true,
                    }
                }
                // Each community attribute is decoded by the owned parser for that attribute, at the
                // position it appears, so an unsupported sub-type, a length that is not a whole
                // element, and the special values all follow the owned rules and the raw bytes of a
                // malformed one land in `unknown` where the owned path puts them.
                AttrType::COMMUNITIES
                | AttrType::EXTENDED_COMMUNITIES
                | AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES
                | AttrType::LARGE_COMMUNITIES => {
                    let input = bytes::Bytes::copy_from_slice(val);
                    let decoded = match AttrType::from(code) {
                        AttrType::COMMUNITIES => {
                            crate::parser::bgp::attributes::parse_communities_attribute(input).map(
                                |value| match value {
                                    crate::models::AttributeValue::Communities(v) => {
                                        communities.extend(v.into_iter().map(MetaCommunity::Plain));
                                        true
                                    }
                                    _ => false,
                                },
                            )
                        }
                        AttrType::EXTENDED_COMMUNITIES => {
                            crate::parser::bgp::attributes::parse_extended_communities_attribute(
                                input,
                            )
                            .map(|value| match value {
                                crate::models::AttributeValue::ExtendedCommunities(v) => {
                                    communities
                                        .extend(v.into_iter().map(MetaCommunity::Extended));
                                    true
                                }
                                _ => false,
                            })
                        }
                        AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES => crate::parser::bgp::attributes::parse_ipv6_extended_communities_attribute(input)
                            .map(|value| match value {
                                crate::models::AttributeValue::Ipv6AddressSpecificExtendedCommunities(v) => {
                                    communities
                                        .extend(v.into_iter().map(MetaCommunity::Ipv6Extended));
                                    true
                                }
                                _ => false,
                            }),
                        _ => crate::parser::bgp::attributes::parse_large_communities_attribute(input)
                            .map(|value| match value {
                                crate::models::AttributeValue::LargeCommunities(v) => {
                                    communities.extend(v.into_iter().map(MetaCommunity::Large));
                                    true
                                }
                                _ => false,
                            }),
                    };
                    if !decoded.unwrap_or(false) {
                        undecoded = true;
                    }
                }
                AttrType::ONLY_TO_CUSTOMER => {
                    if val.len() >= 4 {
                        only_to_customer = Some(Asn::new_32bit(u32::from_be_bytes([
                            val[0], val[1], val[2], val[3],
                        ])));
                    } else {
                        undecoded = true;
                    }
                }
                AttrType::MP_REACHABLE_NLRI => {
                    match mp_reach_next_hop(
                        val,
                        self.prefix(),
                        afi,
                        safi,
                        is_add_path,
                        (self.flags & FLAG_UPDATE) != 0,
                    ) {
                        Ok(address) => mp_next_hop = address,
                        Err(()) => undecoded = true,
                    }
                }
                // Types the element path keeps as raw bytes, mirroring `get_relevant_attributes`.
                // A valid traffic-engineering attribute is parsed by the owned path and then
                // discarded from the element, so only a malformed one is kept raw.
                AttrType::TRAFFIC_ENGINEERING => {
                    if crate::parser::bgp::attributes::parse_traffic_engineering(
                        bytes::Bytes::copy_from_slice(val),
                    )
                    .is_err()
                    {
                        undecoded = true;
                    }
                }
                AttrType::Unknown(_)
                | AttrType::RESERVED
                | AttrType::PMSI_TUNNEL
                | AttrType::PE_DISTINGUISHER_LABELS
                | AttrType::BGPSEC_PATH
                | AttrType::ATTR_SET => unknown.push(AttrRaw {
                    code,
                    bytes: Bytes::copy_from_slice(val),
                }),
                _ => {}
            }
            if undecoded {
                unknown.push(AttrRaw {
                    code,
                    bytes: Bytes::copy_from_slice(val),
                });
            }
        }

        // RFC 6793 §4.2.3: when AS_PATH is shorter than AS4_PATH, AS4_PATH is ignored.
        let source = match (as_path_wire, as4_path_wire) {
            (None, None) => AsPathSource::Absent,
            (Some(path), None) => AsPathSource::Single(path),
            (None, Some(path)) => AsPathSource::Single(path),
            (Some(path), Some(as4_path)) => {
                if wire_route_len(path) < wire_route_len(as4_path) {
                    AsPathSource::Single(path)
                } else {
                    AsPathSource::Merged {
                        as_path: path,
                        as4_path,
                    }
                }
            }
        };
        let as_path = AsPathView { source }.to_as_path();
        let origin_asns = match source {
            AsPathSource::Absent => None,
            AsPathSource::Single(wire) => Some(single_wire_origins(wire).to_vec()),
            AsPathSource::Merged { as_path, as4_path } => {
                Some(merged_wire_origins(as_path, as4_path).to_vec())
            }
        };

        let is_withdrawal = self.elem_type() == ElemType::WITHDRAW;
        BgpElem {
            timestamp: self.timestamp(),
            elem_type: self.elem_type(),
            peer_ip: self.peer_ip,
            peer_asn: self.peer_asn,
            peer_bgp_id: self.peer_bgp_id,
            prefix: NetworkPrefix {
                prefix: self.prefix,
                path_id: self.path_id,
            },
            next_hop: next_hop.or(mp_next_hop),
            as_path,
            origin,
            origin_asns,
            // A withdrawal carries no attributes, so the owned path leaves these unset; every other
            // case keeps the `Some(0)` default the owned path applies too.
            local_pref: (!is_withdrawal).then(|| local_pref.unwrap_or(0)),
            med: (!is_withdrawal).then(|| med.unwrap_or(0)),
            communities: (!communities.is_empty()).then_some(communities),
            atomic,
            aggr_asn: aggregator.map(|value| value.0),
            aggr_ip: aggregator.map(|value| value.1),
            only_to_customer,
            unknown: (!unknown.is_empty()).then_some(unknown),
            deprecated: (!deprecated.is_empty()).then_some(deprecated),
        }
    }

    /// Returns this element's Unix timestamp as seconds (`f64`): the entry's originated time for
    /// a dump, the record's time for an update.
    #[inline]
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }

    /// Returns whether this element is an announcement or a withdrawal.
    #[inline]
    pub fn elem_type(&self) -> ElemType {
        self.elem_type
    }

    fn scan_u32_attr(&self, target_code: u8) -> Option<u32> {
        let bytes = self.attr_bytes;
        let len = bytes.len();
        let mut pos = 0usize;
        let mut found = None;

        while pos + 3 <= len {
            let flags = bytes[pos];
            let code = bytes[pos + 1];
            let (hdr_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
                (3usize, bytes[pos + 2] as usize)
            } else {
                if pos + 4 > len {
                    break;
                }
                (
                    4usize,
                    u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize,
                )
            };
            let val_start = pos + hdr_len;
            let val_end = val_start + attr_len;
            if val_end > len {
                self.warn_truncated_attr_once(code, attr_len, len - val_start);
                break;
            }
            if code == target_code && attr_len >= 4 {
                found = Some(u32::from_be_bytes([
                    bytes[val_start],
                    bytes[val_start + 1],
                    bytes[val_start + 2],
                    bytes[val_start + 3],
                ]));
            }
            pos = val_end;
        }
        found
    }

    #[inline]
    fn usable_attr_prefix(&self) -> &'a [u8] {
        let bytes = self.attr_bytes;
        let len = bytes.len();
        let mut pos = 0usize;
        while pos + 3 <= len {
            let flags = bytes[pos];
            let code = bytes[pos + 1];
            let (hdr_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
                (3usize, bytes[pos + 2] as usize)
            } else {
                if pos + 4 > len {
                    break;
                }
                (
                    4usize,
                    u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize,
                )
            };
            let val_start = pos + hdr_len;
            let val_end = val_start + attr_len;
            if val_end > len {
                self.warn_truncated_attr_once(code, attr_len, len - val_start);
                break;
            }
            pos = val_end;
        }
        &bytes[..pos]
    }
}
