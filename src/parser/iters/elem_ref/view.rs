//! Borrowed attribute views over one element's attribute block.
//!
//! Each type here reads the bytes the record already holds and yields values on demand. The
//! iterators over a single attribute allocate nothing; the ones that merge or coalesce (`segments`)
//! reuse the owned model's inline storage and allocate only past it.

use super::*;

pub(super) fn wire_route_len(mut wire: &[u8]) -> usize {
    let mut total = 0usize;
    while wire.len() >= 2 {
        let seg_type = wire[0];
        let count = wire[1] as usize;
        match seg_type {
            AS_PATH_AS_SEQUENCE => total += count,
            AS_PATH_AS_SET => total += 1,
            _ => {}
        }
        wire = &wire[2 + count * 4..];
    }
    total
}

/// The global next hop of an `MP_REACH_NLRI` value.
///
/// The owned NLRI parser decides it: the families it accepts, the reserved octet, the next-hop
/// widths, and the RFC 6396 §4.3.4 rule that a dump's entry may omit the attribute's own address
/// family all behave here exactly as they do there. A body it rejects has no next hop, which is what
/// the owned element path reports too. It allocates the copied body and the prefix list it decodes.
pub(super) fn mp_reach_next_hop(
    value: &[u8],
    prefix: NetworkPrefix,
    afi: Afi,
    safi: Safi,
    add_path: bool,
    from_update: bool,
) -> Result<Option<IpAddr>, ()> {
    let prefix_list = [prefix];
    let (afi, safi, prefixes) = if from_update {
        (None, None, None)
    } else {
        (Some(afi), Some(safi), Some(&prefix_list[..]))
    };
    let decoded = crate::parser::bgp::attributes::parse_nlri(
        bytes::Bytes::copy_from_slice(value),
        &afi,
        &safi,
        &prefixes,
        true,
        add_path,
    )
    .map_err(|_| ())?;
    match decoded {
        crate::models::AttributeValue::MpReachNlri(nlri) => {
            Ok(nlri.next_hop.map(|next_hop| next_hop.global_addr()))
        }
        _ => Err(()),
    }
}

///////////////////////////////////////////////////////////////////////////////
// AS_PATH & Origin ASN Views
///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, Debug)]
pub(super) enum AsPathSource<'a> {
    Absent,
    Single(&'a [u8]),
    Merged {
        as_path: &'a [u8],
        as4_path: &'a [u8],
    },
}

/// Segment kind in a wire `AS_PATH` attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum AsPathSegmentType {
    AsSet,
    AsSequence,
    ConfedSequence,
    ConfedSet,
}

impl AsPathSegmentType {
    #[inline]
    fn from_wire(code: u8) -> Self {
        match code {
            AS_PATH_AS_SET => Self::AsSet,
            AS_PATH_AS_SEQUENCE => Self::AsSequence,
            AS_PATH_CONFED_SEQUENCE => Self::ConfedSequence,
            AS_PATH_CONFED_SET => Self::ConfedSet,
            // Every caller validates the path first, so this is unreachable today; a segment type
            // added later must not turn that into a panic.
            _ => Self::AsSequence,
        }
    }
}

/// Borrowed view over one segment in a wire `AS_PATH`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AsPathSegmentRef<'a> {
    seg_type: AsPathSegmentType,
    asn_bytes: &'a [u8],
}

/// Zero-allocation borrowed view over an element's effective `AS_PATH`.
///
/// Iterating an `AsPathView` yields every [`Asn`] across its wire segments in order, expanding
/// `AS_SET` (and confederation) segments inline on the fly without allocating. Call
/// [`segments`](Self::segments) to inspect segment boundaries or [`to_vec`](Self::to_vec) to
/// materialise an owned `Vec<Asn>`.
#[derive(Clone, Copy, Debug)]
pub struct AsPathView<'a> {
    pub(super) source: AsPathSource<'a>,
}

impl<'a> AsPathView<'a> {
    /// Returns `true` if a valid `AS_PATH` (or `AS4_PATH`) attribute is present on the element
    /// (including an empty 0-segment iBGP `AS_PATH`).
    #[inline]
    pub fn is_present(&self) -> bool {
        !matches!(self.source, AsPathSource::Absent)
    }

    /// Returns `true` if the path yields no AS numbers.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    /// Returns the path's segments after the same RFC 6793 merge and coalesce the owned [`AsPath`]
    /// applies, so their boundaries match `elem.as_path` exactly.
    ///
    /// A single-segment path keeps its ASNs inline; a path with more than one segment, or with a
    /// segment of more than six ASNs, allocates for the part that does not fit.
    #[inline]
    pub fn segments(&self) -> crate::models::SegmentIntoIter {
        match self.to_as_path() {
            Some(path) => path.into_segments_iter(),
            None => AsPath::default().into_segments_iter(),
        }
    }

    /// The wire segments this path is made of, without merging or coalescing them.
    #[inline]
    fn wire_segments(&self) -> AsPathSegments<'a> {
        match self.source {
            AsPathSource::Absent => AsPathSegments {
                lead: &[],
                lead_remaining: 0,
                tail: &[],
            },
            AsPathSource::Single(wire) => AsPathSegments {
                lead: &[],
                lead_remaining: 0,
                tail: wire,
            },
            AsPathSource::Merged { as_path, as4_path } => {
                let lead_remaining = wire_route_len(as_path) - wire_route_len(as4_path);
                AsPathSegments {
                    lead: if lead_remaining > 0 { as_path } else { &[] },
                    lead_remaining,
                    tail: as4_path,
                }
            }
        }
    }

    /// Returns a zero-allocation iterator over all [`Asn`]s in the path, expanding `AS_SET`
    /// segments inline on the fly.
    #[inline]
    pub fn iter(&self) -> AsPathIter<'a> {
        match self.source {
            AsPathSource::Absent => AsPathIter {
                cur_words: &[],
                segs: AsPathSegments {
                    lead: &[],
                    lead_remaining: 0,
                    tail: &[],
                },
            },
            AsPathSource::Single(wire) => {
                if wire.len() >= 2 {
                    let count = wire[1] as usize;
                    let end = 2 + count * 4;
                    AsPathIter {
                        cur_words: bytes_as_be_u32_words(&wire[2..end]),
                        segs: AsPathSegments {
                            lead: &[],
                            lead_remaining: 0,
                            tail: &wire[end..],
                        },
                    }
                } else {
                    AsPathIter {
                        cur_words: &[],
                        segs: AsPathSegments {
                            lead: &[],
                            lead_remaining: 0,
                            tail: &[],
                        },
                    }
                }
            }
            AsPathSource::Merged { .. } => AsPathIter {
                cur_words: &[],
                segs: self.wire_segments(),
            },
        }
    }

    /// Materialises all [`Asn`]s in this path (with `AS_SET` expanded in wire order) into a `Vec`.
    pub fn to_vec(&self) -> Vec<Asn> {
        self.iter().collect()
    }

    /// Converts this view into an owned `Option<AsPath>` matching [`BgpElem::as_path`](crate::BgpElem::as_path).
    pub fn to_as_path(&self) -> Option<AsPath> {
        match self.source {
            AsPathSource::Absent => None,
            AsPathSource::Single(wire) => Some(wire_to_owned_as_path(wire)),
            AsPathSource::Merged { as_path, as4_path } => {
                let p1 = wire_to_owned_as_path(as_path);
                let p2 = wire_to_owned_as_path(as4_path);
                Some(AsPath::merge_aspath_as4path(&p1, &p2))
            }
        }
    }
}

fn wire_to_owned_as_path(wire: &[u8]) -> AsPath {
    let mut out = AsPath::new();
    let mut rest = wire;
    while rest.len() >= 2 {
        let code = rest[0];
        let count = rest[1] as usize;
        let end = 2 + count * 4;
        let asns = bytes_as_be_u32_words(&rest[2..end])
            .iter()
            .map(|w| Asn::new_32bit(w.get()))
            .collect();
        let seg = match code {
            AS_PATH_AS_SET => Some(AsPathSegment::AsSet(asns)),
            AS_PATH_AS_SEQUENCE => Some(AsPathSegment::AsSequence(asns)),
            AS_PATH_CONFED_SEQUENCE => Some(AsPathSegment::ConfedSequence(asns)),
            AS_PATH_CONFED_SET => Some(AsPathSegment::ConfedSet(asns)),
            // Validated before this runs, so this arm is unreachable today; skipping is safer than
            // panicking if a later segment type reaches here.
            _ => None,
        };
        if let Some(seg) = seg {
            out.append_segment(seg);
        }
        rest = &rest[end..];
    }
    out
}

impl<'a> IntoIterator for AsPathView<'a> {
    type Item = Asn;
    type IntoIter = AsPathIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &AsPathView<'a> {
    type Item = Asn;
    type IntoIter = AsPathIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over borrowed [`AsPathSegmentRef`]s of an [`AsPathView`].
#[derive(Clone, Debug)]
pub(super) struct AsPathSegments<'a> {
    lead: &'a [u8],
    lead_remaining: usize,
    tail: &'a [u8],
}

impl<'a> Iterator for AsPathSegments<'a> {
    type Item = AsPathSegmentRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.lead_remaining > 0 && self.lead.len() >= 2 {
            let code = self.lead[0];
            let count = self.lead[1] as usize;
            let end = 2 + count * 4;
            let full_asn_bytes = &self.lead[2..end];
            self.lead = &self.lead[end..];

            let seg_type = AsPathSegmentType::from_wire(code);
            let route_asns = match seg_type {
                AsPathSegmentType::AsSequence => count,
                AsPathSegmentType::AsSet => 1,
                AsPathSegmentType::ConfedSequence | AsPathSegmentType::ConfedSet => 0,
            };

            if route_asns <= self.lead_remaining {
                self.lead_remaining -= route_asns;
                if self.lead_remaining == 0 {
                    self.lead = &[];
                }
                return Some(AsPathSegmentRef {
                    seg_type,
                    asn_bytes: full_asn_bytes,
                });
            } else {
                // Only AS_SEQUENCE can straddle the leading count boundary (RFC 6793 §4.2.3).
                let take_bytes = self.lead_remaining * 4;
                self.lead_remaining = 0;
                self.lead = &[];
                return Some(AsPathSegmentRef {
                    seg_type,
                    asn_bytes: &full_asn_bytes[..take_bytes],
                });
            }
        }

        if self.tail.len() >= 2 {
            let code = self.tail[0];
            let count = self.tail[1] as usize;
            let end = 2 + count * 4;
            let asn_bytes = &self.tail[2..end];
            self.tail = &self.tail[end..];
            return Some(AsPathSegmentRef {
                seg_type: AsPathSegmentType::from_wire(code),
                asn_bytes,
            });
        }

        None
    }
}

/// Iterator over [`Asn`]s in an [`AsPathView`], expanding `AS_SET` segments on the fly.
#[derive(Clone, Debug)]
pub struct AsPathIter<'a> {
    cur_words: &'a [BeU32],
    segs: AsPathSegments<'a>,
}

impl<'a> Iterator for AsPathIter<'a> {
    type Item = Asn;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((first, rest)) = self.cur_words.split_first() {
                self.cur_words = rest;
                return Some(Asn::new_32bit(first.get()));
            }
            let seg = self.segs.next()?;
            self.cur_words = bytes_as_be_u32_words(seg.asn_bytes);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum OriginsRepr<'a> {
    Absent,
    Empty,
    One(Asn),
    Set(&'a [BeU32]),
}

#[inline]
pub(super) fn single_wire_origins(wire: &[u8]) -> AsnsView<'_> {
    // Fast path (99.99% of RIB entries): single non-empty AS_SEQUENCE segment.
    if wire.len() >= 6 && wire[0] == AS_PATH_AS_SEQUENCE && 2 + (wire[1] as usize) * 4 == wire.len()
    {
        let last = wire.len() - 4;
        let asn = Asn::new_32bit(u32::from_be_bytes([
            wire[last],
            wire[last + 1],
            wire[last + 2],
            wire[last + 3],
        ]));
        return AsnsView {
            repr: OriginsRepr::One(asn),
        };
    }

    let mut rest = wire;
    let mut last_seg: Option<(u8, &[u8])> = None;
    while rest.len() >= 2 {
        let code = rest[0];
        let count = rest[1] as usize;
        let end = 2 + count * 4;
        last_seg = Some((code, &rest[2..end]));
        rest = &rest[end..];
    }

    let repr = match last_seg {
        Some((AS_PATH_AS_SEQUENCE, bytes)) if bytes.len() >= 4 => {
            let i = bytes.len() - 4;
            OriginsRepr::One(Asn::new_32bit(u32::from_be_bytes([
                bytes[i],
                bytes[i + 1],
                bytes[i + 2],
                bytes[i + 3],
            ])))
        }
        Some((AS_PATH_AS_SET, bytes)) if !bytes.is_empty() => {
            OriginsRepr::Set(bytes_as_be_u32_words(bytes))
        }
        _ => OriginsRepr::Empty,
    };
    AsnsView { repr }
}

/// Compute exact post-`coalesce()` origin ASNs of RFC 6793 merged `(as_path, as4_path)` without
/// allocating.
#[cold]
pub(super) fn merged_wire_origins<'a>(as_path: &'a [u8], as4_path: &'a [u8]) -> AsnsView<'a> {
    #[derive(Clone, Copy)]
    enum LastCoalesced<'b> {
        None,
        EmptySeq,
        NonEmptyAsSeq(Asn),
        NonEmptyConfedSeq,
        AsSet(&'b [BeU32]),
        ConfedSet,
    }

    let segs = AsPathSegments {
        lead: if wire_route_len(as_path) > wire_route_len(as4_path) {
            as_path
        } else {
            &[]
        },
        lead_remaining: wire_route_len(as_path) - wire_route_len(as4_path),
        tail: as4_path,
    };

    let mut state = LastCoalesced::None;
    for seg in segs {
        let next_state = match seg.seg_type {
            AsPathSegmentType::AsSequence => {
                if seg.asn_bytes.len() >= 4 {
                    let i = seg.asn_bytes.len() - 4;
                    LastCoalesced::NonEmptyAsSeq(Asn::new_32bit(u32::from_be_bytes([
                        seg.asn_bytes[i],
                        seg.asn_bytes[i + 1],
                        seg.asn_bytes[i + 2],
                        seg.asn_bytes[i + 3],
                    ])))
                } else {
                    LastCoalesced::EmptySeq
                }
            }
            AsPathSegmentType::ConfedSequence => {
                if seg.asn_bytes.is_empty() {
                    LastCoalesced::EmptySeq
                } else {
                    LastCoalesced::NonEmptyConfedSeq
                }
            }
            AsPathSegmentType::AsSet => LastCoalesced::AsSet(bytes_as_be_u32_words(seg.asn_bytes)),
            AsPathSegmentType::ConfedSet => LastCoalesced::ConfedSet,
        };

        // Mirrors `AsPathSegment::merge_in_place` in `AsPath::coalesce`.
        state = match (state, next_state) {
            (LastCoalesced::None, y) | (LastCoalesced::EmptySeq, y) => y,
            (x, LastCoalesced::EmptySeq) => x,
            (_, y) => y,
        };
    }

    let repr = match state {
        LastCoalesced::NonEmptyAsSeq(asn) => OriginsRepr::One(asn),
        LastCoalesced::AsSet(words) if !words.is_empty() => OriginsRepr::Set(words),
        _ => OriginsRepr::Empty,
    };
    AsnsView { repr }
}

/// Zero-allocation view over the originating ASNs of an element's `AS_PATH`.
#[derive(Clone, Copy, Debug)]
pub struct AsnsView<'a> {
    pub(super) repr: OriginsRepr<'a>,
}

impl<'a> AsnsView<'a> {
    /// Returns `true` when the element carries a valid `AS_PATH` (matching
    /// `elem.origin_asns.is_some()` on [`BgpElem`](crate::BgpElem)).
    #[inline]
    pub fn is_present(&self) -> bool {
        !matches!(self.repr, OriginsRepr::Absent)
    }

    /// Returns the number of originating ASNs (`0`, `1`, or the cardinality of a trailing
    /// `AS_SET`).
    #[inline]
    pub fn len(&self) -> usize {
        match self.repr {
            OriginsRepr::Absent | OriginsRepr::Empty => 0,
            OriginsRepr::One(_) => 1,
            OriginsRepr::Set(words) => words.len(),
        }
    }

    /// Returns `true` if there are zero originating ASNs.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator over the originating [`Asn`]s without allocating.
    #[inline]
    pub fn iter(&self) -> AsnsIter<'a> {
        AsnsIter { repr: self.repr }
    }

    /// Materialises the originating [`Asn`]s into a `Vec<Asn>`.
    pub fn to_vec(&self) -> Vec<Asn> {
        self.iter().collect()
    }
}

impl<'a> IntoIterator for AsnsView<'a> {
    type Item = Asn;
    type IntoIter = AsnsIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &AsnsView<'a> {
    type Item = Asn;
    type IntoIter = AsnsIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over originating [`Asn`]s from [`AsnsView`].
#[derive(Clone, Debug)]
pub struct AsnsIter<'a> {
    repr: OriginsRepr<'a>,
}

impl<'a> Iterator for AsnsIter<'a> {
    type Item = Asn;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.repr {
            OriginsRepr::Absent | OriginsRepr::Empty => None,
            OriginsRepr::One(asn) => {
                let out = *asn;
                self.repr = OriginsRepr::Empty;
                Some(out)
            }
            OriginsRepr::Set(words) => {
                let (first, rest) = words.split_first()?;
                *words = rest;
                Some(Asn::new_32bit(first.get()))
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = match self.repr {
            OriginsRepr::Absent | OriginsRepr::Empty => 0,
            OriginsRepr::One(_) => 1,
            OriginsRepr::Set(words) => words.len(),
        };
        (len, Some(len))
    }
}

impl ExactSizeIterator for AsnsIter<'_> {}

///////////////////////////////////////////////////////////////////////////////
// Communities View
///////////////////////////////////////////////////////////////////////////////

/// Cast a byte slice whose length is a multiple of 4 into a zero-copy slice of unaligned
/// network-byte-order 32-bit words (`zerocopy::big_endian::U32`) without `unsafe`.
///
/// If `bytes.len()` is not a multiple of 4, returns an empty slice.
#[inline]
pub(super) fn bytes_as_be_u32_words(bytes: &[u8]) -> &[BeU32] {
    if !bytes.len().is_multiple_of(4) {
        return &[];
    }
    <[BeU32]>::ref_from_bytes(bytes).unwrap_or(&[])
}

/// Borrowed view over an element's BGP community attributes (`COMMUNITIES`,
/// `EXTENDED_COMMUNITIES`, `IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES`, and
/// `LARGE_COMMUNITIES`).
///
/// Note on wire layout: BGP attributes in MRT bodies sit at arbitrary 1-byte alignments, store
/// integers in network byte order (big-endian), and split plain, extended, and large communities
/// across distinct TLV attributes. Consequently, a native `&[u32]` slice cannot borrow the wire
/// bytes directly on little-endian hosts without copying. Instead, `CommunitiesView` borrows the
/// attribute bytes directly and exposes zero-allocation 32-bit word accessors ([`words`](Self::words),
/// alongside typed in-place adapters
/// ([`as_plain`](Self::as_plain), [`as_extended`](Self::as_extended),
/// [`as_ipv6_extended`](Self::as_ipv6_extended), [`as_large`](Self::as_large), and
/// [`iter`](Self::iter)).
#[derive(Clone, Copy, Debug)]
pub struct CommunitiesView<'a> {
    pub(super) attr_bytes: &'a [u8],
}

impl<'a> CommunitiesView<'a> {
    /// Returns `true` if the element carries no communities of any kind.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    /// Iterates over all raw 32-bit big-endian words across all valid community attributes in wire
    /// order (`1` word per plain community, `2` per extended, `5` per IPv6 extended, `3` per
    /// large).
    #[inline]
    pub fn words(&self) -> CommunityWordsIter<'a> {
        CommunityWordsIter {
            rest_attrs: self.attr_bytes,
            cur_words: &[],
        }
    }

    /// Iterates over standard RFC 1997 [`Community`] values (`COMMUNITIES`, type 8).
    #[inline]
    pub fn as_plain(&self) -> PlainCommunitiesIter<'a> {
        PlainCommunitiesIter {
            rest_attrs: self.attr_bytes,
            cur_words: &[],
        }
    }

    /// Iterates over RFC 4360 [`ExtendedCommunity`] values (`EXTENDED_COMMUNITIES`, type 16).
    #[inline]
    pub fn as_extended(&self) -> ExtendedCommunitiesIter<'a> {
        ExtendedCommunitiesIter {
            rest_attrs: self.attr_bytes,
            cur_bytes: &[],
        }
    }

    /// Iterates over RFC 5701 [`Ipv6AddrExtCommunity`] values
    /// (`IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES`, type 25).
    #[inline]
    pub fn as_ipv6_extended(&self) -> Ipv6ExtendedCommunitiesIter<'a> {
        Ipv6ExtendedCommunitiesIter {
            rest_attrs: self.attr_bytes,
            cur_bytes: &[],
        }
    }

    /// Iterates over RFC 8092 [`LargeCommunity`] values (`LARGE_COMMUNITIES`, type 32).
    #[inline]
    pub fn as_large(&self) -> LargeCommunitiesIter<'a> {
        LargeCommunitiesIter {
            rest_attrs: self.attr_bytes,
            cur_words: &[],
        }
    }

    /// Iterates over all [`MetaCommunity`] values in wire attribute order, matching
    /// [`BgpElem::communities`](crate::BgpElem::communities).
    #[inline]
    pub fn iter(&self) -> CommunitiesIter<'a> {
        CommunitiesIter {
            rest_attrs: self.attr_bytes,
            cur_kind: ActiveCommunityAttr::None,
        }
    }
}

impl<'a> IntoIterator for CommunitiesView<'a> {
    type Item = MetaCommunity;
    type IntoIter = CommunitiesIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &CommunitiesView<'a> {
    type Item = MetaCommunity;
    type IntoIter = CommunitiesIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[inline]
pub(super) fn next_attr_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if bytes.len() < 3 {
        return None;
    }
    let flags = bytes[0];
    let code = bytes[1];
    let (hdr_len, attr_len) = if (flags & AttrFlags::EXTENDED.bits()) == 0 {
        (3usize, bytes[2] as usize)
    } else {
        if bytes.len() < 4 {
            return None;
        }
        (4usize, u16::from_be_bytes([bytes[2], bytes[3]]) as usize)
    };
    let end = hdr_len + attr_len;
    if end > bytes.len() {
        return None;
    }
    Some((code, &bytes[hdr_len..end], &bytes[end..]))
}

/// Iterator over all raw 32-bit community words across an element's community attributes.
#[derive(Clone, Debug)]
pub struct CommunityWordsIter<'a> {
    rest_attrs: &'a [u8],
    cur_words: &'a [BeU32],
}

impl Iterator for CommunityWordsIter<'_> {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<u32> {
        loop {
            if let Some((first, rest)) = self.cur_words.split_first() {
                self.cur_words = rest;
                return Some(first.get());
            }
            let (code, val, next_rest) = next_attr_tlv(self.rest_attrs)?;
            self.rest_attrs = next_rest;
            let valid = match AttrType::from(code) {
                AttrType::COMMUNITIES => val.len().is_multiple_of(4),
                AttrType::EXTENDED_COMMUNITIES => val.len().is_multiple_of(8),
                AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES => {
                    val.len().is_multiple_of(20)
                }
                AttrType::LARGE_COMMUNITIES => val.len().is_multiple_of(12),
                _ => false,
            };
            if valid {
                self.cur_words = bytes_as_be_u32_words(val);
            }
        }
    }
}

/// Iterator over standard [`Community`] values from [`CommunitiesView::as_plain`].
#[derive(Clone, Debug)]
pub struct PlainCommunitiesIter<'a> {
    rest_attrs: &'a [u8],
    cur_words: &'a [BeU32],
}

impl Iterator for PlainCommunitiesIter<'_> {
    type Item = Community;

    #[inline]
    fn next(&mut self) -> Option<Community> {
        loop {
            if let Some((first, rest)) = self.cur_words.split_first() {
                self.cur_words = rest;
                return Some(crate::parser::bgp::attributes::decode_regular_community(
                    first.get(),
                ));
            }
            let (code, val, next_rest) = next_attr_tlv(self.rest_attrs)?;
            self.rest_attrs = next_rest;
            if code == u8::from(AttrType::COMMUNITIES) && val.len().is_multiple_of(4) {
                self.cur_words = bytes_as_be_u32_words(val);
            }
        }
    }
}

/// Iterator over [`ExtendedCommunity`] values from [`CommunitiesView::as_extended`].
#[derive(Clone, Debug)]
pub struct ExtendedCommunitiesIter<'a> {
    rest_attrs: &'a [u8],
    cur_bytes: &'a [u8],
}

impl Iterator for ExtendedCommunitiesIter<'_> {
    type Item = ExtendedCommunity;

    #[inline]
    fn next(&mut self) -> Option<ExtendedCommunity> {
        loop {
            if self.cur_bytes.len() >= 8 {
                let mut chunk = &self.cur_bytes[..8];
                self.cur_bytes = &self.cur_bytes[8..];
                return Some(
                    crate::parser::bgp::attributes::parse_extended_community_one(&mut chunk)
                        .unwrap_or(ExtendedCommunity::Raw([0u8; 8])),
                );
            }
            let (code, val, next_rest) = next_attr_tlv(self.rest_attrs)?;
            self.rest_attrs = next_rest;
            if code == u8::from(AttrType::EXTENDED_COMMUNITIES) && val.len().is_multiple_of(8) {
                self.cur_bytes = val;
            }
        }
    }
}

/// Iterator over [`Ipv6AddrExtCommunity`] values from [`CommunitiesView::as_ipv6_extended`].
#[derive(Clone, Debug)]
pub struct Ipv6ExtendedCommunitiesIter<'a> {
    rest_attrs: &'a [u8],
    cur_bytes: &'a [u8],
}

impl Iterator for Ipv6ExtendedCommunitiesIter<'_> {
    type Item = Ipv6AddrExtCommunity;

    #[inline]
    fn next(&mut self) -> Option<Ipv6AddrExtCommunity> {
        loop {
            if self.cur_bytes.len() >= 20 {
                let mut chunk = &self.cur_bytes[..20];
                self.cur_bytes = &self.cur_bytes[20..];
                return crate::parser::bgp::attributes::parse_ipv6_extended_community_one(
                    &mut chunk,
                )
                .ok();
            }
            let (code, val, next_rest) = next_attr_tlv(self.rest_attrs)?;
            self.rest_attrs = next_rest;
            if code == u8::from(AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES)
                && val.len().is_multiple_of(20)
            {
                self.cur_bytes = val;
            }
        }
    }
}

/// Iterator over [`LargeCommunity`] values from [`CommunitiesView::as_large`].
#[derive(Clone, Debug)]
pub struct LargeCommunitiesIter<'a> {
    rest_attrs: &'a [u8],
    cur_words: &'a [BeU32],
}

impl Iterator for LargeCommunitiesIter<'_> {
    type Item = LargeCommunity;

    #[inline]
    fn next(&mut self) -> Option<LargeCommunity> {
        loop {
            if self.cur_words.len() >= 3 {
                let ga = self.cur_words[0].get();
                let d0 = self.cur_words[1].get();
                let d1 = self.cur_words[2].get();
                self.cur_words = &self.cur_words[3..];
                return Some(LargeCommunity::new(ga, [d0, d1]));
            }
            let (code, val, next_rest) = next_attr_tlv(self.rest_attrs)?;
            self.rest_attrs = next_rest;
            if code == u8::from(AttrType::LARGE_COMMUNITIES) && val.len().is_multiple_of(12) {
                self.cur_words = bytes_as_be_u32_words(val);
            }
        }
    }
}

#[derive(Clone, Debug)]
enum ActiveCommunityAttr<'a> {
    None,
    Plain(&'a [BeU32]),
    Extended(&'a [u8]),
    Ipv6Extended(&'a [u8]),
    Large(&'a [BeU32]),
}

/// Iterator over all [`MetaCommunity`] items in wire attribute order.
#[derive(Clone, Debug)]
pub struct CommunitiesIter<'a> {
    rest_attrs: &'a [u8],
    cur_kind: ActiveCommunityAttr<'a>,
}

impl Iterator for CommunitiesIter<'_> {
    type Item = MetaCommunity;

    #[inline]
    fn next(&mut self) -> Option<MetaCommunity> {
        loop {
            match &mut self.cur_kind {
                ActiveCommunityAttr::Plain(words) => {
                    if let Some((first, rest)) = words.split_first() {
                        *words = rest;
                        return Some(MetaCommunity::Plain(
                            crate::parser::bgp::attributes::decode_regular_community(first.get()),
                        ));
                    }
                }
                ActiveCommunityAttr::Extended(bytes) => {
                    if bytes.len() >= 8 {
                        let mut chunk = &bytes[..8];
                        *bytes = &bytes[8..];
                        return Some(MetaCommunity::Extended(
                            crate::parser::bgp::attributes::parse_extended_community_one(
                                &mut chunk,
                            )
                            .unwrap_or(ExtendedCommunity::Raw([0u8; 8])),
                        ));
                    }
                }
                ActiveCommunityAttr::Ipv6Extended(bytes) => {
                    if bytes.len() >= 20 {
                        let mut chunk = &bytes[..20];
                        *bytes = &bytes[20..];
                        if let Ok(item) =
                            crate::parser::bgp::attributes::parse_ipv6_extended_community_one(
                                &mut chunk,
                            )
                        {
                            return Some(MetaCommunity::Ipv6Extended(item));
                        }
                    }
                }
                ActiveCommunityAttr::Large(words) => {
                    if words.len() >= 3 {
                        let ga = words[0].get();
                        let d0 = words[1].get();
                        let d1 = words[2].get();
                        *words = &words[3..];
                        return Some(MetaCommunity::Large(LargeCommunity::new(ga, [d0, d1])));
                    }
                }
                ActiveCommunityAttr::None => {}
            }

            self.cur_kind = ActiveCommunityAttr::None;
            let (code, val, next_rest) = next_attr_tlv(self.rest_attrs)?;
            self.rest_attrs = next_rest;
            match AttrType::from(code) {
                AttrType::COMMUNITIES if val.len().is_multiple_of(4) => {
                    self.cur_kind = ActiveCommunityAttr::Plain(bytes_as_be_u32_words(val));
                }
                AttrType::EXTENDED_COMMUNITIES if val.len().is_multiple_of(8) => {
                    self.cur_kind = ActiveCommunityAttr::Extended(val);
                }
                AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES
                    if val.len().is_multiple_of(20) =>
                {
                    self.cur_kind = ActiveCommunityAttr::Ipv6Extended(val);
                }
                AttrType::LARGE_COMMUNITIES if val.len().is_multiple_of(12) => {
                    self.cur_kind = ActiveCommunityAttr::Large(bytes_as_be_u32_words(val));
                }
                _ => {}
            }
        }
    }
}
