//! Byte-level pre-checks for filters that only need attribute bytes.
//!
//! An origin filter can only match an element whose AS path ends at the requested origin, a
//! community filter needs a specific pair in the COMMUNITIES attribute, and a path filter needs one
//! ASN at a known position in the path. A dump record in which no entry can satisfy one of those
//! yields no matching elements, so it can be skipped before its body is parsed. Deciding this costs
//! one walk over the TLV headers plus a comparison on the values the predicate names, against a full
//! attribute decode and an element construction per entry.
//!
//! The one rule here is that a reject must be certain: whenever this module cannot decide an entry
//! it reports that, and the caller parses the record the general way.

use crate::models::{Asn, Origin};
use crate::parser::mrt::frame::FLAG_ADD_PATH;
use crate::Filter;
use smallvec::SmallVec;

/// The predicates one record-level pass can decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttrPredicate {
    /// `origin_asn=N`
    OriginAsn(u32),
    /// `origin_asns=N,M`
    OriginAsns(Vec<u32>),
    /// `origin=igp|egp|incomplete`
    OriginValue(Origin),
    /// `community=^ASN:VALUE$`
    CommunityExact { asn: u16, value: u16 },
    /// `community=^ASN:`
    CommunityAsn { asn: u16 },
    /// An AS path whose first, last, or middle element is one ASN.
    PathAsn {
        asn: u32,
        at_start: bool,
        at_end: bool,
    },
}

/// What one entry's attribute block says, as far as the predicates above need to know.
#[derive(Debug, Default)]
struct EntryFacts<'a> {
    origin_at: Option<u8>,
    path: Option<&'a [u8]>,
    communities: Option<&'a [u8]>,
    large_communities: Option<&'a [u8]>,
    ext_communities: Option<&'a [u8]>,
    /// `AS4_PATH` can replace the origin and the AS path.
    has_as4_path: bool,
    /// A community attribute appears more than once. The owned path merges every instance into one
    /// list, so this module cannot answer from a single slice.
    duplicate_community: bool,
    truncated: bool,
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

/// Walk one attribute block once and record where the attributes this module cares about sit.
fn read_entry(attrs: &[u8]) -> EntryFacts<'_> {
    let mut facts = EntryFacts::default();
    let mut rest = attrs;
    while !rest.is_empty() {
        if rest.len() < 3 {
            facts.truncated = true;
            return facts;
        }
        let extended = rest[0] & 0x10 != 0;
        let attr_type = rest[1];
        let (header_len, body_len) = if extended {
            if rest.len() < 4 {
                facts.truncated = true;
                return facts;
            }
            (4, read_u16(&rest[2..]) as usize)
        } else {
            (3, rest[2] as usize)
        };
        if rest.len() < header_len + body_len {
            facts.truncated = true;
            return facts;
        }
        let body = &rest[header_len..header_len + body_len];
        match attr_type {
            // The owned path keeps the earlier value when a later attribute of the same type cannot
            // be parsed: the malformed one becomes raw bytes in `unknown`.
            1 => {
                if let Some(at) = body.first().filter(|at| **at <= 2) {
                    facts.origin_at = Some(*at);
                }
            }
            2 => {
                if path_validates(body) {
                    facts.path = Some(body);
                }
            }
            8 => {
                facts.duplicate_community |= facts.communities.is_some();
                facts.communities = Some(body);
            }
            // 16 is the extended community and 25 the IPv6 address-specific form; both render with
            // a leading type field, so both can satisfy an anchored pattern.
            16 | 25 => {
                facts.duplicate_community |= facts.ext_communities.is_some();
                facts.ext_communities = Some(body);
            }
            32 => {
                facts.duplicate_community |= facts.large_communities.is_some();
                facts.large_communities = Some(body);
            }
            17 => facts.has_as4_path = true,
            _ => {}
        }
        rest = &rest[header_len + body_len..];
    }
    facts
}

/// Whether every segment of a 4-byte `AS_PATH` is well formed.
///
/// The owned path rejects the whole attribute when any segment is invalid, so a malformed duplicate
/// must not replace a valid path this module already read.
fn path_validates(mut body: &[u8]) -> bool {
    while !body.is_empty() {
        if body.len() < 2 {
            return false;
        }
        let segment_type = body[0];
        let len = body[1] as usize * 4;
        if !(1..=4).contains(&segment_type) || body.len() < 2 + len {
            return false;
        }
        body = &body[2 + len..];
    }
    true
}

/// The origin of a 4-byte `AS_PATH`: `Ok(None)` for a path that has none.
///
/// Mirrors `AsPath::iter_origins`: only the last segment decides, a sequence contributes its last ASN,
/// a set contributes every member, and a confederation segment contributes nothing.
fn path_origin(mut body: &[u8]) -> Result<Option<Asn>, ()> {
    let mut last: Option<(u8, &[u8])> = None;
    while !body.is_empty() {
        if body.len() < 2 {
            return Err(());
        }
        let segment_type = body[0];
        let count = body[1] as usize;
        let len = count * 4;
        if !(1..=4).contains(&segment_type) || body.len() < 2 + len {
            return Err(());
        }
        last = Some((segment_type, &body[2..2 + len]));
        body = &body[2 + len..];
    }
    let Some((segment_type, members)) = last else {
        return Ok(None);
    };
    match segment_type {
        // AS_SEQUENCE: the origin is the last ASN.
        2 => Ok(members
            .as_chunks::<4>()
            .0
            .last()
            .map(|chunk| u32::from_be_bytes(*chunk).into())),
        // AS_SET: a single member is decisive, several are not worth deciding here.
        1 => {
            if members.len() == 4 {
                Ok(Some(
                    u32::from_be_bytes([members[0], members[1], members[2], members[3]]).into(),
                ))
            } else {
                Err(())
            }
        }
        // Confederations never contribute an origin.
        3 | 4 => Ok(None),
        _ => Err(()),
    }
}

/// The rendered element list of a 4-byte `AS_PATH`, with `None` for a set.
///
/// The path renders as its segments joined by single spaces: a sequence as space-separated ASNs and a
/// set as `{a,b}`. A needle made of ASNs and spaces therefore only lines up with sequence members.
fn path_elements(body: &[u8]) -> Result<SmallVec<[Option<u32>; 32]>, ()> {
    let mut elements: SmallVec<[Option<u32>; 32]> = SmallVec::new();
    let mut rest = body;
    while !rest.is_empty() {
        if rest.len() < 2 {
            return Err(());
        }
        let segment_type = rest[0];
        let count = rest[1] as usize;
        // An empty segment still renders its separator, which shifts every later position.
        if count == 0 {
            return Err(());
        }
        let len = count * 4;
        if rest.len() < 2 + len {
            return Err(());
        }
        let members = &rest[2..2 + len];
        match segment_type {
            // AS_SEQUENCE and AS_CONFED_SEQUENCE render as space-separated ASNs.
            2 | 3 => {
                for chunk in members.as_chunks::<4>().0 {
                    if elements.len() == elements.capacity() {
                        return Err(());
                    }
                    elements.push(Some(u32::from_be_bytes(*chunk)));
                }
            }
            // AS_SET and AS_CONFED_SET render as one `{...}` element.
            1 | 4 => {
                if elements.len() == elements.capacity() {
                    return Err(());
                }
                elements.push(None);
            }
            _ => return Err(()),
        }
        rest = &rest[2 + len..];
    }
    Ok(elements)
}

fn path_matches(body: &[u8], asn: u32, at_start: bool, at_end: bool) -> Result<bool, ()> {
    Ok(positions_match(
        &path_elements(body)?,
        asn,
        at_start,
        at_end,
    ))
}

/// The position rule both the byte walk and the decoded path share.
///
/// A needle that ends in a space needs an element after the match, and one that starts with a space
/// needs an element before it, so a single-element path only answers the `^N$` shape.
fn positions_match(elements: &[Option<u32>], asn: u32, at_start: bool, at_end: bool) -> bool {
    let (Some(first), Some(last)) = (elements.first(), elements.last()) else {
        return false;
    };
    let matches = |element: &Option<u32>| *element == Some(asn);
    match (at_start, at_end) {
        (true, true) => elements.len() == 1 && matches(first),
        (true, false) => elements.len() > 1 && matches(first),
        (false, true) => elements.len() > 1 && matches(last),
        (false, false) => elements.len() > 2 && elements[1..elements.len() - 1].iter().any(matches),
    }
}

/// A per-entry screen derived from a filter set, applied before an element is built.
///
/// It is deliberately pessimistic: an entry is dropped only when one conjunct is certain to fail for
/// its decoded attributes, and every other entry goes on to be built and filtered as before.
pub(crate) struct EntryScreen {
    predicates: SmallVec<[AttrPredicate; 4]>,
}

impl EntryScreen {
    pub(crate) fn new(filters: &[Filter]) -> Option<Self> {
        let predicates: SmallVec<[AttrPredicate; 4]> =
            filters.iter().filter_map(predicate_for).collect();
        (!predicates.is_empty()).then_some(EntryScreen { predicates })
    }

    /// The same answer from the entry's raw attribute block, for the borrowed path.
    pub(crate) fn admits_bytes(&self, attrs: &[u8]) -> bool {
        let facts = read_entry(attrs);
        if facts.truncated {
            return true;
        }
        self.predicates
            .iter()
            .all(|predicate| entry_satisfies(&facts, predicate) != Some(false))
    }
}

fn community_matches(body: &[u8], asn: u16, value: Option<u16>) -> bool {
    body.as_chunks::<4>().0.iter().any(|chunk| {
        read_u16(chunk) == asn && value.is_none_or(|wanted| wanted == read_u16(&chunk[2..]))
    })
}

/// A large community renders as `global_admin:local:local`, so an anchored `^ASN:` pattern matches
/// exactly when the global administrator is that ASN.
fn large_community_matches(body: &[u8], asn: u16) -> bool {
    body.as_chunks::<12>()
        .0
        .iter()
        .any(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) == asn as u32)
}

/// Read a filter into a predicate this module can decide, when it recognises the shape.
pub(crate) fn predicate_for(filter: &Filter) -> Option<AttrPredicate> {
    match filter {
        Filter::OriginAsn(asn) => Some(AttrPredicate::OriginAsn(*asn)),
        Filter::OriginAsns(asns) => Some(AttrPredicate::OriginAsns(asns.clone())),
        Filter::Origin(origin) => Some(AttrPredicate::OriginValue(*origin)),
        Filter::Community(regex) => parse_community_pattern(regex.pattern()),
        Filter::AsPath(regex) => parse_path_pattern(regex.pattern()),
        _ => None,
    }
}

/// Recognise the anchored forms only: an unanchored pattern may match part of a longer number or of
/// a large community, which this module does not model.
fn parse_community_pattern(pattern: &str) -> Option<AttrPredicate> {
    let rest = pattern.strip_prefix('^')?;
    if let Some(number) = rest.strip_suffix('$') {
        let (asn, value) = number.split_once(':')?;
        if !digits(asn) || !digits(value) {
            return None;
        }
        Some(AttrPredicate::CommunityExact {
            asn: asn.parse().ok()?,
            value: value.parse().ok()?,
        })
    } else {
        let asn = rest.strip_suffix(':')?;
        if !digits(asn) {
            return None;
        }
        Some(AttrPredicate::CommunityAsn {
            asn: asn.parse().ok()?,
        })
    }
}

fn digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Recognise a single-ASN needle whose both ends are pinned to an anchor or a space and nothing else,
/// which is what makes a token comparison reproduce the regex on the rendered path.
fn parse_path_pattern(pattern: &str) -> Option<AttrPredicate> {
    let mut rest = pattern;
    let anchored_start = rest.starts_with('^');
    if anchored_start {
        rest = &rest[1..];
    }
    let anchored_end = rest.ends_with('$');
    if anchored_end {
        rest = &rest[..rest.len() - 1];
    }
    let (leading_space, rest) = match rest.strip_prefix(' ') {
        Some(tail) => (true, tail),
        None => (false, rest),
    };
    let (trailing_space, number) = match rest.strip_suffix(' ') {
        Some(head) => (true, head),
        None => (false, rest),
    };
    if (leading_space && anchored_start) || (trailing_space && anchored_end) {
        return None;
    }
    if !(leading_space || anchored_start) || !(trailing_space || anchored_end) {
        return None;
    }
    if !digits(number) {
        return None;
    }
    Some(AttrPredicate::PathAsn {
        asn: number.parse().ok()?,
        at_start: anchored_start,
        at_end: anchored_end,
    })
}

/// Whether one entry satisfies one predicate: `Some(true)`, `Some(false)`, or `None` for undecidable.
fn entry_satisfies(facts: &EntryFacts<'_>, predicate: &AttrPredicate) -> Option<bool> {
    if facts.truncated {
        return None;
    }
    match predicate {
        AttrPredicate::OriginAsn(asn) => {
            if facts.has_as4_path {
                return None;
            }
            Some(path_origin(facts.path?).ok()? == Some((*asn).into()))
        }
        AttrPredicate::OriginAsns(asns) => {
            if facts.has_as4_path {
                return None;
            }
            let origin = path_origin(facts.path?).ok()?;
            Some(origin.is_some_and(|origin| asns.iter().any(|asn| Asn::from(*asn) == origin)))
        }
        AttrPredicate::OriginValue(origin) => Some(facts.origin_at == Some(*origin as u8)),
        // A two-field exact pattern cannot be satisfied by a large (three fields) or extended
        // (four fields) community, so those attributes do not affect the answer.
        AttrPredicate::CommunityExact { asn, value } => {
            if facts.duplicate_community {
                return None;
            }
            Some(
                facts
                    .communities
                    .is_some_and(|body| community_matches(body, *asn, Some(*value))),
            )
        }
        AttrPredicate::CommunityAsn { asn } => {
            if facts.duplicate_community {
                return None;
            }
            let plain = facts
                .communities
                .is_some_and(|body| community_matches(body, *asn, None));
            let large = facts
                .large_communities
                .is_some_and(|body| large_community_matches(body, *asn));
            // An extended community renders as `type:subtype:global:local`, and its first field is
            // the community type as a small number, so a pattern above 255 can never match one.
            if *asn <= u8::MAX as u16 && facts.ext_communities.is_some() && !plain && !large {
                return None;
            }
            Some(plain || large)
        }
        AttrPredicate::PathAsn {
            asn,
            at_start,
            at_end,
        } => {
            if facts.has_as4_path {
                return None;
            }
            Some(path_matches(facts.path?, *asn, *at_start, *at_end).ok()?)
        }
    }
}

/// Where a `BGP4MP` UPDATE record keeps its path attributes, or `None` when this module should not
/// guess. Only the fixed header and the two length prefixes are walked; nothing is decoded.
fn bgp4mp_attributes(body: &[u8], subtype: u16) -> Option<&[u8]> {
    let asn_len = match crate::parser::mrt::frame::bgp4mp_asn_len(subtype)? {
        crate::models::AsnLength::Bits16 => 2,
        crate::models::AsnLength::Bits32 => 4,
    };
    let mut rest = body.get(asn_len * 2..)?;
    if rest.len() < 4 {
        return None;
    }
    let ip_len = match u16::from_be_bytes([rest[2], rest[3]]) {
        1 => 4,
        2 => 16,
        _ => return None,
    };
    rest = rest.get(4 + ip_len * 2..)?;
    // The BGP message: 16-byte marker, two-byte length, one-byte type.
    if rest.len() < 19 || rest[18] != 2 {
        return None;
    }
    rest = &rest[19..];
    if rest.len() < 2 {
        return None;
    }
    let withdrawn_len = read_u16(rest) as usize;
    rest = rest.get(2 + withdrawn_len..)?;
    if rest.len() < 2 {
        return None;
    }
    let attr_len = read_u16(rest) as usize;
    rest.get(2..2 + attr_len)
}

/// Whether a `BGP4MP` UPDATE record provably yields no element that any of `filters` would keep.
///
/// Every element such a record yields shares one attribute block, so one decision covers the record.
/// Withdrawals carry no attributes and therefore fail an attribute predicate as well, which is what
/// makes the record-level answer safe.
pub(crate) fn bgp4mp_record_excluded(filters: &[Filter], body: &[u8], subtype: u16) -> bool {
    let predicates: SmallVec<[AttrPredicate; 4]> =
        filters.iter().filter_map(predicate_for).collect();
    if predicates.is_empty() {
        return false;
    }
    // A record whose AS numbers are two bytes wide carries a two-byte AS_PATH; this module reads the
    // four-byte form, so the path-based predicates are left to the general path there.
    let four_byte_asns = matches!(
        crate::parser::mrt::frame::bgp4mp_asn_len(subtype),
        Some(crate::models::AsnLength::Bits32)
    );
    let Some(attrs) = bgp4mp_attributes(body, subtype) else {
        return false;
    };
    let facts = read_entry(attrs);
    if facts.truncated {
        return false;
    }
    predicates.iter().any(|predicate| {
        let reads_path = matches!(
            predicate,
            AttrPredicate::OriginAsn(_)
                | AttrPredicate::OriginAsns(_)
                | AttrPredicate::PathAsn { .. }
        );
        if reads_path && !four_byte_asns {
            return false;
        }
        entry_satisfies(&facts, predicate) == Some(false)
    })
}

/// Whether a RIB record provably yields no element that any of `filters` would keep.
///
/// `false` is the answer whenever the record cannot be decided, so callers may skip the record on
/// `true` and parse it otherwise.
pub(crate) fn rib_record_excluded(
    filters: &[Filter],
    body: &[u8],
    entries_offset: usize,
    flags: u8,
) -> bool {
    let predicates: SmallVec<[AttrPredicate; 4]> =
        filters.iter().filter_map(predicate_for).collect();
    if predicates.is_empty() {
        return false;
    }
    // 0 = no entry matched yet, 1 = an entry matched, 2 = an entry could not be decided.
    let mut state: SmallVec<[u8; 4]> = SmallVec::from_elem(0, predicates.len());

    let head = if flags & FLAG_ADD_PATH != 0 { 12 } else { 8 };
    let mut rest = body.get(entries_offset..).unwrap_or(&[]);
    while !rest.is_empty() {
        if rest.len() < head {
            return false;
        }
        let attr_len = read_u16(&rest[head - 2..]) as usize;
        if rest.len() < head + attr_len {
            return false;
        }
        let facts = read_entry(&rest[head..head + attr_len]);
        if facts.truncated {
            return false;
        }
        for (index, predicate) in predicates.iter().enumerate() {
            match entry_satisfies(&facts, predicate) {
                Some(true) => state[index] = 1,
                Some(false) => {}
                None if state[index] != 1 => state[index] = 2,
                None => {}
            }
        }
        rest = &rest[head + attr_len..];
    }
    // A record is skipped only when one conjunct is certain to fail for every entry it has.
    state.contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ComparableRegex;

    /// A well-formed attribute block with the given TLVs.
    fn attrs(items: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (attr_type, body) in items {
            out.push(0x40);
            out.push(*attr_type);
            out.push(body.len() as u8);
            out.extend_from_slice(body);
        }
        out
    }

    fn as_path(segments: &[(u8, &[u32])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (segment_type, asns) in segments {
            out.push(*segment_type);
            out.push(asns.len() as u8);
            for asn in *asns {
                out.extend_from_slice(&asn.to_be_bytes());
            }
        }
        out
    }

    #[test]
    fn sequence_origin_is_the_last_asn() {
        let path = as_path(&[(2, &[64512, 174, 15169])]);
        let block = attrs(&[(1, &[0]), (2, &path)]);
        let facts = read_entry(&block);
        assert_eq!(path_origin(facts.path.unwrap()), Ok(Some(15169u32.into())));
        assert_eq!(facts.origin_at, Some(0));
    }

    #[test]
    fn several_sequences_use_the_last_segment() {
        let path = as_path(&[(2, &[64512, 174]), (2, &[3356, 15169])]);
        assert_eq!(path_origin(&path), Ok(Some(15169u32.into())));
    }

    #[test]
    fn a_single_member_set_is_decided_and_a_multi_member_set_is_not() {
        let single = as_path(&[(2, &[64512]), (1, &[15169])]);
        assert_eq!(path_origin(&single), Ok(Some(15169u32.into())));
        let multi = as_path(&[(2, &[64512]), (1, &[15169, 13335])]);
        assert_eq!(path_origin(&multi), Err(()));
    }

    #[test]
    fn confederation_segments_contribute_no_origin() {
        let path = as_path(&[(2, &[64512]), (3, &[65001])]);
        assert_eq!(path_origin(&path), Ok(None));
    }

    /// A BGP4MP record whose AS numbers are two bytes wide carries a two-byte AS_PATH. Reading it
    /// with the four-byte layout invents an origin, so the path predicates must bow out while the
    /// predicates that never touch the path keep deciding.
    #[test]
    fn two_byte_bgp4mp_records_are_undecidable_for_path_predicates() {
        use crate::models::Bgp4MpType;

        // Envelope: peer AS 64512, local AS 64513, interface index, AFI 1, two IPv4 addresses.
        let mut body = Vec::new();
        body.extend_from_slice(&64512u16.to_be_bytes());
        body.extend_from_slice(&64513u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[192, 0, 2, 1]);
        body.extend_from_slice(&[192, 0, 2, 2]);
        // A BGP UPDATE: ORIGIN IGP, AS_PATH `3356 13335` in two-byte form, one IPv4 NLRI.
        body.extend_from_slice(&[0xFF; 16]);
        // 19 header octets plus 21 of UPDATE: two length fields, thirteen attribute octets, one NLRI.
        body.extend_from_slice(&40u16.to_be_bytes());
        body.push(2);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&13u16.to_be_bytes());
        body.extend_from_slice(&[0x40, 1, 1, 0]);
        body.extend_from_slice(&[0x40, 2, 6, 2, 2]);
        body.extend_from_slice(&3356u16.to_be_bytes());
        body.extend_from_slice(&13335u16.to_be_bytes());
        body.extend_from_slice(&[24, 203, 0, 113]);

        // Read as four-byte ASNs the path is one ASN, 3356 << 16 | 13335, so a four-byte reading
        // would exclude this record for AS3356.
        assert!(
            !bgp4mp_record_excluded(
                &[Filter::OriginAsn(3356)],
                &body,
                Bgp4MpType::Message as u16
            ),
            "a two-byte record must not be excluded on a path predicate"
        );
        // The community predicate reads no path at all and still decides: no community matches.
        assert!(bgp4mp_record_excluded(
            &[Filter::Community(ComparableRegex::new("^3356:").unwrap())],
            &body,
            Bgp4MpType::Message as u16
        ));
    }

    /// A valid attribute followed by a malformed duplicate keeps its value on the owned path: the
    /// duplicate becomes raw bytes and the earlier parse stands. The byte scan must agree.
    #[test]
    fn a_malformed_duplicate_does_not_overwrite_a_valid_origin() {
        let block = attrs(&[(1, &[0]), (1, &[99])]);
        let facts = read_entry(&block);
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::OriginValue(Origin::IGP)),
            Some(true)
        );
    }

    /// Same shape for the AS path: an invalid segment in a later duplicate must not replace the
    /// path that decides the origin.
    #[test]
    fn a_malformed_duplicate_does_not_overwrite_a_valid_as_path() {
        let valid = as_path(&[(2, &[13335])]);
        let mut malformed = vec![9u8, 0];
        malformed.extend_from_slice(&[2u8, 1]);
        malformed.extend_from_slice(&64512u32.to_be_bytes());
        let block = attrs(&[(2, &valid), (2, &malformed)]);
        let facts = read_entry(&block);
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::OriginAsn(13335)),
            Some(true)
        );
    }

    /// An empty AS_PATH segment still renders a separator, so the rendered positions no longer
    /// line up with the elements; the module must decline instead of answering.
    #[test]
    fn empty_path_segments_are_undecidable() {
        let block = attrs(&[(2, &as_path(&[(2, &[] as &[u32]), (2, &[174, 3356, 15169])]))]);
        let facts = read_entry(&block);
        assert!(!facts.truncated);
        let needle = AttrPredicate::PathAsn {
            asn: 3356,
            at_start: false,
            at_end: false,
        };
        assert_eq!(entry_satisfies(&facts, &needle), None);
    }

    /// The owned path merges every COMMUNITIES attribute into one list; one slice cannot say
    /// whether an earlier attribute would have matched, so a duplicate makes the answer uncertain.
    #[test]
    fn duplicate_community_attributes_are_undecidable() {
        let first = 65000u32 << 16 | 1;
        let second = 65000u32 << 16 | 2;
        let block = attrs(&[(8, &first.to_be_bytes()), (8, &second.to_be_bytes())]);
        let facts = read_entry(&block);
        let needle = AttrPredicate::CommunityExact {
            asn: 65000,
            value: 2,
        };
        assert_eq!(entry_satisfies(&facts, &needle), None);
    }

    /// Attribute 25 is the IPv6 address-specific extended community: it renders with a leading
    /// type field, so an anchored `^N:` pattern can match it and it must not be ignored.
    #[test]
    fn ipv6_extended_communities_count_for_community_predicates() {
        let block = attrs(&[(25, &[0, 0, 0, 0, 0, 0, 0, 1])]);
        let facts = read_entry(&block);
        let needle = AttrPredicate::CommunityAsn { asn: 0 };
        // Not `Some(false)`: a record carrying only attribute 25 could still satisfy `^0:`.
        assert_ne!(entry_satisfies(&facts, &needle), Some(false));
    }

    #[test]
    fn as4_path_and_truncation_are_undecidable() {
        let path = as_path(&[(2, &[64512, 15169])]);
        let block = attrs(&[(2, &path), (17, &path)]);
        let facts = read_entry(&block);
        assert!(facts.has_as4_path);
        let facts = read_entry(&path[..path.len() - 1]);
        assert!(facts.truncated);
    }

    #[test]
    fn empty_and_missing_paths_have_no_origin() {
        assert_eq!(path_origin(&[]), Ok(None));
        assert_eq!(path_origin(&as_path(&[(2, &[])])), Ok(None));
    }

    /// A dump record: one prefix header, then entries that each carry their own attributes.
    fn rib_body(prefix: &[u8], entries: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 1];
        body.extend_from_slice(prefix);
        body.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for attrs in entries {
            body.extend_from_slice(&0u16.to_be_bytes());
            body.extend_from_slice(&1_700_000_000u32.to_be_bytes());
            body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
            body.extend_from_slice(attrs);
        }
        body
    }

    #[test]
    fn a_record_is_excluded_only_when_no_entry_matches() {
        let offset = 4 + 1 + 3 + 2;
        let matching = attrs(&[(2, &as_path(&[(2, &[174, 15169])]))]);
        let other = attrs(&[(2, &as_path(&[(2, &[174, 3356])]))]);
        let filters = [Filter::OriginAsn(15169)];

        let one = rib_body(&[24, 8, 8, 8], std::slice::from_ref(&other));
        assert!(rib_record_excluded(&filters, &one, offset, 0));

        let two = rib_body(&[24, 8, 8, 8], &[other, matching.clone()]);
        assert!(!rib_record_excluded(&filters, &two, offset, 0));

        let three = rib_body(&[24, 8, 8, 8], &[matching]);
        assert!(!rib_record_excluded(&filters, &three, offset, 0));
    }

    #[test]
    fn an_undecidable_entry_prevents_exclusion() {
        let offset = 4 + 1 + 3 + 2;
        let other = attrs(&[(2, &as_path(&[(2, &[174, 3356])]))]);
        let undecidable = attrs(&[(2, &as_path(&[(2, &[174]), (1, &[15169, 13335])]))]);
        let filters = [Filter::OriginAsn(15169)];
        let body = rib_body(&[24, 8, 8, 8], &[other, undecidable]);
        assert!(!rib_record_excluded(&filters, &body, offset, 0));
    }

    /// The prefilter decides whole records, so the only acceptable outcome is the same element
    /// stream the element-level origin test produces. The reference side runs unfiltered, which
    /// takes the framing path that never consults this module.
    #[test]
    fn origin_prefilter_matches_the_element_level_semantics() {
        use crate::models::Origin;
        use crate::parser::BgpkitParser;

        let fixture = "tests/fixtures/routeviews/bview.slice.gz";
        let all: Vec<crate::models::BgpElem> = BgpkitParser::new(fixture)
            .expect("open fixture")
            .into_elem_iter()
            .collect();
        assert!(all.len() > 10_000, "fixture should hold a real slice");

        let expected_for = |predicate: &dyn Fn(&crate::models::BgpElem) -> bool| -> Vec<_> {
            all.iter().filter(|elem| predicate(elem)).cloned().collect()
        };

        for asn in [15169u32, 13335, 3356, 174, 64073, 9999] {
            let expected = expected_for(&|elem| {
                elem.origin_asns
                    .as_ref()
                    .is_some_and(|origins| origins.contains(&asn.into()))
            });
            let actual: Vec<_> = BgpkitParser::new(fixture)
                .expect("open fixture")
                .add_filters(&[crate::Filter::OriginAsn(asn)])
                .into_elem_iter()
                .collect();
            assert_eq!(expected, actual, "origin_asn {asn} diverged");
        }

        for origin in [Origin::IGP, Origin::INCOMPLETE] {
            let expected = expected_for(&|elem| elem.origin == Some(origin));
            let actual: Vec<_> = BgpkitParser::new(fixture)
                .expect("open fixture")
                .add_filters(&[crate::Filter::Origin(origin)])
                .into_elem_iter()
                .collect();
            assert_eq!(expected, actual, "origin {origin} diverged");
        }

        // A community pattern in the anchored shape this module decides.
        for asn in [3356u16, 15169, 13335, 1] {
            let pattern = format!("^{asn}:");
            let expected = expected_for(&|elem| {
                elem.communities.as_ref().is_some_and(|list| {
                    list.iter()
                        .any(|community| community.to_string().starts_with(&format!("{asn}:")))
                })
            });
            let actual: Vec<_> = BgpkitParser::new(fixture)
                .expect("open fixture")
                .add_filters(&[crate::Filter::Community(
                    crate::ComparableRegex::new(&pattern).unwrap(),
                )])
                .into_elem_iter()
                .collect();
            assert_eq!(expected, actual, "community {pattern} diverged");
        }

        // A single-ASN AS path needle pinned by spaces on both sides.
        for asn in [3356u32, 15169, 174] {
            let pattern = format!(" {asn} ");
            let expected = expected_for(&|elem| {
                elem.as_path
                    .as_ref()
                    .is_some_and(|path| path.to_string().contains(&pattern))
            });
            let actual: Vec<_> = BgpkitParser::new(fixture)
                .expect("open fixture")
                .add_filters(&[crate::Filter::AsPath(
                    crate::ComparableRegex::new(&pattern).unwrap(),
                )])
                .into_elem_iter()
                .collect();
            assert_eq!(expected, actual, "as path {pattern} diverged");
        }

        // Two conjuncts at once, to check that neither is narrowed by the other.
        let expected = expected_for(&|elem| {
            elem.origin_asns
                .as_ref()
                .is_some_and(|origins| origins.contains(&15169u32.into()))
                && elem.communities.as_ref().is_some_and(|list| {
                    list.iter()
                        .any(|community| community.to_string().starts_with("15169:"))
                })
        });
        let actual: Vec<_> = BgpkitParser::new(fixture)
            .expect("open fixture")
            .add_filters(&[
                crate::Filter::OriginAsn(15169),
                crate::Filter::Community(crate::ComparableRegex::new("^15169:").unwrap()),
            ])
            .into_elem_iter()
            .collect();
        assert_eq!(expected, actual, "combined filters diverged");
    }

    #[test]
    fn filters_this_module_does_not_decide_never_exclude() {
        let offset = 4 + 1 + 3 + 2;
        let body = rib_body(
            &[24, 8, 8, 8],
            &[attrs(&[(2, &as_path(&[(2, &[174, 3356])]))])],
        );
        assert!(!rib_record_excluded(&[], &body, offset, 0));
        assert!(!rib_record_excluded(
            &[Filter::PeerAsn(64512)],
            &body,
            offset,
            0
        ));
        // An unanchored community pattern is not decided here.
        let filters = [Filter::Community(ComparableRegex::new("15169:").unwrap())];
        assert!(!rib_record_excluded(&filters, &body, offset, 0));
    }

    /// A BGP4MP UPDATE body: peer 65001, local 65002, IPv4, then one announced /24 with attributes.
    fn bgp4mp_update(attrs: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&65001u32.to_be_bytes());
        body.extend_from_slice(&65002u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[10, 0, 0, 1]);
        body.extend_from_slice(&[10, 0, 0, 2]);
        // BGP header: marker, length, type = UPDATE
        body.extend_from_slice(&[0xff; 16]);
        body.extend_from_slice(&(19u16 + 2 + 2 + attrs.len() as u16 + 4).to_be_bytes());
        body.push(2);
        // withdrawn routes: none
        body.extend_from_slice(&0u16.to_be_bytes());
        // path attributes
        body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        body.extend_from_slice(attrs);
        // NLRI: 8.8.8.0/24
        body.extend_from_slice(&[24, 8, 8, 8]);
        body
    }

    #[test]
    fn a_bgp4mp_update_locates_its_attributes() {
        let attrs = attrs(&[(2, &as_path(&[(2, &[174, 15169])]))]);
        let body = bgp4mp_update(&attrs);
        // 0x0004 is BGP4MP_MESSAGE_AS4.
        let located = bgp4mp_attributes(&body, 4).expect("attributes located");
        assert_eq!(located, attrs.as_slice());
        assert!(!bgp4mp_record_excluded(
            &[Filter::OriginAsn(15169)],
            &body,
            4
        ));
        assert!(bgp4mp_record_excluded(&[Filter::OriginAsn(3356)], &body, 4));
        // A subtype whose layout this module does not model stays undecided, and so does a body
        // whose header does not line up with the subtype's widths.
        assert!(bgp4mp_attributes(&body, 99).is_none());
        assert!(!bgp4mp_record_excluded(
            &[Filter::OriginAsn(3356)],
            &body,
            99
        ));
        assert!(
            bgp4mp_attributes(&body, 6).is_none(),
            "2-byte header against a 4-byte body"
        );
    }

    #[test]
    fn community_patterns_are_only_recognised_when_anchored() {
        assert_eq!(
            parse_community_pattern("^15169:"),
            Some(AttrPredicate::CommunityAsn { asn: 15169 })
        );
        assert_eq!(
            parse_community_pattern("^15169:1$"),
            Some(AttrPredicate::CommunityExact {
                asn: 15169,
                value: 1
            })
        );
        assert_eq!(parse_community_pattern("15169:"), None);
        assert_eq!(parse_community_pattern("^15169:.*"), None);
        assert_eq!(parse_community_pattern("^no-export$"), None);
    }

    #[test]
    fn path_patterns_need_both_ends_pinned() {
        assert_eq!(
            parse_path_pattern(" 3356 "),
            Some(AttrPredicate::PathAsn {
                asn: 3356,
                at_start: false,
                at_end: false
            })
        );
        assert_eq!(
            parse_path_pattern("^3356 "),
            Some(AttrPredicate::PathAsn {
                asn: 3356,
                at_start: true,
                at_end: false
            })
        );
        assert_eq!(
            parse_path_pattern(" 3356$"),
            Some(AttrPredicate::PathAsn {
                asn: 3356,
                at_start: false,
                at_end: true
            })
        );
        // A bare number can match part of a longer ASN, and a multi-ASN needle spans elements.
        assert_eq!(parse_path_pattern("3356"), None);
        assert_eq!(parse_path_pattern("174 3356"), None);
        assert_eq!(parse_path_pattern(" ?174 1916$"), None);
    }

    #[test]
    fn path_positions_follow_the_rendered_string() {
        let needle = AttrPredicate::PathAsn {
            asn: 3356,
            at_start: false,
            at_end: false,
        };
        let satisfied = |segments: &[(u8, &[u32])]| {
            let block = attrs(&[(2, &as_path(segments))]);
            let facts = read_entry(&block);
            assert!(!facts.truncated);
            entry_satisfies(&facts, &needle)
        };
        // Middle of a three-ASN path matches.
        assert_eq!(satisfied(&[(2, &[174, 3356, 15169])]), Some(true));
        // First and last do not: the needle is pinned by spaces on both sides.
        assert_eq!(satisfied(&[(2, &[3356, 15169])]), Some(false));
        assert_eq!(satisfied(&[(2, &[174, 3356])]), Some(false));
        // A set renders as one element, so a member never lines up with the needle.
        assert_eq!(
            satisfied(&[(2, &[174]), (1, &[3356, 15169]), (2, &[1])]),
            Some(false)
        );
        // A one-sided needle still needs something on both sides of the element.
        let anchored = |at_start: bool, at_end: bool| {
            entry_satisfies(
                &read_entry(&attrs(&[(2, &as_path(&[(2, &[3356])]))])),
                &AttrPredicate::PathAsn {
                    asn: 3356,
                    at_start,
                    at_end,
                },
            )
        };
        assert_eq!(anchored(true, true), Some(true));
        assert_eq!(anchored(true, false), Some(false));
        assert_eq!(anchored(false, true), Some(false));
        assert_eq!(
            entry_satisfies(
                &read_entry(&attrs(&[(2, &as_path(&[(2, &[3356, 15169])]))])),
                &AttrPredicate::PathAsn {
                    asn: 3356,
                    at_start: true,
                    at_end: false
                }
            ),
            Some(true)
        );
    }

    #[test]
    fn community_predicates_need_plain_communities_only() {
        let plain = attrs(&[(8, &communities(&[(15169, 0), (3356, 100)]))]);
        let facts = read_entry(&plain);
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::CommunityAsn { asn: 15169 }),
            Some(true)
        );
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::CommunityAsn { asn: 13335 }),
            Some(false)
        );
        assert_eq!(
            entry_satisfies(
                &facts,
                &AttrPredicate::CommunityExact {
                    asn: 15169,
                    value: 0
                }
            ),
            Some(true)
        );
        // A large community matches through its global administrator.
        // 15169 is 0x3B41, so the global administrator is 0x00003B41.
        let large = attrs(&[(32, &[0, 0, 0x3B, 0x41, 0, 0, 0, 2, 0, 0, 0, 3])]);
        let facts = read_entry(&large);
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::CommunityAsn { asn: 15169 }),
            Some(true)
        );
        // An extended community renders `type:subtype:global:local`, so a pattern at or below 255
        // could match it and the entry is not decided; above 255 it cannot and the answer is certain.
        let ext = attrs(&[(16, &[0, 2, 0, 2, 0, 0, 0, 1])]);
        let facts = read_entry(&ext);
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::CommunityAsn { asn: 15169 }),
            Some(false)
        );
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::CommunityAsn { asn: 2 }),
            None
        );
        // An exact two-field pattern can only ever match a plain community.
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::CommunityExact { asn: 2, value: 2 }),
            Some(false)
        );
    }

    #[test]
    fn conjuncts_are_decided_independently() {
        let offset = 4 + 1 + 3 + 2;
        // Entry one satisfies the origin, entry two satisfies the community, and no single element
        // satisfies both. Neither conjunct is certain to fail on its own, so the record is kept.
        let only_origin = attrs(&[
            (2, &as_path(&[(2, &[174, 15169])])),
            (8, &communities(&[(3356, 1)])),
        ]);
        let only_community = attrs(&[
            (2, &as_path(&[(2, &[174, 3356])])),
            (8, &communities(&[(15169, 1)])),
        ]);
        let both = attrs(&[
            (2, &as_path(&[(2, &[174, 15169])])),
            (8, &communities(&[(15169, 1)])),
        ]);
        let filters = [
            Filter::OriginAsn(15169),
            Filter::Community(ComparableRegex::new("^15169:").unwrap()),
        ];
        // One entry that satisfies only the origin fails the community conjunct, so the record
        // goes; the same holds for one entry that satisfies only the community.
        assert!(rib_record_excluded(
            &filters,
            &rib_body(&[24, 8, 8, 8], std::slice::from_ref(&only_origin)),
            offset,
            0
        ));
        assert!(rib_record_excluded(
            &filters,
            &rib_body(&[24, 8, 8, 8], std::slice::from_ref(&only_community)),
            offset,
            0
        ));
        // With both entries present, each conjunct is satisfied by some entry, and no element is
        // known to satisfy both; the record stays so the element filter can decide.
        assert!(!rib_record_excluded(
            &filters,
            &rib_body(&[24, 8, 8, 8], &[only_origin, only_community]),
            offset,
            0
        ));
        // An entry that satisfies both keeps the record on its own.
        assert!(!rib_record_excluded(
            &filters,
            &rib_body(&[24, 8, 8, 8], &[both]),
            offset,
            0
        ));
        // And a record with neither is skipped.
        let neither = attrs(&[
            (2, &as_path(&[(2, &[174, 3356])])),
            (8, &communities(&[(13335, 1)])),
        ]);
        assert!(rib_record_excluded(
            &filters,
            &rib_body(&[24, 8, 8, 8], &[neither]),
            offset,
            0
        ));
    }

    fn communities(items: &[(u16, u16)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (asn, value) in items {
            out.extend_from_slice(&asn.to_be_bytes());
            out.extend_from_slice(&value.to_be_bytes());
        }
        out
    }
}
