//! Byte-level pre-checks for filters that only need attribute bytes.
//!
//! An origin filter can only match an element whose AS path ends at the requested origin. A dump
//! record in which no entry can satisfy that yields no matching elements, so it can be skipped before
//! its body is parsed. Deciding this costs one walk over the TLV headers plus a comparison on the
//! values the predicate names, against a full attribute decode and an element construction per entry.
//!
//! Only shapes with a structural meaning are decided here: a path and an ORIGIN attribute have one,
//! while a community or AS path regular expression depends on how those values are written out, so
//! those filters are left to the general path.
//!
//! The one rule is that a reject must be certain: whenever this module cannot decide an entry it
//! reports that, and the caller parses the record the general way.

use crate::models::{Asn, Origin};
use crate::parser::mrt::frame::FLAG_ADD_PATH;
use crate::Filter;
use smallvec::SmallVec;

/// The predicates one record-level pass can decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttrPredicate {
    /// `origin_asn=N`
    Asn(u32),
    /// `origin_asns=N,M`
    Asns(Vec<u32>),
    /// `origin=igp|egp|incomplete`
    Value(Origin),
}

/// What one entry's attribute block says, as far as the predicates above need to know.
#[derive(Debug, Default)]
struct EntryFacts<'a> {
    origin_at: Option<u8>,
    path: Option<&'a [u8]>,
    /// `AS4_PATH` can replace the origin.
    has_as4_path: bool,
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
            17 => facts.has_as4_path = true,
            _ => {}
        }
        rest = &rest[header_len + body_len..];
    }
    facts
}

/// Whether a four-byte `AS_PATH` is well formed, by the rule the owned decoder applies.
///
/// The owned path rejects the whole attribute when any segment is invalid, so a malformed duplicate
/// must not replace a path this module already read.
fn path_validates(body: &[u8]) -> bool {
    crate::parser::bgp::attributes::validate_as_path_slice(body, &crate::models::AsnLength::Bits32)
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

/// Read a filter into a predicate this module can decide, when it recognises the shape.
pub(crate) fn predicate_for(filter: &Filter) -> Option<AttrPredicate> {
    match filter {
        Filter::OriginAsn(asn) => Some(AttrPredicate::Asn(*asn)),
        Filter::OriginAsns(asns) => Some(AttrPredicate::Asns(asns.clone())),
        Filter::Origin(origin) => Some(AttrPredicate::Value(*origin)),
        _ => None,
    }
}

/// Whether one entry satisfies one predicate: `Some(true)`, `Some(false)`, or `None` for undecidable.
fn entry_satisfies(facts: &EntryFacts<'_>, predicate: &AttrPredicate) -> Option<bool> {
    if facts.truncated {
        return None;
    }
    match predicate {
        AttrPredicate::Asn(asn) => {
            if facts.has_as4_path {
                return None;
            }
            Some(path_origin(facts.path?).ok()? == Some((*asn).into()))
        }
        AttrPredicate::Asns(asns) => {
            if facts.has_as4_path {
                return None;
            }
            let origin = path_origin(facts.path?).ok()?;
            Some(origin.is_some_and(|origin| asns.iter().any(|asn| Asn::from(*asn) == origin)))
        }
        AttrPredicate::Value(origin) => Some(facts.origin_at == Some(*origin as u8)),
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
    // A record whose AS numbers are two bytes wide also carries a two-byte AS_PATH; this module reads
    // the four-byte form, so an origin predicate is left to the general path there.
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
        if !four_byte_asns {
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

    #[test]
    fn empty_and_missing_paths_have_no_origin() {
        assert_eq!(path_origin(&[]), Ok(None));
        let block = attrs(&[(1, &[0])]);
        let facts = read_entry(&block);
        assert_eq!(entry_satisfies(&facts, &AttrPredicate::Asn(15169)), None);
    }

    /// A BGP4MP record whose AS numbers are two bytes wide carries a two-byte AS_PATH. Reading it
    /// with the four-byte layout invents an origin, so an origin predicate must bow out.
    #[test]
    fn two_byte_bgp4mp_records_are_undecidable_for_origin_predicates() {
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
            "a two-byte record must not be excluded on an origin predicate"
        );
    }

    /// A valid attribute followed by a malformed duplicate keeps its value on the owned path: the
    /// duplicate becomes raw bytes and the earlier parse stands. The byte scan must agree.
    #[test]
    fn a_malformed_duplicate_does_not_overwrite_a_valid_origin() {
        let block = attrs(&[(1, &[0]), (1, &[99])]);
        let facts = read_entry(&block);
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::Value(Origin::IGP)),
            Some(true)
        );
    }

    /// Same shape for the AS path: an invalid segment in a later duplicate must not replace the
    /// path that decides the origin, and `ORIGIN` still decides on its own.
    #[test]
    fn a_malformed_duplicate_does_not_overwrite_a_valid_as_path() {
        let valid = as_path(&[(2, &[13335])]);
        let mut malformed = vec![9u8, 0];
        malformed.extend_from_slice(&[2u8, 1]);
        malformed.extend_from_slice(&64512u32.to_be_bytes());
        let block = attrs(&[(2, &valid), (2, &malformed), (1, &[0])]);
        let facts = read_entry(&block);
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::Asn(13335)),
            Some(true)
        );
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::Value(Origin::IGP)),
            Some(true)
        );
    }

    #[test]
    fn as4_path_and_truncation_are_undecidable() {
        let path = as_path(&[(2, &[64512, 13335])]);
        let mut block = attrs(&[(1, &[0]), (2, &path), (17, &[0, 0, 0, 0])]);
        // `AS4_PATH` can replace the origin, so the answer is left to the general path.
        block.extend_from_slice(&[0x40, 8, 4, 0, 0, 0, 0]);
        assert_eq!(
            entry_satisfies(&read_entry(&block), &AttrPredicate::Asn(13335)),
            None
        );
        let mut short = attrs(&[(1, &[0])]);
        short.extend_from_slice(&[0x40, 2, 30]);
        assert!(read_entry(&short).truncated);
    }

    /// Nothing may be skipped when the filter set names no shape this module decides. A community or
    /// AS path expression is written out by the renderer, so those filters go down the general path.
    #[test]
    fn filters_this_module_does_not_decide_never_exclude() {
        use crate::ComparableRegex;

        let path = as_path(&[(2, &[64512, 3356])]);
        let block = attrs(&[(1, &[0]), (2, &path)]);
        for filter in [
            Filter::Community(ComparableRegex::new("^3356:").unwrap()),
            Filter::AsPath(ComparableRegex::new("^64512 ").unwrap()),
        ] {
            assert_eq!(predicate_for(&filter), None);
            let body = rib_body(&[203, 0, 113], std::slice::from_ref(&block));
            assert!(!rib_record_excluded(
                std::slice::from_ref(&filter),
                &body,
                4,
                0
            ));
        }
    }

    /// A RIB record is a prefix length followed by the prefix, then entries of
    /// `peer_index, originated_time, attr_len, attributes`.
    fn rib_body(prefix: &[u8], entries: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![(prefix.len() * 8) as u8];
        body.extend_from_slice(prefix);
        for (index, entry) in entries.iter().enumerate() {
            // Peer index (two bytes), originated time (four), attribute length (two).
            body.extend_from_slice(&(index as u16).to_be_bytes());
            body.extend_from_slice(&0u32.to_be_bytes());
            body.extend_from_slice(&(entry.len() as u16).to_be_bytes());
            body.extend_from_slice(entry);
        }
        body
    }

    #[test]
    fn a_record_is_excluded_only_when_no_entry_matches() {
        let matching = attrs(&[(1, &[0]), (2, &as_path(&[(2, &[64512, 15169])]))]);
        let other = attrs(&[(1, &[0]), (2, &as_path(&[(2, &[64512, 3356])]))]);
        let filters = [Filter::OriginAsn(15169)];
        let both = rib_body(&[203, 0, 113], &[other.clone(), matching]);
        assert!(!rib_record_excluded(&filters, &both, 4, 0));
        let only_other = rib_body(&[203, 0, 113], &[other]);
        assert!(rib_record_excluded(&filters, &only_other, 4, 0));
    }

    #[test]
    fn an_undecidable_entry_prevents_exclusion() {
        // A multi-member AS_SET leaves the origin open.
        let undecided = attrs(&[
            (1, &[0]),
            (2, &as_path(&[(2, &[64512]), (1, &[15169, 13335])])),
        ]);
        let other = attrs(&[(1, &[0]), (2, &as_path(&[(2, &[64512, 3356])]))]);
        let body = rib_body(&[203, 0, 113], &[other, undecided]);
        assert!(!rib_record_excluded(
            &[Filter::OriginAsn(15169)],
            &body,
            4,
            0
        ));
    }

    /// The byte-level answer must agree with what the element-level filters would decide.
    #[test]
    fn origin_prefilter_matches_the_element_level_semantics() {
        let igp_15169 = attrs(&[(1, &[0]), (2, &as_path(&[(2, &[64512, 174, 15169])]))]);
        let egp_3356 = attrs(&[(1, &[1]), (2, &as_path(&[(2, &[64512, 3356])]))]);
        let single_member_set = attrs(&[(1, &[0]), (2, &as_path(&[(2, &[64512]), (1, &[15169])]))]);
        // A confederation at the end leaves no origin, which is a fact: no origin filter can match.
        let confederation = attrs(&[(1, &[0]), (2, &as_path(&[(2, &[64512]), (3, &[65001])]))]);

        assert_eq!(
            entry_satisfies(&read_entry(&igp_15169), &AttrPredicate::Asn(15169)),
            Some(true)
        );
        assert_eq!(
            entry_satisfies(&read_entry(&egp_3356), &AttrPredicate::Asn(3356)),
            Some(true)
        );
        assert_eq!(
            entry_satisfies(
                &read_entry(&single_member_set),
                &AttrPredicate::Asns(vec![15169, 13335])
            ),
            Some(true)
        );
        assert_eq!(
            entry_satisfies(&read_entry(&confederation), &AttrPredicate::Asn(65001)),
            Some(false)
        );
        assert_eq!(
            entry_satisfies(&read_entry(&egp_3356), &AttrPredicate::Value(Origin::EGP)),
            Some(true)
        );
        assert_eq!(
            entry_satisfies(
                &read_entry(&igp_15169),
                &AttrPredicate::Value(Origin::INCOMPLETE)
            ),
            Some(false)
        );
    }

    #[test]
    fn conjuncts_are_decided_independently() {
        // Two origin conjuncts that cannot hold at once: each is decided on its own.
        let block = attrs(&[(1, &[0]), (2, &as_path(&[(2, &[64512, 15169])]))]);
        let facts = read_entry(&block);
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::Asn(3356)),
            Some(false)
        );
        assert_eq!(
            entry_satisfies(&facts, &AttrPredicate::Value(Origin::INCOMPLETE)),
            Some(false)
        );
    }
}
