//! Byte-level pre-checks for filters that need a single attribute.
//!
//! An origin filter can only match an element whose AS path ends at the requested origin, so a
//! dump record in which no entry has that origin yields no matching elements at all. Deciding that
//! from the attribute bytes costs one walk over the TLV headers, against a full attribute decode
//! plus an element construction per entry.
//!
//! The one rule here is that a reject must be certain: whenever this module cannot decide an
//! entry's origins it reports that, and the caller falls back to the general path.

use crate::models::Asn;
use crate::parser::mrt::frame::FLAG_ADD_PATH;
use crate::Filter;

/// The fields a record-level origin check needs from one attribute block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttrSummary {
    /// The last ASN of the path, when the path ends in a sequence.
    pub origin_asn: Option<Asn>,
    /// The raw `ORIGIN` attribute value.
    pub origin: Option<u8>,
}

/// Read the origin ASN and the `ORIGIN` attribute out of one 4-byte-ASN attribute block.
///
/// Returns `Err` when the block cannot be decided from the bytes alone: a truncated block, an
/// `AS4_PATH` that could replace the origin, or a path ending in a multi-member set.
pub(crate) fn scan_attributes(attrs: &[u8]) -> Result<AttrSummary, ()> {
    let mut rest = attrs;
    let mut summary = AttrSummary {
        origin_asn: None,
        origin: None,
    };
    while !rest.is_empty() {
        if rest.len() < 3 {
            return Err(());
        }
        let extended = rest[0] & 0x10 != 0;
        let attr_type = rest[1];
        let (header_len, body_len) = if extended {
            if rest.len() < 4 {
                return Err(());
            }
            (4, u16::from_be_bytes([rest[2], rest[3]]) as usize)
        } else {
            (3, rest[2] as usize)
        };
        if rest.len() < header_len + body_len {
            return Err(());
        }
        let body = &rest[header_len..header_len + body_len];
        match attr_type {
            1 => summary.origin = body.first().copied(),
            2 => summary.origin_asn = path_origin(body)?,
            // AS4_PATH carries the 4-byte complement of a 2-byte AS_PATH and can change the
            // origin; table dumps do not use it, so treat its presence as undecidable.
            17 => return Err(()),
            _ => {}
        }
        rest = &rest[header_len + body_len..];
    }
    Ok(summary)
}

/// The origin of a 4-byte `AS_PATH`: `Ok(None)` for a path that has none.
///
/// Mirrors `AsPath::iter_origins`: only the last segment decides, a sequence contributes its last
/// ASN, a set contributes every member, and a confederation segment contributes nothing.
fn path_origin(mut body: &[u8]) -> Result<Option<Asn>, ()> {
    let mut last: Option<(u8, &[u8])> = None;
    while !body.is_empty() {
        if body.len() < 2 {
            return Err(());
        }
        let segment_type = body[0];
        let count = body[1] as usize;
        let len = count * 4;
        if body.len() < 2 + len {
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

/// Walk the attribute blocks of a RIB record body, one per entry.
struct RibAttrs<'a> {
    rest: &'a [u8],
    add_path: bool,
}

impl<'a> RibAttrs<'a> {
    fn new(body: &'a [u8], entries_offset: usize, flags: u8) -> Self {
        RibAttrs {
            rest: body.get(entries_offset..).unwrap_or(&[]),
            add_path: flags & FLAG_ADD_PATH != 0,
        }
    }

    /// The next entry's attribute block, or `Err(())` when the layout stops making sense.
    fn next_attrs(&mut self) -> Result<Option<&'a [u8]>, ()> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let head = if self.add_path { 12 } else { 8 };
        if self.rest.len() < head {
            return Err(());
        }
        let attr_len = u16::from_be_bytes([self.rest[head - 2], self.rest[head - 1]]) as usize;
        if self.rest.len() < head + attr_len {
            return Err(());
        }
        let attrs = &self.rest[head..head + attr_len];
        self.rest = &self.rest[head + attr_len..];
        Ok(Some(attrs))
    }
}

/// Whether a RIB record provably yields no element that an origin filter would keep.
///
/// `false` is the answer whenever the record cannot be decided, so callers may skip the record on
/// `true` and parse it otherwise.
pub(crate) fn rib_record_excluded_by_origin(
    filters: &[Filter],
    body: &[u8],
    entries_offset: usize,
    flags: u8,
) -> bool {
    let mut decided_none = false;
    for filter in filters {
        let matched_any = match filter {
            Filter::OriginAsn(asn) => rib_has_origin(body, entries_offset, flags, |summary| {
                summary.origin_asn == Some((*asn).into())
            }),
            Filter::OriginAsns(asns) => rib_has_origin(body, entries_offset, flags, |summary| {
                summary
                    .origin_asn
                    .is_some_and(|origin| asns.iter().any(|asn| Asn::from(*asn) == origin))
            }),
            Filter::Origin(origin) => rib_has_origin(body, entries_offset, flags, |summary| {
                summary.origin == Some(*origin as u8)
            }),
            // Anything else is decided by the general path, including negated filters, whose
            // "every entry matches" shape is not what this helper answers.
            _ => None,
        };
        if matched_any == Some(false) {
            decided_none = true;
        }
    }
    decided_none
}

/// `Some(true)` when some entry satisfies `predicate`, `Some(false)` when none can, `None` when an
/// entry could not be decided.
fn rib_has_origin(
    body: &[u8],
    entries_offset: usize,
    flags: u8,
    predicate: impl Fn(&AttrSummary) -> bool,
) -> Option<bool> {
    let mut entries = RibAttrs::new(body, entries_offset, flags);
    loop {
        match entries.next_attrs() {
            Ok(Some(attrs)) => match scan_attributes(attrs) {
                Ok(summary) if predicate(&summary) => return Some(true),
                Ok(_) => {}
                Err(()) => return None,
            },
            Ok(None) => return Some(false),
            Err(()) => return None,
        }
    }
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
        let summary = scan_attributes(&block).expect("decidable");
        assert_eq!(summary.origin_asn, Some(15169u32.into()));
        assert_eq!(summary.origin, Some(0));
    }

    #[test]
    fn several_sequences_use_the_last_segment() {
        let path = as_path(&[(2, &[64512, 174]), (2, &[3356, 15169])]);
        let summary = scan_attributes(&attrs(&[(2, &path)])).expect("decidable");
        assert_eq!(summary.origin_asn, Some(15169u32.into()));
    }

    #[test]
    fn a_single_member_set_is_decided_and_a_multi_member_set_is_not() {
        let single = as_path(&[(2, &[64512]), (1, &[15169])]);
        assert_eq!(
            scan_attributes(&attrs(&[(2, &single)]))
                .expect("decidable")
                .origin_asn,
            Some(15169u32.into())
        );
        let multi = as_path(&[(2, &[64512]), (1, &[15169, 13335])]);
        assert!(scan_attributes(&attrs(&[(2, &multi)])).is_err());
    }

    #[test]
    fn confederation_segments_contribute_no_origin() {
        let path = as_path(&[(2, &[64512]), (3, &[65001])]);
        let summary = scan_attributes(&attrs(&[(2, &path)])).expect("decidable");
        assert_eq!(summary.origin_asn, None);
    }

    #[test]
    fn as4_path_and_truncation_are_undecidable() {
        let path = as_path(&[(2, &[64512, 15169])]);
        assert!(scan_attributes(&attrs(&[(2, &path), (17, &path)])).is_err());
        assert!(scan_attributes(&path[..path.len() - 1]).is_err());
    }

    #[test]
    fn empty_and_missing_paths_have_no_origin() {
        assert_eq!(
            scan_attributes(&attrs(&[])).expect("decidable").origin_asn,
            None
        );
        assert_eq!(
            scan_attributes(&attrs(&[(2, &[])]))
                .expect("decidable")
                .origin_asn,
            None
        );
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
        // /24: one length byte plus three octets.
        let offset = 4 + 1 + 3 + 2;
        let matching = attrs(&[(2, &as_path(&[(2, &[174, 15169])]))]);
        let other = attrs(&[(2, &as_path(&[(2, &[174, 3356])]))]);
        let filters = [Filter::OriginAsn(15169)];

        let one = rib_body(&[24, 8, 8, 8], std::slice::from_ref(&other));
        assert!(rib_record_excluded_by_origin(&filters, &one, offset, 0));

        let two = rib_body(&[24, 8, 8, 8], &[other.clone(), matching.clone()]);
        assert!(!rib_record_excluded_by_origin(&filters, &two, offset, 0));

        let three = rib_body(&[24, 8, 8, 8], &[matching]);
        assert!(!rib_record_excluded_by_origin(&filters, &three, offset, 0));
    }

    #[test]
    fn an_undecidable_entry_prevents_exclusion() {
        let offset = 4 + 1 + 3 + 2;
        let other = attrs(&[(2, &as_path(&[(2, &[174, 3356])]))]);
        let undecidable = attrs(&[(2, &as_path(&[(2, &[174]), (1, &[15169, 13335])]))]);
        let filters = [Filter::OriginAsn(15169)];
        let body = rib_body(&[24, 8, 8, 8], &[other, undecidable]);
        assert!(!rib_record_excluded_by_origin(&filters, &body, offset, 0));
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
    }

    #[test]
    fn filters_this_module_does_not_decide_never_exclude() {
        let offset = 4 + 1 + 3 + 2;
        let body = rib_body(
            &[24, 8, 8, 8],
            &[attrs(&[(2, &as_path(&[(2, &[174, 3356])]))])],
        );
        assert!(!rib_record_excluded_by_origin(&[], &body, offset, 0));
        assert!(!rib_record_excluded_by_origin(
            &[Filter::PeerAsn(64512)],
            &body,
            offset,
            0
        ));
    }
}
