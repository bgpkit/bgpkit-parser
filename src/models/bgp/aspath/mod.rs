use crate::models::*;
use itertools::Itertools;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::mem::discriminant;

pub mod iters;
pub use iters::*;

#[cfg(feature = "serde")]
mod serde_impl;

#[cfg(test)]
mod tests;

/// Enum of AS path segment.
#[derive(Debug, Clone)]
pub enum AsPathSegment<'a> {
    AsSequence(Cow<'a, [Asn]>),
    AsSet(Cow<'a, [Asn]>),
    ConfedSequence(Cow<'a, [Asn]>),
    ConfedSet(Cow<'a, [Asn]>),
}

impl AsPathSegment<'_> {
    pub fn borrowed(&self) -> AsPathSegment {
        match self {
            AsPathSegment::AsSequence(x) => AsPathSegment::AsSequence(Cow::Borrowed(&**x)),
            AsPathSegment::AsSet(x) => AsPathSegment::AsSet(Cow::Borrowed(&**x)),
            AsPathSegment::ConfedSequence(x) => AsPathSegment::ConfedSequence(Cow::Borrowed(&**x)),
            AsPathSegment::ConfedSet(x) => AsPathSegment::ConfedSet(Cow::Borrowed(&**x)),
        }
    }

    pub fn to_static_owned(&self) -> AsPathSegment<'static> {
        match self {
            AsPathSegment::AsSequence(x) => AsPathSegment::AsSequence(Cow::Owned(x.to_vec())),
            AsPathSegment::AsSet(x) => AsPathSegment::AsSet(Cow::Owned(x.to_vec())),
            AsPathSegment::ConfedSequence(x) => {
                AsPathSegment::ConfedSequence(Cow::Owned(x.to_vec()))
            }
            AsPathSegment::ConfedSet(x) => AsPathSegment::ConfedSet(Cow::Owned(x.to_vec())),
        }
    }

    /// Shorthand for creating an `AsSequence` segment.
    pub fn sequence<S: AsRef<[u32]>>(seq: S) -> Self {
        AsPathSegment::AsSequence(seq.as_ref().iter().copied().map_into().collect())
    }

    /// Shorthand for creating an `AsSet` segment.
    pub fn set<S: AsRef<[u32]>>(seq: S) -> Self {
        AsPathSegment::AsSet(seq.as_ref().iter().copied().map_into().collect())
    }

    /// Get the number of ASNs this segment adds to the route. For the number of ASNs within the
    /// segment use [AsPathSegment::len] instead.
    pub fn route_len(&self) -> usize {
        match self {
            AsPathSegment::AsSequence(v) => v.len(),
            AsPathSegment::AsSet(_) => 1,
            AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_) => 0,
        }
    }

    /// Ge the total number of ASNs within this segment. For the number of ASNs this segment adds to
    /// a packet's route, use [AsPathSegment::route_len] instead.
    pub fn len(&self) -> usize {
        self.as_ref().len()
    }

    /// Returns true if this segment has a length of 0.
    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }

    /// Gets if a segment represents the local members of an autonomous system confederation.
    /// Shorthand for `matches!(x, AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_))`.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc3065#section-5>
    pub fn is_confed(&self) -> bool {
        matches!(
            self,
            AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_)
        )
    }

    /// Merge two [AsPathSegment]s in place and return if the merge was successful.
    ///
    /// See [AsPath::coalesce] for more information.
    fn merge_in_place(&mut self, other: &mut Self) -> bool {
        use AsPathSegment::*;

        match (self, other) {
            (AsSequence(x), AsSequence(y)) | (ConfedSequence(x), ConfedSequence(y)) => {
                x.to_mut().extend_from_slice(y);
                true
            }
            (x @ (AsSequence(_) | ConfedSequence(_)), y) if x.is_empty() => {
                std::mem::swap(x, y);
                true
            }
            (_, AsSequence(y) | ConfedSequence(y)) if y.is_empty() => true,
            _ => false,
        }
    }

    /// A much more aggressive version of [AsPathSegment::merge_in_place] which de-duplicates and
    /// converts sets with only 1 ASN to sequences.
    ///
    /// See [AsPath::dedup_coalesce] for more information.
    fn dedup_merge_in_place(&mut self, other: &mut Self) -> bool {
        use AsPathSegment::*;

        other.dedup();
        match (self, other) {
            (AsSequence(x), AsSequence(y)) | (ConfedSequence(x), ConfedSequence(y)) => {
                let x_mut = x.to_mut();
                x_mut.extend_from_slice(y);
                x_mut.dedup();
                true
            }
            (x @ (AsSequence(_) | ConfedSequence(_)), y) if x.is_empty() => {
                std::mem::swap(x, y);
                true
            }
            (_, AsSequence(y) | ConfedSequence(y)) if y.is_empty() => true,
            _ => false,
        }
    }

    /// Deduplicate ASNs in this path segment. Additionally, sets are sorted and may be converted to
    /// sequences if they only have a single element.
    ///
    /// See [AsPath::dedup_coalesce] for more information.
    fn dedup(&mut self) {
        match self {
            AsPathSegment::AsSequence(x) | AsPathSegment::ConfedSequence(x) => x.to_mut().dedup(),
            AsPathSegment::AsSet(x) => {
                let x_mut = x.to_mut();
                x_mut.sort_unstable();
                x_mut.dedup();
                if x.len() == 1 {
                    *self = AsPathSegment::AsSequence(std::mem::take(x));
                }
            }
            AsPathSegment::ConfedSet(x) => {
                let x_mut = x.to_mut();
                x_mut.sort_unstable();
                x_mut.dedup();
                if x.len() == 1 {
                    *self = AsPathSegment::ConfedSequence(std::mem::take(x));
                }
            }
        }
    }
}

impl AsRef<[Asn]> for AsPathSegment<'_> {
    fn as_ref(&self) -> &[Asn] {
        let (AsPathSegment::AsSequence(x)
        | AsPathSegment::AsSet(x)
        | AsPathSegment::ConfedSequence(x)
        | AsPathSegment::ConfedSet(x)) = self;
        x
    }
}

impl Hash for AsPathSegment<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash the discriminant since we do not differentiate between confederation segments
        discriminant(self).hash(state);

        let set = match self {
            AsPathSegment::AsSequence(x) | AsPathSegment::ConfedSequence(x) => {
                return x.hash(state)
            }
            AsPathSegment::AsSet(x) | AsPathSegment::ConfedSet(x) => x,
        };

        // FIXME: Once is_sorted is stabilized, call it first to determine if sorting is required
        if set.len() <= 32 {
            let mut buffer = [Asn::new_32bit(0); 32];
            set.iter()
                .zip(&mut buffer)
                .for_each(|(asn, buffer)| *buffer = *asn);

            let slice = &mut buffer[..set.len()];
            slice.sort_unstable();
            Asn::hash_slice(slice, state);
            return;
        }

        // Fallback to allocating a Vec on the heap to sort
        set.iter().sorted().for_each(|x| x.hash(state));
    }
}

/// Check for equality of two path segments.
/// ```rust
/// # use bgpkit_parser::models::AsPathSegment;
/// let a = AsPathSegment::sequence([1, 2, 3]);
/// let b = AsPathSegment::set([1, 2, 3]);
///
/// // Sequences must be identical to be considered equivalent
/// assert_eq!(a, AsPathSegment::sequence([1, 2, 3]));
/// assert_ne!(a, AsPathSegment::sequence([1, 2, 3, 3]));
///
/// // Sets may be reordered, but must contain exactly the same ASNs.
/// assert_eq!(b, AsPathSegment::set([3, 1, 2]));
/// assert_ne!(b, AsPathSegment::set([1, 2, 3, 3]));
/// ```
impl PartialEq for AsPathSegment<'_> {
    fn eq(&self, other: &Self) -> bool {
        let (x, y) = match (self, other) {
            (AsPathSegment::AsSequence(x), AsPathSegment::AsSequence(y))
            | (AsPathSegment::ConfedSequence(x), AsPathSegment::ConfedSequence(y)) => {
                return x == y
            }
            (AsPathSegment::AsSet(x), AsPathSegment::AsSet(y))
            | (AsPathSegment::ConfedSet(x), AsPathSegment::ConfedSet(y)) => (x, y),
            _ => return false,
        };

        // Attempt to exit early
        if x.len() != y.len() {
            return false;
        } else if x == y {
            return true;
        }

        if x.len() <= 32 {
            let mut x_buffer = [Asn::new_32bit(0); 32];
            let mut y_buffer = [Asn::new_32bit(0); 32];
            x.iter()
                .zip(&mut x_buffer)
                .for_each(|(asn, buffer)| *buffer = *asn);
            y.iter()
                .zip(&mut y_buffer)
                .for_each(|(asn, buffer)| *buffer = *asn);

            x_buffer[..x.len()].sort_unstable();
            y_buffer[..y.len()].sort_unstable();
            return x_buffer[..x.len()] == y_buffer[..y.len()];
        }

        x.iter()
            .sorted()
            .zip(y.iter().sorted())
            .all(|(a, b)| a == b)
    }
}

impl Eq for AsPathSegment<'_> {}

#[derive(Debug, PartialEq, Clone, Eq, Default, Hash)]
pub struct AsPath {
    pub segments: Vec<AsPathSegment<'static>>,
}

impl AsPath {
    pub fn new() -> AsPath {
        AsPath { segments: vec![] }
    }

    /// Shorthand for creating an `AsPath` consisting of a single `AsSequence` segment.
    pub fn from_sequence<S: AsRef<[u32]>>(seq: S) -> Self {
        let segment = AsPathSegment::AsSequence(seq.as_ref().iter().copied().map_into().collect());

        AsPath {
            segments: vec![segment],
        }
    }

    pub fn from_segments(segments: Vec<AsPathSegment<'static>>) -> AsPath {
        AsPath { segments }
    }

    /// Adds a new segment to the end of the path. This will change the origin of the path. No
    /// validation or merging the segment is performed during this step.
    pub fn append_segment(&mut self, segment: AsPathSegment<'static>) {
        self.segments.push(segment);
    }

    /// Check if the path is empty. Note that a non-empty path may have a route length of 0 due to
    /// empty segments or confederation segments.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Get the total length of the routes this path represents. For example, if this route
    /// contained a sequence of 5 ASNs followed by a set of 3 ASNs, the total route length would be
    /// 6.
    ///
    /// Confederation segments do not count towards the total route length. This means it is
    /// possible to have a non-empty AsPath with a length of 0.
    pub fn route_len(&self) -> usize {
        self.segments.iter().map(AsPathSegment::route_len).sum()
    }

    /// Get the number of segments that make up this path. For the number of ASNs in routes
    /// represented by this path, use [AsPath::route_len].
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Get the total number of routes this path represents. This function assumes the total number
    /// of route variations can be represented by a u64.
    pub fn num_route_variations(&self) -> u64 {
        let mut variations: u64 = 1;

        for segment in &self.segments {
            if let AsPathSegment::AsSet(x) = segment {
                variations *= x.len() as u64;
            }
        }

        variations
    }

    /// Checks if any segments of this [AsPath] contain the following ASN.
    pub fn contains_asn(&self, x: Asn) -> bool {
        self.iter_segments().flatten().contains(&x)
    }

    /// Coalesce this [AsPath] into the minimum number of segments required without changing the
    /// values along the path. This can be helpful as some BGP servers will prepend additional
    /// segments without coalescing sequences. For de-duplicating see [AsPath::dedup_coalesce].
    ///
    /// Changes applied by this function:
    ///  - Merge adjacent AS_SEQUENCE segments
    ///  - Merge adjacent AS_CONFED_SEQUENCE segments
    ///  - Removing empty AS_SEQUENCE and AS_CONFED_SEQUENCE segments
    ///
    /// ```rust
    /// # use bgpkit_parser::models::{AsPath, AsPathSegment};
    /// let mut a = AsPath::from_segments(vec![
    ///     AsPathSegment::sequence([1, 2]),
    ///     AsPathSegment::sequence([]),
    ///     AsPathSegment::sequence([2]),
    ///     AsPathSegment::set([2]),
    ///     AsPathSegment::set([5, 3, 3, 2]),
    /// ]);
    ///
    /// let expected = AsPath::from_segments(vec![
    ///     AsPathSegment::sequence([1, 2, 2]),
    ///     AsPathSegment::set([2]),
    ///     AsPathSegment::set([5, 3, 3, 2]),
    /// ]);
    ///
    /// a.coalesce();
    /// assert_eq!(a, expected);
    /// ```
    /// If there is only one segment, no changes will occur. This function will not attempt to
    /// deduplicate sequences or alter sets.
    pub fn coalesce(&mut self) {
        let mut end_index = 0;
        let mut scan_index = 1;

        while scan_index < self.segments.len() {
            let (a, b) = self.segments.split_at_mut(scan_index);
            if !AsPathSegment::merge_in_place(&mut a[end_index], &mut b[0]) {
                end_index += 1;
                self.segments.swap(end_index, scan_index);
            }
            scan_index += 1;
        }

        self.segments.truncate(end_index + 1);
    }

    /// A more aggressive version of [AsPath::coalesce] which also de-duplicates ASNs within this
    /// path and converts sets of a single ASN to sequences. Some BGP servers will prepend their own
    /// ASN multiple times when announcing a path to artificially increase the route length and make
    /// the route seem less less desirable to peers.This function is best suited for use-cases which
    /// only care about transitions between ASes along the path.
    ///
    /// Changes applied by this function:
    ///  - Merge adjacent AS_SEQUENCE segments
    ///  - Merge adjacent AS_CONFED_SEQUENCE segments
    ///  - Removing empty AS_SEQUENCE and AS_CONFED_SEQUENCE segments
    ///  - De-duplicate ASNs in AS_SEQUENCE and AS_CONFED_SEQUENCE segments
    ///  - Sort and de-duplicate ASNs in AS_SET and AS_CONFED_SET segments
    ///  - Convert AS_SET and AS_CONFED_SET segments with exactly 1 element to sequences
    ///
    /// ```rust
    /// # use bgpkit_parser::models::{AsPath, AsPathSegment};
    /// let mut a = AsPath::from_segments(vec![
    ///     AsPathSegment::sequence([1, 2]),
    ///     AsPathSegment::sequence([]),
    ///     AsPathSegment::sequence([2]),
    ///     AsPathSegment::set([2]),
    ///     AsPathSegment::set([5, 3, 3, 2]),
    /// ]);
    ///
    /// let expected = AsPath::from_segments(vec![
    ///     AsPathSegment::sequence([1, 2]),
    ///     AsPathSegment::set([2, 3, 5]),
    /// ]);
    ///
    /// a.dedup_coalesce();
    /// assert_eq!(a, expected);
    /// ```
    pub fn dedup_coalesce(&mut self) {
        if !self.segments.is_empty() {
            self.segments[0].dedup();
        }
        let mut end_index = 0;
        let mut scan_index = 1;

        while scan_index < self.segments.len() {
            let (a, b) = self.segments.split_at_mut(scan_index);
            if !AsPathSegment::dedup_merge_in_place(&mut a[end_index], &mut b[0]) {
                end_index += 1;
                self.segments.swap(end_index, scan_index);
            }
            scan_index += 1;
        }

        self.segments.truncate(end_index + 1);
    }

    /// Checks if two paths correspond to equivalent routes. Unlike `a == b`, this function will
    /// ignore duplicate ASNs by comparing the coalesced versions of each path.
    ///
    /// This is equivalent to [AsPath::eq] after calling [AsPath::dedup_coalesce] on both paths.
    pub fn has_equivalent_routing(&self, other: &Self) -> bool {
        let mut a = self.to_owned();
        let mut b = other.to_owned();

        a.dedup_coalesce();
        b.dedup_coalesce();

        a == b
    }

    /// Get the length of ASN required to store all of the ASNs within this path
    pub fn required_asn_length(&self) -> AsnLength {
        self.iter_segments().flatten().map(Asn::required_len).fold(
            AsnLength::Bits16,
            |a, b| match (a, b) {
                (AsnLength::Bits16, AsnLength::Bits16) => AsnLength::Bits16,
                _ => AsnLength::Bits32,
            },
        )
    }

    /// Construct AsPath from AS_PATH and AS4_PATH
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc6793#section-4.2.3>
    ///
    /// ```text
    ///    If the number of AS numbers in the AS_PATH attribute is less than the
    ///    number of AS numbers in the AS4_PATH attribute, then the AS4_PATH
    ///    attribute SHALL be ignored, and the AS_PATH attribute SHALL be taken
    ///    as the AS path information.
    ///
    ///    If the number of AS numbers in the AS_PATH attribute is larger than
    ///    or equal to the number of AS numbers in the AS4_PATH attribute, then
    ///    the AS path information SHALL be constructed by taking as many AS
    ///    numbers and path segments as necessary from the leading part of the
    ///    AS_PATH attribute, and then prepending them to the AS4_PATH attribute
    ///    so that the AS path information has a number of AS numbers identical
    ///    to that of the AS_PATH attribute.  Note that a valid
    ///    AS_CONFED_SEQUENCE or AS_CONFED_SET path segment SHALL be prepended
    ///    if it is either the leading path segment or is adjacent to a path
    ///    segment that is prepended.
    /// ```
    pub fn merge_aspath_as4path(aspath: &AsPath, as4path: &AsPath) -> Option<AsPath> {
        if aspath.route_len() < as4path.route_len() {
            return Some(aspath.clone());
        }

        let mut as4iter = as4path.segments.iter();
        let mut as4seg = as4iter.next();
        let mut new_segs: Vec<AsPathSegment> = vec![];
        if as4seg.is_none() {
            new_segs.extend(aspath.segments.clone());
            return Some(AsPath { segments: new_segs });
        }

        for seg in &aspath.segments {
            let as4seg_unwrapped = as4seg.unwrap();
            if let (AsPathSegment::AsSequence(seq), AsPathSegment::AsSequence(seq4)) =
                (seg, as4seg_unwrapped)
            {
                let diff_len = seq.len() - seq4.len();
                let mut new_seq: Vec<Asn> = vec![];
                new_seq.extend(seq.iter().take(diff_len));
                new_seq.extend(seq4.iter());
                new_segs.push(AsPathSegment::AsSequence(Cow::Owned(new_seq)));
            } else {
                new_segs.push(as4seg_unwrapped.clone());
            }
            as4seg = as4iter.next();
        }

        Some(AsPath { segments: new_segs })
    }

    /// This function serves as a alternative to [AsPath::iter_origins] which attempts to make the
    /// assumption that a path can only have exactly one origin. If a path does not have exactly 1
    /// origin (such as when empty or ending in a set), then `None` will be returned instead.
    pub fn get_singular_origin(&self) -> Option<Asn> {
        match self.segments.last() {
            Some(AsPathSegment::AsSequence(v)) => v.last().copied(),
            Some(AsPathSegment::AsSet(v)) if v.len() == 1 => Some(v[0]),
            _ => None,
        }
    }
}

impl Display for AsPath {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        for (index, segment) in self.iter_segments().enumerate() {
            if index != 0 {
                write!(f, " ")?;
            }

            match segment {
                AsPathSegment::AsSequence(v) | AsPathSegment::ConfedSequence(v) => {
                    let mut asn_iter = v.iter();
                    if let Some(first_element) = asn_iter.next() {
                        write!(f, "{}", first_element)?;

                        for asn in asn_iter {
                            write!(f, " {}", asn)?;
                        }
                    }
                }
                AsPathSegment::AsSet(v) | AsPathSegment::ConfedSet(v) => {
                    write!(f, "{{")?;
                    let mut asn_iter = v.iter();
                    if let Some(first_element) = asn_iter.next() {
                        write!(f, "{}", first_element)?;

                        for asn in asn_iter {
                            write!(f, ",{}", asn)?;
                        }
                    }
                    write!(f, "}}")?;
                }
            }
        }

        Ok(())
    }
}
