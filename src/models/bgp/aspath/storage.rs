use crate::models::{AsPathSegment, Asn};
use smallvec::{smallvec, SmallVec};
use std::borrow::Cow;
use std::hash::{Hash, Hasher};
use std::mem::size_of;
use std::slice;

const STORAGE_SIZE_LIMIT: usize = 64;

pub type MixedStorage =
    SmallVec<[AsPathSegment<'static>; STORAGE_SIZE_LIMIT / size_of::<AsPathSegment>()]>;

#[derive(Debug, Clone, Eq)]
pub enum AsPathStorage {
    /// By far the most common type of AS Path appearing in RIB data is a single sequence of between
    /// 1 to ~20 ASNs. We can optimize for this use case by providing space in the structure for
    /// those ASNs before allocating to the heap. After checking a couple of RIB table dumps,
    /// roughly 75% of AS_PATHs consist of a single sequence with 5 ASNs. By expanding to 16, we
    /// can then hold roughly 99.5% of observed AS_PATH attributes on the stack without allocation.
    SingleSequence(SmallVec<[Asn; STORAGE_SIZE_LIMIT / size_of::<Asn>()]>),
    /// Fallback case where we defer to the typical list of generic segments
    Mixed(MixedStorage),
}

impl Hash for AsPathStorage {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            AsPathStorage::SingleSequence(x) => {
                let segment = AsPathSegment::AsSequence(Cow::Borrowed(x));
                AsPathSegment::hash_slice(slice::from_ref(&segment), state)
            }
            AsPathStorage::Mixed(segments) => AsPathSegment::hash_slice(segments, state),
        }
    }
}

impl PartialEq for AsPathStorage {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (AsPathStorage::SingleSequence(x), AsPathStorage::SingleSequence(y)) => x == y,
            (AsPathStorage::Mixed(x), AsPathStorage::Mixed(y)) => x == y,
            (AsPathStorage::SingleSequence(x), AsPathStorage::Mixed(y))
            | (AsPathStorage::Mixed(y), AsPathStorage::SingleSequence(x)) => {
                let segment = AsPathSegment::AsSequence(Cow::Borrowed(x));
                slice::from_ref(&segment) == &y[..]
            }
        }
    }
}

impl Default for AsPathStorage {
    fn default() -> Self {
        AsPathStorage::SingleSequence(SmallVec::default())
    }
}

impl FromIterator<AsPathSegment<'static>> for AsPathStorage {
    fn from_iter<T: IntoIterator<Item = AsPathSegment<'static>>>(iter: T) -> Self {
        AsPathStorage::Mixed(MixedStorage::from_iter(iter))
    }
}

impl AsPathStorage {
    /// Checks if there are any segments in this storage
    #[inline]
    pub fn is_empty(&self) -> bool {
        match self {
            // A single sequence still counts as 1 segment even if empty
            AsPathStorage::SingleSequence(_) => false,
            AsPathStorage::Mixed(segments) => segments.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            AsPathStorage::SingleSequence(_) => 1,
            AsPathStorage::Mixed(segments) => segments.len(),
        }
    }

    pub fn switch_to_mixed_storage(&mut self, preserve_single_sequence: bool) -> &mut MixedStorage {
        loop {
            match self {
                AsPathStorage::SingleSequence(seq) => {
                    if preserve_single_sequence {
                        let segment = AsPathSegment::AsSequence(Cow::Owned(seq.to_vec()));
                        *self = AsPathStorage::Mixed(smallvec![segment]);
                    } else {
                        *self = AsPathStorage::Mixed(SmallVec::new())
                    }
                }
                AsPathStorage::Mixed(segments) => return segments,
            }
        }
    }
}
