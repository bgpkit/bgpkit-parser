use crate::models::aspath::storage::{AsPathStorage, SingleSequenceStorage};
use crate::models::{AsPath, AsPathSegment, Asn};
use smallvec::SmallVec;
use std::borrow::Cow;

pub struct AsPathBuilder {
    storage: AsPathStorage,
    first_sequence: bool,
}

impl AsPathBuilder {
    #[inline(always)]
    pub fn new() -> Self {
        AsPathBuilder::default()
    }

    /// Appends an ASN to the end of the last segment in the path. If there are no segments or the
    /// last segment is not an `AS_PATH_AS_SEQUENCE`, a new segment will be added.
    pub fn push_sequence_asn(&mut self, asn: Asn) {
        self.first_sequence = false;
        match &mut self.storage {
            AsPathStorage::SingleSequence(seq) => seq.push(asn),
            AsPathStorage::Mixed(segments) => {
                if let Some(AsPathSegment::AsSequence(seq)) = segments.last_mut() {
                    seq.to_mut().push(asn);
                }

                segments.push(AsPathSegment::AsSequence(Cow::Owned(vec![asn])));
            }
        }
    }

    pub fn push_segment(&mut self, segment: AsPathSegment<'static>) {
        let segments = self.storage.switch_to_mixed_storage(!self.first_sequence);
        segments.push(segment);
    }

    /// Begin a new AS sequence within this path being built. The given length is used similarly to
    /// [Vec::with_capacity] to perform pre-allocation of the underlying storage.
    #[inline(always)]
    pub fn begin_as_sequence(&mut self, length: usize) -> AsPathSegmentBuilder {
        let storage = &mut self.storage;
        if self.first_sequence {
            if let AsPathStorage::SingleSequence(seq) = storage {
                self.first_sequence = false;
                seq.reserve_exact(length);
                return AsPathSegmentBuilder {
                    inner: AsPathSegmentBuilderInner::InPlace(seq),
                };
            }
        }

        Self::begin_sequence_cold_path(storage, length)
    }

    /// Begin a new AS set within this path being built. The given length is used similarly to
    /// [Vec::with_capacity] to perform pre-allocation of the underlying storage.
    #[cold]
    pub fn begin_as_set(&mut self, length: usize) -> AsPathSegmentBuilder {
        let segments = self.storage.switch_to_mixed_storage(!self.first_sequence);
        segments.push(AsPathSegment::AsSet(Cow::Owned(Vec::with_capacity(length))));

        if let Some(AsPathSegment::AsSet(Cow::Owned(asns))) = segments.last_mut() {
            AsPathSegmentBuilder {
                inner: AsPathSegmentBuilderInner::Heap(asns),
            }
        } else {
            unreachable!("Last segment will match the item pushed to the vec")
        }
    }

    /// Begin a new confed sequence within this path being built. The given length is used similarly to
    /// [Vec::with_capacity] to perform pre-allocation of the underlying storage.
    #[cold]
    pub fn begin_confed_sequence(&mut self, length: usize) -> AsPathSegmentBuilder {
        let segments = self.storage.switch_to_mixed_storage(!self.first_sequence);
        segments.push(AsPathSegment::ConfedSequence(Cow::Owned(
            Vec::with_capacity(length),
        )));

        if let Some(AsPathSegment::ConfedSequence(Cow::Owned(asns))) = segments.last_mut() {
            AsPathSegmentBuilder {
                inner: AsPathSegmentBuilderInner::Heap(asns),
            }
        } else {
            unreachable!("Last segment will match the item pushed to the vec")
        }
    }

    /// Begin a new confed set within this path being built. The given length is used similarly to
    /// [Vec::with_capacity] to perform pre-allocation of the underlying storage.
    #[cold]
    pub fn begin_confed_set(&mut self, length: usize) -> AsPathSegmentBuilder {
        let segments = self.storage.switch_to_mixed_storage(!self.first_sequence);
        segments.push(AsPathSegment::ConfedSet(Cow::Owned(Vec::with_capacity(
            length,
        ))));

        if let Some(AsPathSegment::ConfedSet(Cow::Owned(asns))) = segments.last_mut() {
            AsPathSegmentBuilder {
                inner: AsPathSegmentBuilderInner::Heap(asns),
            }
        } else {
            unreachable!("Last segment will match the item pushed to the vec")
        }
    }

    #[inline]
    pub fn build(self) -> AsPath {
        AsPath {
            storage: self.storage,
        }
    }

    #[cold]
    fn begin_sequence_cold_path(
        storage: &mut AsPathStorage,
        length: usize,
    ) -> AsPathSegmentBuilder {
        let segments = storage.switch_to_mixed_storage(true);

        segments.push(AsPathSegment::AsSequence(Cow::Owned(Vec::with_capacity(
            length,
        ))));

        if let Some(AsPathSegment::AsSequence(Cow::Owned(asns))) = segments.last_mut() {
            AsPathSegmentBuilder {
                inner: AsPathSegmentBuilderInner::Heap(asns),
            }
        } else {
            unreachable!("Last segment will match the item pushed to the vec")
        }
    }
}

impl Default for AsPathBuilder {
    #[inline]
    fn default() -> Self {
        AsPathBuilder {
            storage: AsPathStorage::SingleSequence(SmallVec::new()),
            first_sequence: true,
        }
    }
}

#[repr(transparent)]
pub struct AsPathSegmentBuilder<'a> {
    inner: AsPathSegmentBuilderInner<'a>,
}

enum AsPathSegmentBuilderInner<'a> {
    InPlace(&'a mut SingleSequenceStorage),
    Heap(&'a mut Vec<Asn>),
}

impl<'a> AsPathSegmentBuilder<'a> {
    #[inline(always)]
    pub fn push(&mut self, asn: Asn) {
        match &mut self.inner {
            AsPathSegmentBuilderInner::InPlace(arr) => arr.push(asn),
            AsPathSegmentBuilderInner::Heap(arr) => arr.push(asn),
        }
    }
}
