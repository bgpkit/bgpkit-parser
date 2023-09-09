use crate::models::aspath::storage::{AsPathStorage, MixedStorage};
use crate::models::{AsPath, AsPathSegment, Asn};
use smallvec::smallvec;
use std::borrow::Cow;
use std::iter::Copied;
use std::marker::PhantomData;
use std::slice;

impl AsPathSegment<'_> {
    /// Get an iterator over the ASNs within this path segment
    pub fn iter(&self) -> <&'_ Self as IntoIterator>::IntoIter {
        self.into_iter()
    }

    /// Get a mutable iterator over the ASNs within this path segment
    pub fn iter_mut(&mut self) -> <&'_ mut Self as IntoIterator>::IntoIter {
        self.into_iter()
    }
}

pub enum MaybeOwnedIntoIter<'a, T: Copy> {
    Borrow(Copied<std::slice::Iter<'a, T>>),
    Owned(std::vec::IntoIter<T>),
}

impl<'a, T: Copy> Iterator for MaybeOwnedIntoIter<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            MaybeOwnedIntoIter::Borrow(x) => x.next(),
            MaybeOwnedIntoIter::Owned(x) => x.next(),
        }
    }
}

impl<'a> IntoIterator for AsPathSegment<'a> {
    type Item = Asn;
    type IntoIter = MaybeOwnedIntoIter<'a, Asn>;

    fn into_iter(self) -> Self::IntoIter {
        let (AsPathSegment::AsSequence(x)
        | AsPathSegment::AsSet(x)
        | AsPathSegment::ConfedSequence(x)
        | AsPathSegment::ConfedSet(x)) = self;

        match x {
            Cow::Borrowed(y) => MaybeOwnedIntoIter::Borrow(y.iter().copied()),
            Cow::Owned(y) => MaybeOwnedIntoIter::Owned(y.into_iter()),
        }
    }
}

impl<'a, 'b: 'a> IntoIterator for &'a AsPathSegment<'b> {
    type Item = &'a Asn;
    type IntoIter = std::slice::Iter<'a, Asn>;

    fn into_iter(self) -> Self::IntoIter {
        let (AsPathSegment::AsSequence(x)
        | AsPathSegment::AsSet(x)
        | AsPathSegment::ConfedSequence(x)
        | AsPathSegment::ConfedSet(x)) = self;
        x.iter()
    }
}

impl<'a, 'b: 'a> IntoIterator for &'a mut AsPathSegment<'b> {
    type Item = &'a mut Asn;
    type IntoIter = std::slice::IterMut<'a, Asn>;

    fn into_iter(self) -> Self::IntoIter {
        let (AsPathSegment::AsSequence(x)
        | AsPathSegment::AsSet(x)
        | AsPathSegment::ConfedSequence(x)
        | AsPathSegment::ConfedSet(x)) = self;
        x.to_mut().iter_mut()
    }
}

/// This is not a perfect solution since it is theoretically possible that a path could be created
/// with more variations than a u64. That being said, the chances of such a thing occurring are
/// essentially non-existent unless a BGP peer begins announcing maliciously constructed paths.
struct AsPathNumberedRouteIter<'a> {
    path: &'a [AsPathSegment<'a>],
    index: usize,
    route_num: u64,
}

impl<'a> Iterator for AsPathNumberedRouteIter<'a> {
    type Item = Asn;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.path.first()? {
                AsPathSegment::AsSequence(x) => match x.get(self.index) {
                    None => {
                        self.index = 0;
                        self.path = &self.path[1..];
                    }
                    Some(asn) => {
                        self.index += 1;
                        return Some(*asn);
                    }
                },
                AsPathSegment::AsSet(x) => {
                    self.path = &self.path[1..];
                    if x.is_empty() {
                        return Some(Asn::RESERVED);
                    }

                    let asn = x[(self.route_num % x.len() as u64) as usize];
                    self.route_num /= x.len() as u64;
                    return Some(asn);
                }
                _ => self.path = &self.path[1..],
            }
        }
    }
}

pub struct AsPathRouteIter<'a, D> {
    path: Cow<'a, AsPathStorage>,
    route_num: u64,
    total_routes: u64,
    _phantom: PhantomData<D>,
}

impl<'a, D> Iterator for AsPathRouteIter<'a, D>
where
    D: FromIterator<Asn>,
{
    type Item = D;

    fn next(&mut self) -> Option<Self::Item> {
        if self.route_num >= self.total_routes {
            return None;
        }

        match self.path.as_ref() {
            AsPathStorage::SingleSequence(x) => {
                self.route_num += 1;
                Some(D::from_iter(x.iter().copied()))
            }
            AsPathStorage::Mixed(path) => {
                // Attempt to speed up what is by far the most common case (a path of a single sequence)
                if self.route_num == 0 && path.len() == 1 {
                    if let AsPathSegment::AsSequence(sequence) = &path[0] {
                        let route = D::from_iter(sequence.iter().copied());
                        self.route_num += 1;
                        return Some(route);
                    }
                }

                let route_asn_iter = AsPathNumberedRouteIter {
                    path: path.as_ref(),
                    index: 0,
                    route_num: self.route_num,
                };

                self.route_num += 1;
                Some(D::from_iter(route_asn_iter))
            }
        }
    }
}

#[repr(transparent)]
pub struct SegmentIter<'a> {
    inner: SegmentIterInner<'a>,
}

enum SegmentIterInner<'a> {
    Single(Option<&'a [Asn]>),
    Mixed(slice::Iter<'a, AsPathSegment<'static>>),
}

impl<'a> Iterator for SegmentIter<'a> {
    type Item = AsPathSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            SegmentIterInner::Single(x) => {
                x.take().map(Cow::Borrowed).map(AsPathSegment::AsSequence)
            }
            SegmentIterInner::Mixed(x) => x.next().map(|x| x.borrowed()),
        }
    }
}

pub type SegmentIntoIter = <MixedStorage as IntoIterator>::IntoIter;

impl AsPath {
    pub fn iter_segments(&self) -> SegmentIter<'_> {
        let inner = match &self.storage {
            AsPathStorage::SingleSequence(x) => SegmentIterInner::Single(Some(x)),
            AsPathStorage::Mixed(x) => SegmentIterInner::Mixed(x.iter()),
        };

        SegmentIter { inner }
    }

    pub fn into_segments_iter(self) -> SegmentIntoIter {
        match self.storage {
            AsPathStorage::SingleSequence(asns) => {
                let segment = AsPathSegment::AsSequence(Cow::Owned(asns.to_vec()));
                smallvec![segment].into_iter()
            }
            AsPathStorage::Mixed(segments) => segments.into_iter(),
        }
    }

    /// Gets an iterator over all possible routes this path represents.
    pub fn iter_routes<D>(&self) -> AsPathRouteIter<'_, D>
    where
        D: FromIterator<Asn>,
    {
        AsPathRouteIter {
            path: Cow::Borrowed(&self.storage),
            route_num: 0,
            total_routes: self.num_route_variations(),
            _phantom: PhantomData,
        }
    }

    /// Iterate through the originating ASNs of this path. This functionality is provided for
    /// completeness, but in almost all cases this iterator should only contain a single element.
    /// Alternatively, [AsPath::get_singular_origin] can be used if
    pub fn iter_origins(&self) -> impl '_ + Iterator<Item = Asn> {
        let origin_slice = match &self.storage {
            AsPathStorage::SingleSequence(v) => v.last().map(slice::from_ref).unwrap_or(&[]),
            AsPathStorage::Mixed(segments) => match segments.last() {
                Some(AsPathSegment::AsSequence(v)) => v.last().map(slice::from_ref).unwrap_or(&[]),
                Some(AsPathSegment::AsSet(v)) => v.as_ref(),
                _ => &[],
            },
        };

        origin_slice.iter().copied()
    }
}

/// Iterates over all route variations the given `AsPath` represents.
impl<'a> IntoIterator for &'a AsPath {
    type Item = Vec<Asn>;
    type IntoIter = AsPathRouteIter<'a, Vec<Asn>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_routes()
    }
}

/// Iterates over all route variations the given `AsPath` represents.
impl IntoIterator for AsPath {
    type Item = Vec<Asn>;
    type IntoIter = AsPathRouteIter<'static, Vec<Asn>>;

    fn into_iter(self) -> Self::IntoIter {
        AsPathRouteIter {
            total_routes: self.num_route_variations(),
            path: Cow::Owned(self.storage),
            route_num: 0,
            _phantom: PhantomData,
        }
    }
}
