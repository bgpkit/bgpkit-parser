use crate::models::*;
use itertools::Itertools;
use serde::{Serialize, Serializer};
use std::fmt::{Display, Formatter};

/// Enum of AS path segment.
#[derive(Debug, PartialEq, Clone, Eq)]
pub enum AsPathSegment {
    AsSequence(Vec<Asn>),
    AsSet(Vec<Asn>),
    ConfedSequence(Vec<Asn>),
    ConfedSet(Vec<Asn>),
}

impl AsPathSegment {
    pub fn count_asns(&self) -> usize {
        match self {
            AsPathSegment::AsSequence(v) => v.len(),
            AsPathSegment::AsSet(_) => 1,
            AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_) => 0,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Default)]
pub struct AsPath {
    pub segments: Vec<AsPathSegment>,
}

impl AsPath {
    pub fn new() -> AsPath {
        AsPath { segments: vec![] }
    }

    pub fn from_segments(segments: Vec<AsPathSegment>) -> AsPath {
        AsPath { segments }
    }

    pub fn add_segment(&mut self, segment: AsPathSegment) {
        self.segments.push(segment);
    }

    pub fn segments(&self) -> &Vec<AsPathSegment> {
        &self.segments
    }

    pub fn count_asns(&self) -> usize {
        self.segments.iter().map(AsPathSegment::count_asns).sum()
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
        if aspath.count_asns() < as4path.count_asns() {
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
                new_seq.extend(seq4);
                new_segs.push(AsPathSegment::AsSequence(new_seq));
            } else {
                new_segs.push(as4seg_unwrapped.clone());
            }
            as4seg = as4iter.next();
        }

        Some(AsPath { segments: new_segs })
    }

    pub fn get_origin(&self) -> Option<Vec<Asn>> {
        if let Some(seg) = self.segments.last() {
            match seg {
                AsPathSegment::AsSequence(v) => v.last().map(|n| vec![*n]),
                AsPathSegment::AsSet(v) => Some(v.clone()),
                AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_) => None,
            }
        } else {
            None
        }
    }

    pub fn to_u32_vec(&self) -> Option<Vec<u32>> {
        if !self
            .segments
            .iter()
            .all(|seg| matches!(seg, AsPathSegment::AsSequence(_v)))
        {
            // as path contains AS set or confederated sequence/set
            return None;
        }
        let mut path = vec![];
        for s in &self.segments {
            if let AsPathSegment::AsSequence(seg) = s {
                for asn in seg {
                    path.push(asn.asn);
                }
            } else {
                // this won't happen
                return None;
            }
        }
        Some(path)
    }
}

impl Display for AsPath {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        for (index, segment) in self.segments().iter().enumerate() {
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
                },
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

impl Serialize for AsPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::models::*;

    #[test]
    fn test_aspath_as4path_merge() {
        let aspath = AsPath {
            segments: vec![AsPathSegment::AsSequence(
                [1, 2, 3, 5].map(|i| i.into()).to_vec(),
            )],
        };
        let as4path = AsPath {
            segments: vec![AsPathSegment::AsSequence(
                [2, 3, 7].map(|i| i.into()).to_vec(),
            )],
        };
        let newpath = AsPath::merge_aspath_as4path(&aspath, &as4path).unwrap();
        assert_eq!(
            newpath.segments[0],
            AsPathSegment::AsSequence([1, 2, 3, 7].map(|i| { i.into() }).to_vec())
        );
    }

    #[test]
    fn test_get_origin() {
        let aspath = AsPath {
            segments: vec![AsPathSegment::AsSequence(
                [1, 2, 3, 5].map(|i| i.into()).to_vec(),
            )],
        };
        let origins = aspath.get_origin();
        assert!(origins.is_some());
        assert_eq!(origins.unwrap(), vec![5]);

        let aspath = AsPath {
            segments: vec![
                AsPathSegment::AsSequence([1, 2, 3, 5].map(|i| i.into()).to_vec()),
                AsPathSegment::AsSet([7, 8].map(|i| i.into()).to_vec()),
            ],
        };
        let origins = aspath.get_origin();
        assert!(origins.is_some());
        assert_eq!(origins.unwrap(), vec![7, 8]);
    }

    #[test]
    fn test_aspath_to_vec() {
        let as4path = AsPath {
            segments: vec![AsPathSegment::AsSequence(
                [2, 3, 4].map(|i| i.into()).to_vec(),
            )],
        };
        assert_eq!(as4path.to_u32_vec(), Some(vec![2, 3, 4]));

        let as4path = AsPath {
            segments: vec![
                AsPathSegment::AsSequence([2, 3, 4].map(|i| i.into()).to_vec()),
                AsPathSegment::AsSequence([5, 6, 7].map(|i| i.into()).to_vec()),
            ],
        };
        assert_eq!(as4path.to_u32_vec(), Some(vec![2, 3, 4, 5, 6, 7]));

        let as4path = AsPath {
            segments: vec![AsPathSegment::AsSet([2, 3, 4].map(|i| i.into()).to_vec())],
        };
        assert_eq!(as4path.to_u32_vec(), None);
    }
}
