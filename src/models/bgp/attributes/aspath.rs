use crate::models::*;
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

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;
    use serde::de::{SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::borrow::Cow;

    /// Segment type names using names from RFC3065.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc3065#section-5>
    #[allow(non_camel_case_types)]
    #[derive(Serialize, Deserialize)]
    enum SegmentType {
        AS_SET,
        AS_SEQUENCE,
        AS_CONFED_SEQUENCE,
        AS_CONFED_SET,
    }

    #[derive(Serialize, Deserialize)]
    struct VerboseSegment<'s> {
        ty: SegmentType,
        values: Cow<'s, [Asn]>,
    }

    impl Serialize for AsPathSegment {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let (ty, elements) = match self {
                AsPathSegment::AsSequence(x) => (SegmentType::AS_SEQUENCE, x.as_ref()),
                AsPathSegment::AsSet(x) => (SegmentType::AS_SET, x.as_ref()),
                AsPathSegment::ConfedSequence(x) => (SegmentType::AS_CONFED_SEQUENCE, x.as_ref()),
                AsPathSegment::ConfedSet(x) => (SegmentType::AS_CONFED_SET, x.as_ref()),
            };

            let verbose = VerboseSegment {
                ty,
                values: Cow::Borrowed(elements),
            };

            verbose.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for AsPathSegment {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let verbose = VerboseSegment::deserialize(deserializer)?;

            let values = verbose.values.into_owned();
            match verbose.ty {
                SegmentType::AS_SET => Ok(AsPathSegment::AsSet(values)),
                SegmentType::AS_SEQUENCE => Ok(AsPathSegment::AsSequence(values)),
                SegmentType::AS_CONFED_SEQUENCE => Ok(AsPathSegment::ConfedSequence(values)),
                SegmentType::AS_CONFED_SET => Ok(AsPathSegment::ConfedSet(values)),
            }
        }
    }

    /// Check if we can serialize an `AsPath` using the simplified format and get the number of
    /// elements to do so. The ambiguities that could prevent us from doing so are confederation
    /// segments and adjacent sequence segments.
    fn simplified_format_len(segments: &[AsPathSegment]) -> Option<usize> {
        let mut elements = 0;
        let mut prev_was_sequence = false;
        for segment in segments {
            match segment {
                AsPathSegment::AsSequence(seq) if !prev_was_sequence => {
                    prev_was_sequence = true;
                    elements += seq.len();
                }
                AsPathSegment::AsSet(_) => {
                    prev_was_sequence = false;
                    elements += 1;
                }
                _ => return None,
            }
        }

        Some(elements)
    }

    /// # Serialization format
    /// For the sake of readability and ease of use within other applications, there are verbose and
    /// simplified variants for serialization.
    ///
    /// ## Simplified format
    /// The simplified format is the default preferred serialization format. This format does not
    /// cover confederation segments and involves a single list of ASNs within the path sequence.
    /// For sets, a list of set members is used in place of an ASN.
    /// ```rust
    /// # use bgpkit_parser::models::{Asn, AsPath};
    /// # use bgpkit_parser::models::AsPathSegment::*;
    ///
    /// let a: AsPath = serde_json::from_str("[123, 942, 102]").unwrap();
    /// let b: AsPath = serde_json::from_str("[231, 432, [643, 836], 352]").unwrap();
    ///
    /// assert_eq!(&a.segments, &[
    ///     AsSequence(vec![Asn::from(123), Asn::from(942), Asn::from(102)])
    /// ]);
    /// assert_eq!(&b.segments, &[
    ///     AsSequence(vec![Asn::from(231), Asn::from(432)]),
    ///     AsSet(vec![Asn::from(643), Asn::from(836)]),
    ///     AsSequence(vec![Asn::from(352)])
    /// ]);
    /// ```
    ///
    /// ## Verbose format
    /// The verbose format serves as the fallback format for when the simplified format can not be
    /// used due to ambiguity. This happens when confederation segments are present, or multiple
    /// sequences occur back to back. In this format, segments are explicitly seperated and labeled.
    /// Segment types, denoted by the `ty` field, correspond to the names used within RFC3065
    /// (`AS_SET`, `AS_SEQUENCE`, `AS_CONFED_SEQUENCE`, `AS_CONFED_SET`).
    /// ```rust
    /// # use bgpkit_parser::models::{Asn, AsPath};
    /// # use bgpkit_parser::models::AsPathSegment::*;
    ///
    /// let a = r#"[
    ///     { "ty": "AS_CONFED_SEQUENCE", "values": [123, 942] },
    ///     { "ty": "AS_SEQUENCE", "values": [773] },
    ///     { "ty": "AS_SEQUENCE", "values": [382, 293] }
    /// ]"#;
    ///
    /// let parsed: AsPath = serde_json::from_str(a).unwrap();
    /// assert_eq!(&parsed.segments, &[
    ///     ConfedSequence(vec![Asn::from(123), Asn::from(942)]),
    ///     AsSequence(vec![Asn::from(773)]),
    ///     AsSequence(vec![Asn::from(382), Asn::from(293)])
    /// ]);
    /// ```
    impl Serialize for AsPath {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if let Some(num_elements) = simplified_format_len(&self.segments) {
                // Serialize simplified format
                let mut seq_serializer = serializer.serialize_seq(Some(num_elements))?;

                for segment in &self.segments {
                    match segment {
                        AsPathSegment::AsSequence(elements) => {
                            elements
                                .iter()
                                .try_for_each(|x| seq_serializer.serialize_element(x))?;
                        }
                        AsPathSegment::AsSet(x) => seq_serializer.serialize_element(x)?,
                        _ => unreachable!("simplified_format_len checked for confed segments"),
                    }
                }
                return seq_serializer.end();
            }

            // Serialize verbose format
            serializer.collect_seq(&self.segments)
        }
    }

    struct AsPathVisitor;

    impl<'de> Visitor<'de> for AsPathVisitor {
        type Value = AsPath;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("list of AS_PATH segments")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // Technically, we can handle an input that mixes the simplified and verbose formats,
            // but we do not want to document this behavior as it may change in future updates.
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum PathElement {
                SequenceElement(Asn),
                Set(Vec<Asn>),
                Verbose(AsPathSegment),
            }

            let mut append_new_sequence = false;
            let mut segments = Vec::new();
            while let Some(element) = seq.next_element()? {
                match element {
                    PathElement::SequenceElement(x) => {
                        if append_new_sequence {
                            // If the input is mixed between verbose and regular segments, this flag
                            // is used to prevent appending to a verbose sequence.
                            append_new_sequence = false;
                            segments.push(AsPathSegment::AsSequence(Vec::new()));
                        }

                        if let Some(AsPathSegment::AsSequence(last_sequence)) = segments.last_mut()
                        {
                            last_sequence.push(x);
                        } else {
                            segments.push(AsPathSegment::AsSequence(vec![x]));
                        }
                    }
                    PathElement::Set(values) => {
                        segments.push(AsPathSegment::AsSet(values));
                    }
                    PathElement::Verbose(verbose) => {
                        segments.push(verbose);
                    }
                }
            }

            Ok(AsPath { segments })
        }
    }

    impl<'de> Deserialize<'de> for AsPath {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_seq(AsPathVisitor)
        }
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
